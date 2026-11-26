"""pytest plugin that turns safetape on for every pytest-recording cassette.

It loads by itself once safetape is installed. Turn it off with ``-p no:safetape``.
"""

from __future__ import annotations

import re
from collections.abc import Generator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

# Only modules that don't import vcrpy belong up here. pytest can load this plugin
# before pytest-recording, and pytest-recording needs to be the one that imports
# vcr.matchers so its asserts get rewritten.
from ._credentials import remembered
from ._redact import redact_text
from ._settings import DEFAULT_STALE_DAYS, Settings

if TYPE_CHECKING:
    from ._persister import StaleCassette

_LOCKDOWN_VALUES = {"auto": None, "on": True, "off": False}


@dataclass
class _State:
    settings: Settings
    stale: dict[str, StaleCassette] = field(default_factory=dict)

    def remember_stale(self, stale: StaleCassette) -> None:
        self.stale.setdefault(stale.path, stale)


_STATE = pytest.StashKey[_State]()


def pytest_addoption(parser: pytest.Parser) -> None:
    def add_list(name: str, help_text: str) -> None:
        parser.addini(name, help_text, type="linelist", default=[])

    add_list("safetape_redact_headers", "safetape: more headers to strip from cassettes")
    add_list("safetape_redact_query_params", "safetape: more query parameters to strip")
    add_list("safetape_redact_body_fields", "safetape: more JSON or form fields to redact")
    add_list("safetape_allow", "safetape: regexes for values that are fine to record")
    add_list("safetape_ignore_body_fields", "safetape: JSON paths the body matcher ignores")
    parser.addini("safetape_rules", "safetape: extra rules files", type="paths", default=[])
    parser.addini(
        "safetape_stale_days",
        "safetape: report cassettes older than this many days, 0 to turn off",
        default=str(DEFAULT_STALE_DAYS),
    )
    parser.addini(
        "safetape_lockdown",
        "safetape: auto (on when CI is set), on or off",
        default="auto",
    )


def pytest_configure(config: pytest.Config) -> None:
    settings = _settings(config)
    try:
        lockdown = settings.lockdown_active
        # Build the rules now so a bad regex or rules file stops the run straight away.
        settings.ruleset  # noqa: B018
    except (ValueError, re.error) as error:
        raise pytest.UsageError(f"safetape: {error}") from error
    config.stash[_STATE] = _State(settings)
    if lockdown and hasattr(config.option, "record_mode"):
        # pytest-recording's --record-mode. "rewrite" would delete cassettes before
        # safetape gets a say, so set it here as early as possible.
        config.option.record_mode = "none"


@pytest.hookimpl(optionalhook=True)
def pytest_recording_configure(config: pytest.Config, vcr: Any) -> None:
    from ._install import install  # noqa: PLC0415 - see the note on the imports above

    state = config.stash[_STATE]
    install(vcr, state.settings, on_stale=state.remember_stale)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item) -> Generator[None, Any, None]:
    """Mask secrets in a test's failure report and captured output.

    pytest's long tracebacks print the arguments of every frame, and a request
    with no recording passes through frames that hold it unscrubbed.
    """
    outcome = yield
    state = item.config.stash.get(_STATE, None)
    if state is not None:
        _redact_report(outcome.get_result(), state.settings)


def _redact_report(report: pytest.TestReport, settings: Settings) -> None:
    if not report.failed and not report.sections:
        return
    known = settings.known_credentials(remembered())
    if report.longrepr is not None and not isinstance(report.longrepr, tuple):
        text = str(report.longrepr)
        clean = redact_text(text, settings, known)
        if clean != text:
            report.longrepr = clean
    report.sections = [
        (title, redact_text(content, settings, known)) for title, content in report.sections
    ]


def pytest_report_header(config: pytest.Config) -> list[str]:
    state = config.stash.get(_STATE, None)
    if state is not None and state.settings.lockdown_active:
        return ["safetape: lockdown is on, so cassettes are only replayed, never recorded"]
    return []


def pytest_terminal_summary(terminalreporter: Any, config: pytest.Config) -> None:
    state = config.stash.get(_STATE, None)
    if state is None or not state.stale:
        return
    days = state.settings.stale_after_days
    terminalreporter.section("safetape")
    terminalreporter.write_line(
        f"These cassettes were recorded more than {days} days ago. "
        "Re-record them to catch API changes:",
    )
    for stale in sorted(state.stale.values(), key=lambda s: s.path):
        terminalreporter.write_line(
            f"  {_relative(stale.path, config)} ({stale.age_days} days old)"
        )


def _relative(path: str, config: pytest.Config) -> str:
    try:
        return str(Path(path).relative_to(config.rootpath))
    except ValueError:
        return path


def _settings(config: pytest.Config) -> Settings:
    raw_days = str(config.getini("safetape_stale_days")).strip()
    try:
        days = int(raw_days)
    except ValueError:
        raise pytest.UsageError(
            f"safetape_stale_days should be a whole number, not {raw_days!r}",
        ) from None
    raw_lockdown = str(config.getini("safetape_lockdown")).strip().lower()
    if raw_lockdown not in _LOCKDOWN_VALUES:
        raise pytest.UsageError(
            f"safetape_lockdown should be auto, on or off, not {raw_lockdown!r}",
        )
    return Settings(
        redact_headers=tuple(config.getini("safetape_redact_headers")),
        redact_query_params=tuple(config.getini("safetape_redact_query_params")),
        redact_body_fields=tuple(config.getini("safetape_redact_body_fields")),
        allow=tuple(config.getini("safetape_allow")),
        rules_files=tuple(config.getini("safetape_rules")),
        ignore_body_fields=tuple(config.getini("safetape_ignore_body_fields")),
        stale_after_days=days if days > 0 else None,
        lockdown=_LOCKDOWN_VALUES[raw_lockdown],
    )
