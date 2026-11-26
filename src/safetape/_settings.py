"""User settings, with the defaults safetape starts from."""

from __future__ import annotations

import os
import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

from . import _presets
from ._rules import Ruleset, default_rules, load_rules

DEFAULT_STALE_DAYS = 90

_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off", ""})


@dataclass(frozen=True)
class Settings:
    """How safetape treats cassettes.

    Everything here adds to safetape's defaults. There's no way to switch a
    default off, so a typo can't quietly stop a header from being stripped.
    """

    redact_headers: Collection[str] = ()
    """More headers to strip from requests and responses."""

    redact_query_params: Collection[str] = ()
    """More query parameters to strip from URLs."""

    redact_body_fields: Collection[str] = ()
    """More JSON or form fields whose values get replaced with REDACTED."""

    allow: Collection[str] = ()
    """Regexes for values that look like secrets but are fine to record."""

    rules_files: Collection[str | Path] = ()
    """Extra JSON rules files, in the same format as safetape's own."""

    ignore_body_fields: Collection[str] = ()
    """JSON paths the body matcher ignores, such as ``metadata.user_id`` or ``messages.*.id``."""

    stale_after_days: int | None = DEFAULT_STALE_DAYS
    """Warn about cassettes recorded longer ago than this. None or 0 turns it off."""

    lockdown: bool | None = None
    """Never record, only replay. None means on when the CI environment variable is set."""

    @cached_property
    def headers(self) -> frozenset[str]:
        return (
            _presets.default_request_headers()
            | _presets.default_response_headers()
            | {h.lower() for h in self.redact_headers}
        )

    @cached_property
    def query_params(self) -> frozenset[str]:
        return _presets.default_query_params() | {q.lower() for q in self.redact_query_params}

    @cached_property
    def body_fields(self) -> frozenset[str]:
        return _presets.BODY_FIELDS | {_presets.normalize_field(f) for f in self.redact_body_fields}

    @cached_property
    def ruleset(self) -> Ruleset:
        ruleset = default_rules()
        for path in self.rules_files:
            extra = load_rules(path)
            ruleset = ruleset.extended(rules=extra.rules, allow_terms=extra.allow_terms)
        return ruleset.extended(allow_patterns=[re.compile(p) for p in self.allow])

    @cached_property
    def lockdown_active(self) -> bool:
        return resolve_lockdown(self.lockdown, os.environ)


def resolve_lockdown(value: bool | None, environ: Mapping[str, str]) -> bool:
    """An explicit setting wins, then SAFETAPE_LOCKDOWN, then whether CI is set."""
    if value is not None:
        return value
    override = environ.get("SAFETAPE_LOCKDOWN")
    if override is not None:
        return _flag(override, "SAFETAPE_LOCKDOWN")
    ci = environ.get("CI", "").strip().lower()
    return ci not in _FALSE


def _flag(raw: str, name: str) -> bool:
    lowered = raw.strip().lower()
    if lowered in _TRUE:
        return True
    if lowered in _FALSE:
        return False
    raise ValueError(f"{name} should be on or off, not {raw!r}")
