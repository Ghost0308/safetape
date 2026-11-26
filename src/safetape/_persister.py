"""A vcrpy persister that refuses to write secrets."""

from __future__ import annotations

import copy
import os
import stat
import tempfile
import warnings
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

from vcr.persisters.filesystem import CassetteDecodeError, CassetteNotFoundError
from vcr.serialize import deserialize as vcr_deserialize
from vcr.serialize import serialize as vcr_serialize

from ._bodies import header_values
from ._rules import Ruleset
from ._scan import Finding, scan_interaction, scan_text
from ._scrub import scrub_interaction
from ._settings import Settings

_ALLOW_HINT = (
    "If it isn't really a secret, add a regex that matches it to safetape's allow list "
    "(Settings(allow=...) or safetape_allow in your pytest config)."
)


class SafetapeError(Exception):
    """Base class for errors safetape raises to stop a cassette being written."""


class SecretFoundError(SafetapeError):
    """A cassette wasn't saved because it still holds something that looks secret."""

    def __init__(self, path: str | os.PathLike[str], findings: Sequence[Finding]) -> None:
        self.path = os.fspath(path)
        self.findings = tuple(findings)
        what = (
            "something that looks like a secret"
            if len(self.findings) == 1
            else f"{len(self.findings)} things that look like secrets"
        )
        lines = [
            f"safetape didn't save {self.path} because it still has {what}:",
            "",
            *(f"  {finding}" for finding in self.findings),
            "",
            "Nothing was written. Strip the value before it's saved, with filter_headers, "
            "filter_query_parameters, before_record_request or before_record_response.",
            _ALLOW_HINT,
        ]
        super().__init__("\n".join(lines))


class LockdownError(SafetapeError):
    """Something tried to record a new cassette while lockdown is on."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = os.fspath(path)
        super().__init__(
            f"safetape lockdown is on, so {self.path} can't be recorded. Lockdown switches on "
            "by itself when the CI environment variable is set. Record cassettes on your "
            "machine and commit them, or set SAFETAPE_LOCKDOWN=0 to record here.",
        )


class StaleCassetteWarning(UserWarning):
    """A cassette was recorded a long time ago."""


@dataclass(frozen=True)
class StaleCassette:
    path: str
    recorded: datetime
    age_days: int

    @property
    def message(self) -> str:
        return (
            f"{self.path} was recorded {self.age_days} days ago "
            f"({self.recorded:%Y-%m-%d}). Re-record it to catch API changes."
        )


class SafePersister:
    """Loads and saves cassettes, and won't save one that still has a secret in it.

    Before a cassette is written, known credential headers, query parameters and
    body fields are stripped, then every part of every interaction is scanned.
    If anything still looks secret, nothing is written and SecretFoundError is
    raised. Files are written as UTF-8 through a temporary file, so a crash
    never leaves half a cassette behind.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        extra_paths: Iterable[str | os.PathLike[str]] = (),
        on_stale: Callable[[StaleCassette], object] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings or Settings()
        self.extra_paths = tuple(os.fspath(p) for p in extra_paths)
        self._on_stale = on_stale
        self._clock = clock or (lambda: datetime.now(UTC))
        self._loaded: dict[str, int] = {}

    def load_cassette(
        self, cassette_path: str | os.PathLike[str], serializer: Any
    ) -> tuple[Any, ...]:
        main = os.fspath(cassette_path)
        requests: list[Any] = []
        responses: list[Any] = []
        metadata: Any = None
        found = False
        for path in dict.fromkeys((main, *self.extra_paths)):
            text = _read(path)
            if text is None:
                continue
            found = True
            loaded_requests, loaded_responses, *rest = vcr_deserialize(text, serializer)
            requests.extend(loaded_requests)
            responses.extend(loaded_responses)
            if path == main and rest:
                metadata = rest[0]
            self._check_stale(path, loaded_responses)
        if not found:
            raise CassetteNotFoundError()
        self._loaded[main] = len(requests)
        if metadata:
            return requests, responses, metadata
        return requests, responses

    def save_cassette(
        self,
        cassette_path: str | os.PathLike[str],
        cassette_dict: Mapping[str, Any],
        serializer: Any,
    ) -> None:
        # The arguments hold the cassette before scrubbing. pytest prints arguments
        # in tracebacks, so keep this frame out of them.
        __tracebackhide__ = True
        path = Path(cassette_path)
        if self.settings.lockdown_active:
            # vcrpy rewrites a cassette it only replayed when drop_unused_requests is on.
            # That's harmless to skip. Anything new means a request was recorded.
            loaded = self._loaded.get(os.fspath(cassette_path), 0)
            if len(cassette_dict.get("requests", ())) > loaded:
                raise LockdownError(path)
            return
        guard = _Guard(serializer, self.settings.ruleset, self.settings, path)
        output = vcr_serialize(cassette_dict, guard)
        _atomic_write(path, output)

    def _check_stale(self, path: str, responses: Iterable[Any]) -> None:
        days = self.settings.stale_after_days
        if not days:
            return
        dates = [d for d in (_recorded_at(r) for r in responses) if d is not None]
        if not dates:
            return
        oldest = min(dates)
        age = self._clock() - oldest
        if age <= timedelta(days=days):
            return
        stale = StaleCassette(path, oldest, age.days)
        if self._on_stale is not None:
            self._on_stale(stale)
        else:
            warnings.warn(StaleCassetteWarning(stale.message), stacklevel=2)


class _Guard:
    """Wraps the real serializer and checks the data on its way through."""

    def __init__(self, inner: Any, ruleset: Ruleset, settings: Settings, path: Path) -> None:
        self._inner = inner
        self._ruleset = ruleset
        self._settings = settings
        self._path = path

    def serialize(self, data: Mapping[str, Any]) -> Any:
        __tracebackhide__ = True
        data = copy.deepcopy(dict(data))
        findings: list[Finding] = []
        for number, interaction in enumerate(data.get("interactions", ()), start=1):
            scrub_interaction(interaction, self._settings)
            findings += scan_interaction(number, interaction, self._ruleset)
        if data.get("metadata"):
            findings += scan_text(repr(data["metadata"]), self._ruleset, "cassette metadata")
        if findings:
            raise SecretFoundError(self._path, findings)

        output = self._inner.serialize(data)
        # The serializer can turn data into text in ways the scan above didn't see,
        # so check what is about to hit the disk as well.
        text = output.decode("utf-8", "replace") if isinstance(output, bytes) else str(output)
        findings = scan_text(text, self._ruleset, "cassette file")
        if findings:
            raise SecretFoundError(self._path, findings)
        return output

    def deserialize(self, text: str) -> Any:
        return self._inner.deserialize(text)


def _read(path: str) -> str | None:
    file = Path(path)
    if not file.is_file():
        return None
    try:
        text = file.read_bytes().decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise CassetteDecodeError(f"{path} isn't valid UTF-8") from error
    # An empty file counts as a missing cassette, as it does in vcrpy.
    return text if text.strip() else None


def _atomic_write(path: Path, output: str | bytes) -> None:
    data = output.encode("utf-8") if isinstance(output, str) else bytes(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(handle, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
        temp.chmod(mode)
        temp.replace(path)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise


def _recorded_at(response: Any) -> datetime | None:
    if not isinstance(response, Mapping):
        return None
    values = header_values(response.get("headers"), "date")
    if not values:
        return None
    try:
        when = parsedate_to_datetime(values[0])
    except (TypeError, ValueError, IndexError):
        return None
    return when if when.tzinfo else when.replace(tzinfo=UTC)
