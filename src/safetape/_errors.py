"""Errors safetape raises to stop a cassette being written."""

from __future__ import annotations

import os
from collections.abc import Sequence

from ._scan import Finding

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
