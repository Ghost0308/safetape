"""The credentials a test run actually uses, so they can be found by value.

Some providers (Mistral, Cohere, Azure OpenAI and others) use keys with no
recognisable shape, so no pattern can find one pasted into a prompt. But safetape
sees the real key when it strips it from a header, and keys usually live in
environment variables. Looking for those exact values catches them anywhere.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
from collections.abc import Collection, Iterable, Mapping
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from ._presets import REDACTED

# Shorter values would turn up by chance.
MIN_LENGTH = 8
ENV_MIN_LENGTH = 12
_MAX_REMEMBERED = 10_000

# File paths, whatever platform wrote them. os.path.isabs only knows its own.
_PATH = re.compile(r"^(?:[/\\~]|[A-Za-z]:[/\\])")
_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9._~+-]*)\s+(\S.*)$")
_ENV_NAME = re.compile(
    r"api[_-]?key|token|secret|passw(?:or)?d|credential|access[_-]?key|private[_-]?key",
    re.IGNORECASE,
)

_remembered: set[str] = set()


def from_headers(headers: Mapping[str, Any] | None, names: Collection[str]) -> set[str]:
    """Credential values from the named headers, without auth schemes like "Bearer"."""
    found: set[str] = set()
    if not headers:
        return found
    for name, raw in headers.items():
        lowered = str(name).lower()
        if lowered not in names:
            continue
        for item in raw if isinstance(raw, (list, tuple)) else [raw]:
            value = (
                item.decode("utf-8", "replace") if isinstance(item, bytes) else str(item)
            ).strip()
            if lowered == "cookie":
                found.update(part.partition("=")[2].strip() for part in value.split(";"))
                continue
            found.add(value)
            match = _SCHEME.match(value)
            if match:
                scheme, token = match.group(1).lower(), match.group(2).strip()
                found.add(token)
                if scheme == "basic":
                    found.add(_basic_password(token))
    return _usable(found)


def from_query(uri: Any, names: Collection[str]) -> set[str]:
    if not isinstance(uri, str):
        return set()
    pairs = parse_qsl(urlsplit(uri).query, keep_blank_values=True)
    return _usable(value for name, value in pairs if name.lower() in names)


def from_environment(environ: Mapping[str, str] | None = None) -> set[str]:
    """Values of environment variables whose names say they hold a secret."""
    environ = os.environ if environ is None else environ
    found = set()
    for name, raw in environ.items():
        value = raw.strip()
        if (
            _ENV_NAME.search(name)
            and len(value) >= ENV_MIN_LENGTH
            and not value.isdigit()
            and "://" not in value
            and not _PATH.match(value)
        ):
            found.add(value)
    return found


def from_request(request: Any, headers: Collection[str], params: Collection[str]) -> set[str]:
    """Credentials in a vcrpy Request that hasn't been scrubbed."""
    if request is None:
        return set()
    return from_headers(getattr(request, "headers", None), headers) | from_query(
        getattr(request, "uri", None),
        params,
    )


def remember(values: Iterable[str]) -> None:
    """Keep credentials seen during this run, for masking them in test reports."""
    for value in values:
        if len(_remembered) >= _MAX_REMEMBERED:
            return
        _remembered.add(value)


def remembered() -> frozenset[str]:
    return frozenset(_remembered)


def _basic_password(token: str) -> str:
    try:
        decoded = base64.b64decode(token, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return ""
    return decoded.partition(":")[2]


def _usable(values: Iterable[str]) -> set[str]:
    return {v for v in values if len(v) >= MIN_LENGTH and v != REDACTED}
