"""Request matchers that ignore stripped credentials and explain differences safely.

vcrpy calls each matcher with the request being made first and the recorded
one second, and shows the AssertionError message when nothing matches.
"""

from __future__ import annotations

import difflib
import json
from collections.abc import Callable, Collection, Sequence
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from vcr.util import read_body

from ._bodies import header_values, media_type, to_bytes
from ._rules import Ruleset
from ._scrub import redact_body_fields, strip_query_params
from ._settings import Settings

Matcher = Callable[[Any, Any], None]

MAX_DIFF_LINES = 60


def build_matchers(settings: Settings) -> dict[str, Matcher]:
    ruleset = settings.ruleset
    params = settings.query_params
    ignore = tuple(path.split(".") for path in settings.ignore_body_fields)

    def query(r1: Any, r2: Any) -> None:
        live, recorded = _query(r1.uri, params), _query(r2.uri, params)
        if live != recorded:
            raise AssertionError(ruleset.redact(f"{live} != {recorded}"))

    def uri(r1: Any, r2: Any) -> None:
        live, recorded = _uri(r1.uri, params), _uri(r2.uri, params)
        if live != recorded:
            raise AssertionError(ruleset.redact(f"{live} != {recorded}"))

    def body(r1: Any, r2: Any) -> None:
        live = _comparable(r1, settings.body_fields, ignore)
        recorded = _comparable(r2, settings.body_fields, ignore)
        if live != recorded:
            raise AssertionError(body_diff(recorded, live, ruleset))

    return {"query": query, "uri": uri, "url": uri, "body": body}


def _query(uri: str, params: Collection[str]) -> list[tuple[str, str]]:
    pairs = parse_qsl(urlsplit(uri).query)
    return sorted((k, v) for k, v in pairs if k.lower() not in params)


def _uri(uri: str, params: Collection[str]) -> str:
    parts = urlsplit(strip_query_params(uri, params))
    # An empty path means "/" (RFC 3986 6.2.3), and some clients record it either way.
    return urlunsplit(parts._replace(path=parts.path or "/"))


def _comparable(
    request: Any,
    fields: Collection[str],
    ignore: Sequence[Sequence[str]],
) -> tuple[str, str]:
    """A body boiled down to what should decide a match, as (kind, text)."""
    raw = to_bytes(read_body(request))
    if not raw:
        return ("empty", "")
    headers = request.headers
    raw = to_bytes(redact_body_fields(raw, headers, fields)) or b""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ("bytes", raw.hex())

    kind = media_type(headers)
    if kind.startswith("multipart/"):
        # Clients pick a new random boundary for every request.
        boundary = _boundary(headers)
        return ("multipart", text.replace(boundary, "BOUNDARY") if boundary else text)
    if kind == "application/x-www-form-urlencoded":
        pairs = sorted(parse_qsl(text, keep_blank_values=True))
        return ("form", "\n".join(f"{k}={v}" for k, v in pairs))
    if "json" in kind or text.lstrip().startswith(("{", "[")):
        try:
            value = json.loads(text)
        except ValueError:
            pass
        else:
            for path in ignore:
                value = drop_path(value, path)
            return ("json", json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))
    return ("text", text)


def _boundary(headers: Any) -> str:
    for value in header_values(headers, "content-type"):
        for param in value.split(";")[1:]:
            name, _, raw = param.strip().partition("=")
            if name.lower() == "boundary":
                return raw.strip('"')
    return ""


def drop_path(value: Any, path: Sequence[str]) -> Any:
    """A copy of a JSON value without the field at ``path``. ``*`` matches any key or index."""
    if not path:
        return value
    head, rest = path[0], path[1:]
    if isinstance(value, dict):
        keys = list(value) if head == "*" else [head] if head in value else []
        result = dict(value)
        for key in keys:
            if rest:
                result[key] = drop_path(value[key], rest)
            else:
                del result[key]
        return result
    if isinstance(value, list):
        if head == "*":
            indices = set(range(len(value)))
        elif head.isdigit() and int(head) < len(value):
            indices = {int(head)}
        else:
            return value
        if not rest:
            return [item for i, item in enumerate(value) if i not in indices]
        return [drop_path(item, rest) if i in indices else item for i, item in enumerate(value)]
    return value


def body_diff(recorded: tuple[str, str], live: tuple[str, str], ruleset: Ruleset) -> str:
    """A unified diff of two bodies with any secrets masked."""
    if recorded[0] == "bytes" or live[0] == "bytes":
        return "the bodies differ (at least one is binary)"
    lines = list(
        difflib.unified_diff(
            recorded[1].splitlines(),
            live[1].splitlines(),
            "recorded",
            "this request",
            n=2,
            lineterm="",
        ),
    )
    if not lines:
        return f"the bodies differ ({recorded[0]} recorded, {live[0]} in this request)"
    if len(lines) > MAX_DIFF_LINES:
        extra = len(lines) - MAX_DIFF_LINES
        lines = [*lines[:MAX_DIFF_LINES], f"... ({extra} more lines)"]
    return ruleset.redact("\n".join(lines))
