"""Strip known credentials from an interaction before it's saved."""

from __future__ import annotations

from collections.abc import Collection, Mapping, MutableMapping
from typing import Any
from urllib.parse import unquote_plus, urlsplit, urlunsplit

from ._bodies import compact_json, content_encodings, media_type, set_header, strict_json, to_bytes
from ._presets import normalize_field
from ._settings import Settings

REDACTED = "REDACTED"


def scrub_interaction(interaction: MutableMapping[str, Any], settings: Settings) -> None:
    """Remove credentials in place. Pass a copy, never the cassette's own data."""
    request = interaction.get("request")
    if isinstance(request, MutableMapping):
        if isinstance(request.get("uri"), str):
            request["uri"] = strip_query_params(request["uri"], settings.query_params)
        _drop_headers_of(request, settings.headers)
        if "body" in request:
            request["body"] = _redacted_body(request, request["body"], settings)

    response = interaction.get("response")
    if isinstance(response, MutableMapping):
        _drop_headers_of(response, settings.headers)
        body = response.get("body")
        if isinstance(body, MutableMapping) and "string" in body:
            body["string"] = _redacted_body(response, body["string"], settings)


def _redacted_body(part: MutableMapping[str, Any], body: Any, settings: Settings) -> Any:
    headers = part.get("headers")
    new = redact_body_fields(body, headers, settings.body_fields)
    if new is not body and isinstance(headers, MutableMapping):
        set_header(headers, "content-length", str(len(to_bytes(new) or b"")))
    return new


def _drop_headers_of(part: MutableMapping[str, Any], names: Collection[str]) -> None:
    headers = part.get("headers")
    if isinstance(headers, Mapping):
        part["headers"] = drop_headers(headers, names)


def drop_headers(headers: Mapping[str, Any], names: Collection[str]) -> dict[str, Any]:
    return {key: value for key, value in headers.items() if str(key).lower() not in names}


def strip_query_params(uri: str, names: Collection[str]) -> str:
    """Drop the named query parameters. Everything else keeps its exact spelling."""
    parts = urlsplit(uri)
    if not parts.query:
        return uri
    pieces = parts.query.split("&")
    kept = [piece for piece in pieces if _param_name(piece) not in names]
    if len(kept) == len(pieces):
        return uri
    return urlunsplit(parts._replace(query="&".join(kept)))


def _param_name(piece: str) -> str:
    return unquote_plus(piece.split("=", 1)[0]).lower()


def redact_body_fields(
    body: Any, headers: Mapping[str, Any] | None, fields: Collection[str]
) -> Any:
    """Replace credential fields in a JSON or form body.

    Returns the body object unchanged when there's nothing to replace, so the
    bytes of an untouched body stay exactly as recorded.
    """
    if body is None or content_encodings(headers):
        return body
    raw = to_bytes(body)
    if not raw:
        return body
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return body

    kind = media_type(headers)
    if kind == "application/x-www-form-urlencoded":
        new_text = _redact_form(text, fields)
    else:
        new_text = _redact_json(text, fields)
    if new_text is None:
        return body
    return new_text if isinstance(body, str) else new_text.encode("utf-8")


def _redact_form(text: str, fields: Collection[str]) -> str | None:
    changed = False
    pieces = []
    for piece in text.split("&"):
        name, sep, value = piece.partition("=")
        if sep and value and value != REDACTED and normalize_field(unquote_plus(name)) in fields:
            pieces.append(f"{name}={REDACTED}")
            changed = True
        else:
            pieces.append(piece)
    return "&".join(pieces) if changed else None


def _redact_json(text: str, fields: Collection[str]) -> str | None:
    stripped = text.lstrip()
    if not stripped.startswith(("{", "[")):
        return None
    try:
        data = strict_json(text)
    except ValueError:
        return None
    new, changed = _redact_value(data, fields)
    return compact_json(new) if changed else None


def _redact_value(value: Any, fields: Collection[str]) -> tuple[Any, bool]:
    if isinstance(value, dict):
        changed = False
        result = {}
        for key, item in value.items():
            if (
                normalize_field(key) in fields
                and isinstance(item, str)
                and item
                and item != REDACTED
            ):
                result[key] = REDACTED
                changed = True
            else:
                result[key], item_changed = _redact_value(item, fields)
                changed = changed or item_changed
        return result, changed
    if isinstance(value, list):
        results = [_redact_value(item, fields) for item in value]
        return [item for item, _ in results], any(changed for _, changed in results)
    return value, False
