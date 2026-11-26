"""A JSON cassette serializer that keeps bodies readable.

vcrpy stores a body as one long string. Here a JSON body is stored as JSON, a
streamed (server-sent events) body as a list of events, and newline-delimited
JSON as a list, so a re-recorded cassette shows a useful diff in review.
Binary bodies are stored as base64.

On replay, structured bodies are encoded again as compact JSON. The data is
the same but the bytes can differ from what the server sent, so
Content-Length is updated to match.

It reads cassettes written by vcrpy's own JSON serializer too.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Mapping
from typing import Any

from ._bodies import compact_json, content_encodings, media_type, set_header, strict_json, to_bytes

__all__ = ["deserialize", "serialize"]

_FORMS = ("string", "base64", "json", "sse", "ndjson")
_LINE_BREAK = re.compile(r"\r\n|\r|\n")
_MULTILINE_FIELDS = ("data", ":")


def serialize(cassette_dict: Mapping[str, Any]) -> str:
    data = dict(cassette_dict)
    data["interactions"] = [_serialize_interaction(i) for i in data.get("interactions", [])]
    text = json.dumps(data, indent=2, ensure_ascii=False, default=_json_default) + "\n"
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        # A lone surrogate can't be written as UTF-8, but JSON can escape it.
        text = json.dumps(data, indent=2, default=_json_default) + "\n"
    return text


def deserialize(cassette_string: str) -> Any:
    data = json.loads(cassette_string)
    if isinstance(data, dict) and isinstance(data.get("interactions"), list):
        data["interactions"] = [_deserialize_interaction(i) for i in data["interactions"]]
    return data


def _serialize_interaction(interaction: Any) -> Any:
    if not isinstance(interaction, Mapping):
        return interaction
    result = dict(interaction)
    request = result.get("request")
    if isinstance(request, Mapping) and "body" in request:
        request = dict(request)
        encoded = _encode(request["body"], request.get("headers"))
        # Plain text request bodies stay bare strings, the way vcrpy writes them.
        request["body"] = encoded.get("string") if set(encoded) <= {"string"} else encoded
        result["request"] = request
    response = result.get("response")
    if isinstance(response, Mapping) and isinstance(response.get("body"), Mapping):
        response = dict(response)
        body = dict(response["body"])
        if "string" in body:
            body.update(_encode(body.pop("string"), response.get("headers")))
        response["body"] = body
        result["response"] = response
    return result


def _deserialize_interaction(interaction: Any) -> Any:
    if not isinstance(interaction, dict):
        return interaction
    request = interaction.get("request")
    if isinstance(request, dict) and isinstance(request.get("body"), dict):
        request["body"], rendered = _decode(request["body"])
        if rendered:
            _fix_length(request, request["body"])
    response = interaction.get("response")
    if isinstance(response, dict) and isinstance(response.get("body"), dict):
        body = response["body"]
        if any(form in body for form in _FORMS):
            value, rendered = _decode(body)
            for form in _FORMS:
                body.pop(form, None)
            body["string"] = value
            if rendered:
                _fix_length(response, value)
    return interaction


def _encode(body: Any, headers: Any) -> dict[str, Any]:
    """The readable form of a body: one of string, base64, json, sse or ndjson."""
    if body is None or (isinstance(body, str) and not body):
        return {"string": body}
    if isinstance(body, str):
        text = body
    else:
        raw = to_bytes(body) or b""
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return {"base64": base64.b64encode(raw).decode("ascii")}
    if content_encodings(headers):
        return {"string": text}

    kind = media_type(headers)
    if kind == "text/event-stream":
        events = parse_sse(text)
        if events is not None and _round_trips(events):
            return {"sse": events}
    elif kind in ("application/x-ndjson", "application/jsonl", "application/jsonlines"):
        lines = parse_ndjson(text)
        if lines is not None:
            return {"ndjson": lines}
    elif "json" in kind or text.lstrip().startswith(("{", "[")):
        try:
            return {"json": strict_json(text)}
        except ValueError:
            pass
    return {"string": text}


def _decode(body: Mapping[str, Any]) -> tuple[str | bytes | None, bool]:
    """A body back in vcrpy's form, and whether it had to be encoded again."""
    forms = [form for form in _FORMS if form in body]
    if len(forms) != 1:
        raise ValueError(f"a body needs exactly one of {', '.join(_FORMS)}, found {forms}")
    form = forms[0]
    value = body[form]
    if form == "string":
        if value is not None and not isinstance(value, str):
            raise ValueError("a 'string' body must be text")
        return value, False
    if form == "base64":
        try:
            return base64.b64decode(value, validate=True), False
        except (TypeError, binascii.Error) as error:
            raise ValueError(f"bad base64 body: {error}") from error
    if form == "json":
        return compact_json(value), True
    if form == "sse":
        return render_sse(value), True
    return render_ndjson(value), True


def _fix_length(part: dict[str, Any], body: str | bytes | None) -> None:
    headers = part.get("headers")
    if isinstance(headers, dict):
        set_header(headers, "content-length", str(len(to_bytes(body) or b"")))


def _json_default(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="replace")
    raise TypeError(f"can't store a {type(value).__name__} in a JSON cassette")


def parse_sse(text: str) -> list[dict[str, Any]] | None:
    """Split a server-sent events stream into events, or None if it isn't a clean one.

    Each event maps field names to values. Repeated data lines are joined with
    newlines, as an SSE client would, and data that is a JSON object or array
    is parsed. Comment lines are kept under the ":" field.
    """
    lines = _LINE_BREAK.split(text)
    if lines.pop() != "":
        return None
    events: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for line in lines:
        if not line:
            if current:
                events.append(_finish_event(current))
                current = {}
            continue
        if line.startswith(":"):
            field, value = ":", line[1:]
        else:
            field, _, value = line.partition(":")
        value = value.removeprefix(" ")
        if field in _MULTILINE_FIELDS:
            current.setdefault(field, []).append(value)
        elif field in current:
            return None
        else:
            current[field] = value
    if current:
        # The last event never got its blank line, so a client would drop it.
        return None
    return events


def _round_trips(events: list[dict[str, Any]]) -> bool:
    try:
        return parse_sse(render_sse(events)) == events
    except ValueError:
        return False


def _finish_event(event: dict[str, Any]) -> dict[str, Any]:
    for field in _MULTILINE_FIELDS:
        if field in event:
            joined = "\n".join(event[field])
            event[field] = _maybe_json(joined) if field == "data" else joined
    return event


def _maybe_json(text: str) -> Any:
    if text.lstrip().startswith(("{", "[")):
        try:
            return strict_json(text)
        except ValueError:
            pass
    return text


def render_sse(events: Any) -> str:
    if not isinstance(events, list):
        raise ValueError("an 'sse' body must be a list of events")
    out: list[str] = []
    for event in events:
        if not isinstance(event, dict) or not event:
            raise ValueError("each SSE event must be a non-empty object")
        for field, value in event.items():
            if not field or (any(c in field for c in ":\r\n") and field != ":"):
                raise ValueError(f"bad SSE field name {field!r}")
            if field in _MULTILINE_FIELDS:
                text = value if isinstance(value, str) else compact_json(value)
                prefix = ":" if field == ":" else f"{field}:"
                out.extend(f"{prefix} {line}\n" for line in text.split("\n"))
            elif isinstance(value, str) and not _LINE_BREAK.search(value):
                out.append(f"{field}: {value}\n")
            else:
                raise ValueError(f"SSE field {field!r} must be a single line of text")
        out.append("\n")
    return "".join(out)


def parse_ndjson(text: str) -> list[Any] | None:
    if not text.endswith("\n"):
        return None
    values = []
    for line in text[:-1].split("\n"):
        try:
            value = strict_json(line)
        except ValueError:
            return None
        if not isinstance(value, (dict, list)):
            return None
        values.append(value)
    return values


def render_ndjson(values: Any) -> str:
    if not isinstance(values, list):
        raise ValueError("an 'ndjson' body must be a list")
    return "".join(compact_json(value) + "\n" for value in values)
