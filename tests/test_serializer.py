from __future__ import annotations

import copy
import gzip
import json
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from vcr.serializers import jsonserializer

from safetape import serializer
from safetape.serializer import parse_ndjson, parse_sse, render_ndjson, render_sse


def _cassette(
    response_body: Any,
    response_type: str | None = "application/json",
    request_body: Any = None,
    request_type: str | None = None,
    extra_response_headers: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    response_headers: dict[str, list[str]] = {"Content-Length": ["999"]}
    if response_type:
        response_headers["Content-Type"] = [response_type]
    response_headers.update(extra_response_headers or {})
    request_headers = {"content-type": [request_type]} if request_type else {}
    return {
        "version": 1,
        "interactions": [
            {
                "request": {
                    "method": "POST",
                    "uri": "https://api.example.com/v1/chat",
                    "body": request_body,
                    "headers": request_headers,
                },
                "response": {
                    "status": {"code": 200, "message": "OK"},
                    "headers": response_headers,
                    "body": {"string": response_body},
                },
            },
        ],
    }


def _round_trip(cassette: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    text = serializer.serialize(cassette)
    stored: dict[str, Any] = json.loads(text)
    return stored["interactions"][0], serializer.deserialize(text)["interactions"][0]


def test_json_bodies_are_stored_as_json() -> None:
    body = json.dumps({"id": "chatcmpl-1", "choices": [{"text": "café"}]}, indent=2)
    stored, loaded = _round_trip(
        _cassette(body, request_body='{"model":"m"}', request_type="application/json"),
    )
    assert stored["request"]["body"] == {"json": {"model": "m"}}
    assert stored["response"]["body"] == {
        "json": {"id": "chatcmpl-1", "choices": [{"text": "café"}]}
    }
    replayed = loaded["response"]["body"]["string"]
    assert json.loads(replayed) == json.loads(body)
    assert loaded["response"]["headers"]["Content-Length"] == [str(len(replayed.encode()))]


def test_json_is_sniffed_without_a_content_type() -> None:
    stored, _ = _round_trip(_cassette('[{"a": 1}]', response_type=None))
    assert stored["response"]["body"] == {"json": [{"a": 1}]}


def test_text_stays_text_and_keeps_its_length() -> None:
    stored, loaded = _round_trip(_cassette("hello\nworld", "text/plain", request_body="plain"))
    assert stored["request"]["body"] == "plain"
    assert stored["response"]["body"] == {"string": "hello\nworld"}
    assert loaded["response"]["headers"]["Content-Length"] == ["999"]
    assert loaded["request"]["body"] == "plain"


@pytest.mark.parametrize(
    "body",
    [
        '{"a": 1, "a": 2}',
        '{"a": NaN}',
        "{not json",
        "",
    ],
)
def test_json_that_wont_round_trip_stays_text(body: str) -> None:
    stored, loaded = _round_trip(_cassette(body))
    assert stored["response"]["body"] == {"string": body}
    assert loaded["response"]["body"]["string"] == body


def test_json_scalars_with_a_json_content_type() -> None:
    stored, loaded = _round_trip(_cassette("42"))
    assert stored["response"]["body"] == {"json": 42}
    assert loaded["response"]["body"]["string"] == "42"


def test_binary_and_compressed_bodies_are_base64_and_exact() -> None:
    raw = gzip.compress(b'{"a": 1}')
    stored, loaded = _round_trip(
        _cassette(
            raw, extra_response_headers={"Content-Encoding": ["gzip"]}, request_body=b"\xff\x00"
        ),
    )
    assert set(stored["response"]["body"]) == {"base64"}
    assert loaded["response"]["body"]["string"] == raw
    assert loaded["response"]["headers"]["Content-Length"] == ["999"]
    assert loaded["request"]["body"] == b"\xff\x00"


def test_compressed_text_is_kept_as_text() -> None:
    stored, _ = _round_trip(
        _cassette('{"a": 1}', extra_response_headers={"Content-Encoding": ["br"]})
    )
    assert stored["response"]["body"] == {"string": '{"a": 1}'}


OPENAI_STREAM = (
    'data: {"choices":[{"delta":{"content":"Hel"}}]}\n\n'
    'data: {"choices":[{"delta":{"content":"lo"}}]}\n\n'
    "data: [DONE]\n\n"
)
ANTHROPIC_STREAM = (
    "event: message_start\r\n"
    'data: {"type": "message_start"}\r\n'
    "\r\n"
    ": keep-alive\r\n"
    "\r\n"
    "event: content_block_delta\r\n"
    "id: 7\r\n"
    "data: first line\r\n"
    "data:second line\r\n"
    "\r\n"
)


def test_sse_streams_are_stored_as_events() -> None:
    stored, loaded = _round_trip(_cassette(OPENAI_STREAM, "text/event-stream; charset=utf-8"))
    assert stored["response"]["body"] == {
        "sse": [
            {"data": {"choices": [{"delta": {"content": "Hel"}}]}},
            {"data": {"choices": [{"delta": {"content": "lo"}}]}},
            {"data": "[DONE]"},
        ],
    }
    assert parse_sse(loaded["response"]["body"]["string"]) == parse_sse(OPENAI_STREAM)


def test_sse_with_events_comments_ids_and_multiline_data() -> None:
    events = parse_sse(ANTHROPIC_STREAM)
    assert events == [
        {"event": "message_start", "data": {"type": "message_start"}},
        {":": "keep-alive"},
        {"event": "content_block_delta", "id": "7", "data": "first line\nsecond line"},
    ]
    assert parse_sse(render_sse(events)) == events


@pytest.mark.parametrize(
    "stream",
    [
        "data: cut off",
        "data: a\n\ndata: never finished\n",
        "event: a\nevent: b\n\n",
    ],
)
def test_odd_sse_streams_stay_text(stream: str) -> None:
    stored, loaded = _round_trip(_cassette(stream, "text/event-stream"))
    assert stored["response"]["body"] == {"string": stream}
    assert loaded["response"]["body"]["string"] == stream


def test_ndjson_is_stored_as_a_list() -> None:
    body = '{"response": "Hi", "done": false}\n{"response": "", "done": true}\n'
    stored, loaded = _round_trip(_cassette(body, "application/x-ndjson"))
    assert stored["response"]["body"] == {
        "ndjson": [{"response": "Hi", "done": False}, {"response": "", "done": True}],
    }
    assert parse_ndjson(loaded["response"]["body"]["string"]) == parse_ndjson(body)


@pytest.mark.parametrize("body", ['{"a": 1}', '{"a": 1}\n\n', '{"a": 1}\n42\n', "{bad\n"])
def test_odd_ndjson_stays_text(body: str) -> None:
    stored, _ = _round_trip(_cassette(body, "application/x-ndjson"))
    assert stored["response"]["body"] == {"string": body}


def test_unicode_is_written_as_is() -> None:
    text = serializer.serialize(_cassette('{"text": "caf\\u00e9 \\ud83d\\ude00"}'))
    assert "café \U0001f600" in text
    assert text.endswith("}\n")


@pytest.mark.parametrize("kind", ["text/plain", "text/event-stream", "application/json"])
def test_lone_surrogates_are_escaped(kind: str) -> None:
    body = {
        "text/plain": "a\ud800b",
        "text/event-stream": "event: \ud800\n\n",
        "application/json": '{"a": "\\ud800"}',
    }[kind]
    text = serializer.serialize(_cassette(body, kind))
    text.encode("utf-8")
    assert "\\ud800" in text
    loaded = serializer.deserialize(text)["interactions"][0]["response"]
    assert loaded["body"]["string"].encode("utf-8", "surrogatepass")
    assert loaded["headers"]["Content-Length"] == [
        str(len(loaded["body"]["string"].encode("utf-8", "surrogatepass")))
        if kind != "text/plain"
        else "999",
    ]


def test_serialize_does_not_change_its_input() -> None:
    cassette = _cassette(b'{"a": 1}', request_body='{"b": 2}', request_type="application/json")
    before = copy.deepcopy(cassette)
    serializer.serialize(cassette)
    assert cassette == before


def test_bytes_headers_are_written_as_text() -> None:
    cassette = _cassette("ok", "text/plain")
    cassette["interactions"][0]["request"]["headers"] = {"x-thing": [b"value"]}
    stored, _ = _round_trip(cassette)
    assert stored["request"]["headers"] == {"x-thing": ["value"]}


def test_unknown_objects_are_refused() -> None:
    cassette = _cassette("ok", "text/plain")
    cassette["interactions"][0]["response"]["extra"] = object()
    with pytest.raises(TypeError, match="can't store a object"):
        serializer.serialize(cassette)


def test_reads_vcrpy_json_cassettes() -> None:
    cassette = _cassette('{"a": 1}', request_body='{"b": 2}')
    text = jsonserializer.serialize(cassette)
    assert serializer.deserialize(text) == cassette


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ({"json": 1, "string": "x"}, "exactly one of"),
        ({}, "exactly one of"),
        ({"string": 5}, "must be text"),
        ({"base64": "not base64!"}, "bad base64"),
        ({"sse": {}}, "list of events"),
        ({"sse": [{}]}, "non-empty object"),
        ({"sse": [{"bad:name": "x"}]}, "bad SSE field name"),
        ({"sse": [{"id": "a\nb"}]}, "single line"),
        ({"ndjson": {}}, "must be a list"),
    ],
)
def test_broken_bodies_are_reported(body: dict[str, Any], message: str) -> None:
    text = json.dumps({"version": 1, "interactions": [{"request": {"body": body}, "response": {}}]})
    with pytest.raises(ValueError, match=message):
        serializer.deserialize(text)


def test_deserialize_leaves_other_shapes_alone() -> None:
    assert serializer.deserialize("[1, 2]") == [1, 2]
    text = json.dumps({"interactions": ["x", {"response": {"body": {"content": "old"}}}]})
    assert serializer.deserialize(text) == json.loads(text)
    assert json.loads(serializer.serialize({"interactions": ["x"]})) == {"interactions": ["x"]}


json_values = st.recursive(
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(), children, max_size=4)
    ),
    max_leaves=20,
)


@given(json_values)
def test_any_json_body_survives(value: Any) -> None:
    body = json.dumps(value)
    _, loaded = _round_trip(_cassette(body))
    assert json.loads(loaded["response"]["body"]["string"]) == value


@given(st.text())
def test_any_text_body_survives_exactly(text: str) -> None:
    _, loaded = _round_trip(_cassette(text, "text/plain", request_body=text))
    assert loaded["response"]["body"]["string"] == text
    assert loaded["request"]["body"] == (text or "")


@given(st.binary())
def test_any_binary_body_survives_exactly(raw: bytes) -> None:
    _, loaded = _round_trip(_cassette(raw, "application/octet-stream"))
    expected = raw.decode("utf-8") if _is_utf8(raw) else raw
    assert loaded["response"]["body"]["string"] == expected


def _is_utf8(raw: bytes) -> bool:
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


line = st.text(st.characters(exclude_characters="\r\n"), max_size=20)
event = st.fixed_dictionaries(
    {},
    optional={
        "event": line,
        "id": line,
        "data": st.lists(line, min_size=1, max_size=3).map("\n".join)
        | json_values.filter(
            lambda v: isinstance(v, (dict, list)),
        ),
        ":": line,
    },
).filter(bool)


@given(st.lists(event, max_size=5))
def test_any_sse_stream_survives(events: list[dict[str, Any]]) -> None:
    stream = render_sse(events)
    _, loaded = _round_trip(_cassette(stream, "text/event-stream"))
    assert parse_sse(loaded["response"]["body"]["string"]) == parse_sse(stream)


@given(st.lists(st.dictionaries(st.text(), json_values, max_size=3), max_size=5))
def test_any_ndjson_survives(values: list[dict[str, Any]]) -> None:
    assert parse_ndjson(render_ndjson(values)) == (values if values else None)
