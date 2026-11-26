from __future__ import annotations

import json
from typing import Any

import pytest
from vcr.request import Request

from safetape import Settings
from safetape._matchers import MAX_DIFF_LINES, build_matchers, drop_path

from .fakes import chars, google_key, openai_key, refresh_token

MATCHERS = build_matchers(Settings(ignore_body_fields=["metadata.user_id", "messages.*.id"]))


def _request(
    uri: str = "https://api.example.com/v1/chat", body: Any = None, **headers: str
) -> Request:
    return Request("POST", uri, body, {k.replace("_", "-"): v for k, v in headers.items()})


def _json_request(value: Any, **headers: str) -> Request:
    return _request(body=json.dumps(value), content_type="application/json", **headers)


def _fails(name: str, live: Request, recorded: Request) -> str:
    with pytest.raises(AssertionError) as error:
        MATCHERS[name](live, recorded)
    return str(error.value)


def test_matchers_keep_vcrpy_names() -> None:
    assert {name: m.__name__ for name, m in MATCHERS.items()} == {
        "query": "query",
        "uri": "uri",
        "url": "uri",
        "body": "body",
    }


def test_query_ignores_stripped_params() -> None:
    live = _request(f"https://g.example.com/v1/models?alt=sse&key={google_key()}")
    recorded = _request("https://g.example.com/v1/models?alt=sse")
    MATCHERS["query"](live, recorded)
    MATCHERS["uri"](live, recorded)


def test_query_and_uri_messages_hide_secrets() -> None:
    key = openai_key()
    live = _request(f"https://x.example.com/v1?q={key}")
    recorded = _request("https://x.example.com/v1?q=other")
    for name in ("query", "uri"):
        message = _fails(name, live, recorded)
        assert key not in message
        assert "openai-key" in message


def test_uri_treats_empty_path_as_slash() -> None:
    MATCHERS["uri"](_request("https://x.example.com"), _request("https://x.example.com/"))


def test_json_bodies_match_whatever_the_formatting() -> None:
    live = _request(body='{"b": [1, 2], "a": {"x": "y"}}', content_type="application/json")
    recorded = _request(body='{\n  "a": {"x": "y"},\n  "b": [1, 2]\n}')
    MATCHERS["body"](live, recorded)


def test_ignored_fields_dont_count() -> None:
    live = _json_request(
        {"metadata": {"user_id": "u-1"}, "messages": [{"id": "a", "content": "hi"}]},
    )
    recorded = _json_request(
        {"metadata": {"user_id": "u-2"}, "messages": [{"id": "b", "content": "hi"}]},
    )
    MATCHERS["body"](live, recorded)


def test_redacted_body_fields_dont_count() -> None:
    live = _request(
        body=f"grant_type=refresh_token&refresh_token={refresh_token()}",
        content_type="application/x-www-form-urlencoded",
    )
    recorded = _request(
        body="refresh_token=REDACTED&grant_type=refresh_token",
        content_type="application/x-www-form-urlencoded",
    )
    MATCHERS["body"](live, recorded)


def test_body_mismatch_shows_a_masked_diff() -> None:
    key = openai_key()
    live = _json_request({"model": "gpt-5", "messages": [{"content": f"use {key}"}]})
    recorded = _json_request({"model": "gpt-4.1", "messages": [{"content": "hello"}]})
    message = _fails("body", live, recorded)
    assert message.startswith("--- recorded\n+++ this request")
    assert '-  "model": "gpt-4.1"' in message
    assert '+  "model": "gpt-5"' in message
    assert key not in message
    assert "<openai-key: sk-p..." in message


def test_long_diffs_are_cut_short() -> None:
    live = _json_request({f"k{i}": i for i in range(100)})
    recorded = _json_request({f"k{i}": -i for i in range(100)})
    message = _fails("body", live, recorded)
    assert len(message.splitlines()) == MAX_DIFF_LINES + 1
    assert message.endswith("more lines)")


@pytest.mark.parametrize(
    ("live_body", "recorded_body", "expected"),
    [
        (b"\xff\x00", b"\xff\x01", "at least one is binary"),
        ("", "something", "+++ this request"),
    ],
)
def test_other_body_mismatches(live_body: Any, recorded_body: Any, expected: str) -> None:
    message = _fails("body", _request(body=live_body), _request(body=recorded_body))
    assert expected in message


def test_multipart_boundaries_dont_count() -> None:
    def upload(boundary: str, name: str = "speech.mp3") -> Request:
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{name}"\r\n'
            f"\r\nAUDIO\r\n--{boundary}--\r\n"
        )
        return _request(body=body, content_type=f'multipart/form-data; boundary="{boundary}"')

    MATCHERS["body"](upload("a1b2c3"), upload("d4e5f6"))
    assert "speech.wav" in _fails("body", upload("a1b2c3", "speech.wav"), upload("d4e5f6"))
    no_boundary = _request(body="x", content_type="multipart/form-data")
    MATCHERS["body"](no_boundary, _request(body="x", content_type="multipart/form-data"))


def test_text_and_empty_bodies_match() -> None:
    MATCHERS["body"](_request(body="plain"), _request(body=b"plain"))
    MATCHERS["body"](_request(body=None), _request(body=b""))
    MATCHERS["body"](_request(body="{broken"), _request(body="{broken"))


def test_same_text_of_different_kinds_differs() -> None:
    live = _request(body="a=1", content_type="application/x-www-form-urlencoded")
    message = _fails("body", live, _request(body="a=1"))
    assert message == "the bodies differ (text recorded, form in this request)"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("a", {"b": [{"c": 1, "d": 2}, {"c": 3}]}),
        ("b.*.c", {"a": 1, "b": [{"d": 2}, {}]}),
        ("b.0", {"a": 1, "b": [{"c": 3}]}),
        ("b.1.c", {"a": 1, "b": [{"c": 1, "d": 2}, {}]}),
        ("b.*", {"a": 1, "b": []}),
        ("*", {}),
        ("b.9", {"a": 1, "b": [{"c": 1, "d": 2}, {"c": 3}]}),
        ("b.x", {"a": 1, "b": [{"c": 1, "d": 2}, {"c": 3}]}),
        ("a.x", {"a": 1, "b": [{"c": 1, "d": 2}, {"c": 3}]}),
        ("missing", {"a": 1, "b": [{"c": 1, "d": 2}, {"c": 3}]}),
    ],
)
def test_drop_path(path: str, expected: Any) -> None:
    value = {"a": 1, "b": [{"c": 1, "d": 2}, {"c": 3}]}
    assert drop_path(value, path.split(".")) == expected
    assert value == {"a": 1, "b": [{"c": 1, "d": 2}, {"c": 3}]}
    assert drop_path(value, []) is value


def test_diff_masks_the_live_requests_own_credentials() -> None:
    key = chars(32)
    live = _json_request({"content": f"my key is {key}"}, authorization=f"Bearer {key}")
    message = _fails("body", live, _json_request({"content": "hello"}))
    assert key not in message
    assert "<known-secret:" in message
