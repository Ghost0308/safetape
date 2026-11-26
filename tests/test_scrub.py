from __future__ import annotations

import json
from typing import Any

import pytest

from safetape import REDACTED, Settings
from safetape._presets import PRESETS, default_query_params, default_request_headers
from safetape._scrub import redact_body_fields, scrub_interaction, strip_query_params

from .fakes import anthropic_key, google_key, openai_key, refresh_token

SETTINGS = Settings()


def _interaction(**request: Any) -> dict[str, Any]:
    response = request.pop("response", {})
    return {
        "request": {
            "method": "POST",
            "uri": request.pop("uri", "https://api.example.com/v1"),
            "body": request.pop("body", None),
            "headers": request.pop("headers", {}),
        },
        "response": {
            "status": {"code": 200, "message": "OK"},
            "headers": response.get("headers", {}),
            "body": {"string": response.get("body", b"")},
        },
    }


def test_credential_headers_are_dropped_whatever_their_case() -> None:
    interaction = _interaction(
        headers={
            "Authorization": [f"Bearer {openai_key()}"],
            "X-API-Key": [anthropic_key()],
            "x-goog-api-key": [google_key()],
            "OpenAI-Organization": ["org-1"],
            "Content-Type": ["application/json"],
        },
        response={
            "headers": {"Set-Cookie": ["a=b"], "openai-project": ["p"], "x-request-id": ["r"]}
        },
    )
    scrub_interaction(interaction, SETTINGS)
    assert interaction["request"]["headers"] == {"Content-Type": ["application/json"]}
    assert interaction["response"]["headers"] == {"x-request-id": ["r"]}


def test_extra_headers_from_settings() -> None:
    interaction = _interaction(headers={"X-Corp-Auth": ["v"], "X-Other": ["w"]})
    scrub_interaction(interaction, Settings(redact_headers=["x-corp-auth"]))
    assert interaction["request"]["headers"] == {"X-Other": ["w"]}


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("https://x/v1/models", "https://x/v1/models"),
        ("https://x/v1/models?alt=sse", "https://x/v1/models?alt=sse"),
        ("https://x/v1/m?alt=sse&key=SECRET&q=a%2Fb+c", "https://x/v1/m?alt=sse&q=a%2Fb+c"),
        ("https://x/v1/m?KEY=SECRET", "https://x/v1/m"),
        ("https://x/p?X-Amz-Signature=abc&X-Amz-Credential=def&v=1", "https://x/p?v=1"),
        ("https://x/p?api%5Fkey=abc", "https://x/p"),
    ],
)
def test_strip_query_params(uri: str, expected: str) -> None:
    assert strip_query_params(uri, SETTINGS.query_params) == expected


def test_json_body_fields_are_redacted_and_length_follows() -> None:
    token = refresh_token()
    body = json.dumps(
        {
            "refresh_token": token,
            "nested": [{"Client-Secret": "abc"}],
            "token": "Paris",
            "empty": "",
        },
        indent=2,
    )
    interaction = _interaction(
        body=body,
        headers={"Content-Type": ["application/json"], "Content-Length": [str(len(body))]},
    )
    scrub_interaction(interaction, SETTINGS)
    new_body = interaction["request"]["body"]
    assert json.loads(new_body) == {
        "refresh_token": REDACTED,
        "nested": [{"Client-Secret": REDACTED}],
        "token": "Paris",
        "empty": "",
    }
    assert interaction["request"]["headers"]["Content-Length"] == [str(len(new_body))]


def test_response_json_fields_are_redacted() -> None:
    body = json.dumps({"access_token": "ya29.x", "expires_in": 3599}).encode()
    interaction = _interaction(
        response={"headers": {"content-length": [str(len(body))]}, "body": body},
    )
    scrub_interaction(interaction, SETTINGS)
    new_body = interaction["response"]["body"]["string"]
    assert isinstance(new_body, bytes)
    assert json.loads(new_body) == {"access_token": REDACTED, "expires_in": 3599}
    assert interaction["response"]["headers"]["content-length"] == [str(len(new_body))]


def test_form_body_fields_are_redacted() -> None:
    token = refresh_token()
    body = f"grant_type=refresh_token&refresh_token={token}&client_id=app"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    assert redact_body_fields(body, headers, SETTINGS.body_fields) == (
        "grant_type=refresh_token&refresh_token=REDACTED&client_id=app"
    )


def test_bodies_are_left_alone_when_nothing_changes() -> None:
    fields = SETTINGS.body_fields
    for body in (
        b'{"model": "m",   "messages": []}',
        b"not json",
        b"\xff\xfe",
        b"",
        b"[1, 2",
        '{"access_token": "REDACTED"}',
    ):
        assert redact_body_fields(body, {}, fields) is body
    form = {"content-type": "application/x-www-form-urlencoded"}
    assert redact_body_fields("a=1&flag", form, fields) == "a=1&flag"
    gzipped = {"content-encoding": "gzip"}
    assert redact_body_fields(b'{"access_token": "x"}', gzipped, fields) == b'{"access_token": "x"}'
    assert redact_body_fields(None, {}, fields) is None


def test_odd_shapes_dont_break_scrubbing() -> None:
    interaction: dict[str, Any] = {"request": {"uri": 5}, "response": {"body": "text"}}
    scrub_interaction(interaction, SETTINGS)
    assert interaction == {"request": {"uri": 5}, "response": {"body": "text"}}


def test_presets_are_all_lower_case_and_included_by_default() -> None:
    for preset in PRESETS.values():
        for name in preset.request_headers | preset.response_headers | preset.query_params:
            assert name == name.lower()
    assert "x-goog-api-key" in default_request_headers()
    assert "key" in default_query_params()
    assert SETTINGS.headers >= default_request_headers()
