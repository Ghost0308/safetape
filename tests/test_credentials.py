from __future__ import annotations

import base64

import pytest
from vcr.request import Request

from safetape import REDACTED, Settings
from safetape import _credentials as credentials
from safetape._presets import CREDENTIAL_HEADERS
from safetape._redact import redact_text

from .fakes import chars, openai_key

SETTINGS = Settings()


def test_header_values_lose_their_auth_scheme() -> None:
    token, raw, password, session = chars(32), chars(40), chars(16), chars(16)
    basic = base64.b64encode(f"user:{password}".encode()).decode()
    headers = {
        "Authorization": [f"Bearer {token}"],
        "X-Api-Key": raw.encode(),
        "Proxy-Authorization": f"Basic {basic}",
        "Cookie": f"session={session}; theme=dark",
        "x-request-id": chars(32),
    }
    found = credentials.from_headers(headers, CREDENTIAL_HEADERS)
    assert {token, raw, password, session} <= found
    assert "dark" not in found
    assert headers["x-request-id"] not in found
    assert credentials.from_headers(None, CREDENTIAL_HEADERS) == set()
    assert credentials.from_headers({"authorization": "Basic !!!"}, CREDENTIAL_HEADERS) == {
        "Basic !!!",
    }


def test_short_and_redacted_values_are_left_out() -> None:
    headers = {"x-api-key": "short", "api-key": REDACTED}
    assert credentials.from_headers(headers, CREDENTIAL_HEADERS) == set()


def test_query_values() -> None:
    key = chars(30)
    uri = f"https://g.example.com/v1/models?key={key}&alt=sse"
    assert credentials.from_query(uri, SETTINGS.query_params) == {key}
    assert credentials.from_query(None, SETTINGS.query_params) == set()


def test_request_values() -> None:
    token, key = chars(32), chars(30)
    request = Request(
        "GET", f"https://x.example.com/?key={key}", None, {"Authorization": f"Bearer {token}"}
    )
    found = credentials.from_request(request, CREDENTIAL_HEADERS, SETTINGS.query_params)
    assert {token, key} <= found
    assert credentials.from_request(None, CREDENTIAL_HEADERS, SETTINGS.query_params) == set()


def test_environment_values() -> None:
    key = chars(32)
    environ = {
        "MISTRAL_API_KEY": f"  {key}  ",
        "AWS_SECRET_ACCESS_KEY": "wJalr/" + chars(34),
        "TOKENIZERS_PARALLELISM": "false",
        "MAX_TOKENS_TOTAL": "123456789012",
        "HF_TOKEN_PATH": "/home/me/.cache/huggingface/token",
        "ACTIONS_ID_TOKEN_REQUEST_URL": "https://example.com/token?x=1",
        "GOOGLE_APPLICATION_CREDENTIALS": "~/keys/service-account.json",
        "AZURE_CREDENTIALS_FILE": "C:\\keys\\azure.json",
        "HOME": chars(30),
    }
    assert credentials.from_environment(environ) == {key, environ["AWS_SECRET_ACCESS_KEY"]}


def test_remembered_values_are_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(credentials, "_remembered", set())
    monkeypatch.setattr(credentials, "_MAX_REMEMBERED", 2)
    credentials.remember(["aaaaaaaa1", "bbbbbbbb2", "cccccccc3"])
    assert credentials.remembered() == {"aaaaaaaa1", "bbbbbbbb2"}


def test_known_credentials_add_the_environment_and_respect_allow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_key, sent, fake = chars(32), chars(32), "fake" + chars(20)
    monkeypatch.setenv("COHERE_API_KEY", env_key)
    monkeypatch.setenv("OTHER_API_KEY", fake)
    other = chars(12)
    known = Settings(allow=[f"^{sent[:6]}"]).known_credentials({sent}, {other})
    assert env_key in known
    assert other in known
    assert sent not in known
    assert fake not in known


def test_user_headers_count_as_credentials_when_they_sound_secret() -> None:
    settings = Settings(redact_headers=["X-Corp-Auth", "X-Trace-Id"])
    assert "x-corp-auth" in settings.credential_headers
    assert "x-trace-id" not in settings.credential_headers
    assert "x-trace-id" in settings.headers


def test_redact_text() -> None:
    known, query_value, pattern = chars(32), chars(20), openai_key()
    text = f"sent {known} to https://x.example.com/v1?alt=sse&KEY={query_value}#top with {pattern}"
    clean = redact_text(text, SETTINGS, {known})
    for secret in (known, query_value, pattern):
        assert secret not in clean
    assert f"<known-secret: {known[:4]}... (32 chars)>" in clean
    assert "&KEY=REDACTED#top" in clean
    assert "<openai-key: sk-p..." in clean
    assert redact_text("nothing here", SETTINGS) == "nothing here"
