"""Real HTTP traffic recorded and replayed through vcrpy with safetape installed."""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import requests
import vcr
from vcr.errors import CannotOverwriteExistingCassetteException

from safetape import LockdownError, SafePersister, SecretFoundError, Settings, install

from .conftest import Route, Server
from .fakes import anthropic_key, chars, google_key, openai_key

CHAT_ANSWER = {"id": "chatcmpl-1", "choices": [{"message": {"content": "café"}}]}


def _vcr(tmp_path: Path, serializer: str = "json", **settings: Any) -> Any:
    settings.setdefault("lockdown", False)
    my_vcr = vcr.VCR(
        cassette_library_dir=str(tmp_path),
        serializer=serializer,
        match_on=["method", "scheme", "host", "port", "path", "query", "body"],
    )
    return install(my_vcr, Settings(**settings))


def _chat_route(server: Server) -> None:
    server.routes["/v1/chat/completions"] = Route(
        json.dumps(CHAT_ANSWER, indent=2).encode(),
        headers={
            "content-type": "application/json",
            "openai-organization": "my-org",
            "set-cookie": "__cf_bm=abc123; path=/; HttpOnly",
            "x-request-id": "req_1",
        },
    )


def test_credentials_never_reach_the_cassette(server: Server, tmp_path: Path) -> None:
    _chat_route(server)
    my_vcr = _vcr(tmp_path)
    key = openai_key()
    with my_vcr.use_cassette("chat.json"):
        response = httpx.post(
            f"{server.url}/v1/chat/completions",
            json={"model": "gpt-5", "messages": [{"role": "user", "content": "hi"}]},
            headers={"Authorization": f"Bearer {key}", "OpenAI-Project": "proj_1"},
        )
    assert response.json() == CHAT_ANSWER

    text = (tmp_path / "chat.json").read_text(encoding="utf-8")
    assert key not in text
    for name in ("authorization", "openai-project", "openai-organization", "set-cookie"):
        assert name not in text.lower()
    assert "x-request-id" in text
    stored = json.loads(text)["interactions"][0]
    assert stored["request"]["body"] == {
        "json": {"model": "gpt-5", "messages": [{"role": "user", "content": "hi"}]},
    }
    assert stored["response"]["body"] == {"json": CHAT_ANSWER}


@pytest.mark.parametrize("client", ["httpx", "requests"])
def test_replay_works_offline_with_a_fixed_content_length(
    server: Server,
    tmp_path: Path,
    client: str,
) -> None:
    _chat_route(server)
    my_vcr = _vcr(tmp_path)
    url = f"{server.url}/v1/chat/completions"
    payload = {"model": "gpt-5"}

    def call() -> Any:
        if client == "httpx":
            return httpx.post(url, json=payload, headers={"x-api-key": anthropic_key()})
        return requests.post(url, json=payload, headers={"x-api-key": anthropic_key()}, timeout=5)

    with my_vcr.use_cassette("chat.json"):
        call()
    assert server.hits == ["/v1/chat/completions"]

    with my_vcr.use_cassette("chat.json", record_mode="none"):
        response = call()
    assert server.hits == ["/v1/chat/completions"]
    assert response.json() == CHAT_ANSWER
    assert int(response.headers["content-length"]) == len(response.content)


def test_query_keys_are_stripped_and_still_match(server: Server, tmp_path: Path) -> None:
    server.routes["/v1beta/models"] = Route(
        b'{"models": []}', headers={"content-type": "application/json"}
    )
    my_vcr = _vcr(tmp_path)
    first, second = google_key(), google_key()
    with my_vcr.use_cassette("models.json"):
        httpx.get(f"{server.url}/v1beta/models", params={"key": first, "pageSize": 5})
    text = (tmp_path / "models.json").read_text(encoding="utf-8")
    assert first not in text
    assert "pageSize=5" in text

    with my_vcr.use_cassette("models.json", record_mode="none"):
        response = httpx.get(f"{server.url}/v1beta/models", params={"key": second, "pageSize": 5})
    assert response.json() == {"models": []}
    assert len(server.hits) == 1


def test_streamed_responses_replay_event_by_event(server: Server, tmp_path: Path) -> None:
    stream = (
        "event: message_start\n"
        'data: {"type":"message_start"}\n\n'
        "event: content_block_delta\n"
        'data: {"type":"content_block_delta","delta":{"text":"Hi"}}\n\n'
        "event: message_stop\n"
        'data: {"type":"message_stop"}\n\n'
    )
    server.routes["/v1/messages"] = Route(
        stream.encode(), headers={"content-type": "text/event-stream"}
    )
    my_vcr = _vcr(tmp_path)

    def events() -> list[str]:
        with httpx.stream("POST", f"{server.url}/v1/messages", json={"stream": True}) as response:
            return [line for line in response.iter_lines() if line]

    with my_vcr.use_cassette("stream.json"):
        live = events()
    stored = json.loads((tmp_path / "stream.json").read_text(encoding="utf-8"))
    sse = stored["interactions"][0]["response"]["body"]["sse"]
    assert [event["event"] for event in sse] == [
        "message_start",
        "content_block_delta",
        "message_stop",
    ]
    assert sse[1]["data"] == {"type": "content_block_delta", "delta": {"text": "Hi"}}

    with my_vcr.use_cassette("stream.json", record_mode="none"):
        assert events() == live


def test_gzip_responses_are_stored_decompressed(server: Server, tmp_path: Path) -> None:
    server.routes["/v1/chat/completions"] = Route(
        gzip.compress(json.dumps(CHAT_ANSWER).encode()),
        headers={"content-type": "application/json", "content-encoding": "gzip"},
    )
    my_vcr = _vcr(tmp_path)
    with my_vcr.use_cassette("chat.json"):
        httpx.post(f"{server.url}/v1/chat/completions", json={})
    stored = json.loads((tmp_path / "chat.json").read_text(encoding="utf-8"))
    response = stored["interactions"][0]["response"]
    assert response["body"] == {"json": CHAT_ANSWER}
    assert "content-encoding" not in {name.lower() for name in response["headers"]}
    with my_vcr.use_cassette("chat.json", record_mode="none"):
        assert httpx.post(f"{server.url}/v1/chat/completions", json={}).json() == CHAT_ANSWER


def test_echoed_secret_stops_the_recording(server: Server, tmp_path: Path) -> None:
    key = openai_key()
    server.routes["/v1/echo"] = Route(
        json.dumps({"error": f"Incorrect API key provided: {key}"}).encode(),
        status=401,
        headers={"content-type": "application/json"},
    )
    my_vcr = _vcr(tmp_path)
    with pytest.raises(SecretFoundError) as error, my_vcr.use_cassette("echo.json"):
        httpx.post(f"{server.url}/v1/echo", json={})
    assert not (tmp_path / "echo.json").exists()
    assert "interaction 1, response body" in str(error.value)
    assert key not in str(error.value)


def test_a_refused_save_still_removes_vcrpys_patches(server: Server, tmp_path: Path) -> None:
    original = httpx.HTTPTransport.handle_request
    server.routes["/v1/echo"] = Route(f"key {openai_key()}".encode())
    my_vcr = _vcr(tmp_path)
    with pytest.raises(SecretFoundError), my_vcr.use_cassette("echo.json"):
        httpx.get(f"{server.url}/v1/echo")
    assert httpx.HTTPTransport.handle_request is original

    def call() -> None:
        httpx.get(f"{server.url}/v1/echo")

    decorated = my_vcr.use_cassette("echo2.json")(call)

    with pytest.raises(SecretFoundError):
        decorated()
    assert httpx.HTTPTransport.handle_request is original


def test_yaml_cassettes_are_protected_too(server: Server, tmp_path: Path) -> None:
    _chat_route(server)
    my_vcr = _vcr(tmp_path, serializer="yaml")
    key = openai_key()
    with my_vcr.use_cassette("chat.yaml"):
        httpx.post(
            f"{server.url}/v1/chat/completions", json={}, headers={"Authorization": f"Bearer {key}"}
        )
    text = (tmp_path / "chat.yaml").read_text(encoding="utf-8")
    assert key not in text
    assert "authorization" not in text.lower()


def test_lockdown_never_touches_the_network(server: Server, tmp_path: Path) -> None:
    _chat_route(server)
    my_vcr = _vcr(tmp_path, lockdown=True)
    with (
        pytest.raises(CannotOverwriteExistingCassetteException),
        my_vcr.use_cassette(
            "missing.json",
            record_mode="all",
        ),
    ):
        httpx.post(f"{server.url}/v1/chat/completions", json={})
    assert server.hits == []
    assert not (tmp_path / "missing.json").exists()

    def call() -> None:
        httpx.post(f"{server.url}/v1/chat/completions", json={})

    # Used bare, use_cassette names the cassette after the function.
    decorated = my_vcr.use_cassette(call)

    with pytest.raises(CannotOverwriteExistingCassetteException):
        decorated()
    assert server.hits == []


def test_lockdown_shows_a_masked_diff_for_a_missing_recording(
    server: Server, tmp_path: Path
) -> None:
    _chat_route(server)
    _vcr_recording = _vcr(tmp_path)
    url = f"{server.url}/v1/chat/completions"
    with _vcr_recording.use_cassette("chat.json"):
        httpx.post(url, json={"model": "gpt-5", "messages": [{"content": "hello"}]})

    key = openai_key()
    locked = _vcr(tmp_path, lockdown=True)
    with (
        pytest.raises(CannotOverwriteExistingCassetteException) as error,
        locked.use_cassette("chat.json"),
    ):
        httpx.post(url, json={"model": "gpt-5", "messages": [{"content": f"my key is {key}"}]})
    message = str(error.value)
    assert '-      "content": "hello"' in message
    assert '+      "content": "my key is <openai-key: sk-p...' in message
    assert len(server.hits) == 1


def test_install_matches_on_body_unless_match_on_was_set() -> None:
    assert install(vcr.VCR()).match_on[-1] == "body"
    assert install(vcr.VCR(match_on=["method", "uri"])).match_on == ["method", "uri"]


def test_installing_twice_is_harmless(tmp_path: Path) -> None:
    my_vcr = _vcr(tmp_path, lockdown=True)
    wrapped = my_vcr.use_cassette
    install(my_vcr, Settings(lockdown=True))
    assert my_vcr.use_cassette is wrapped


def test_lockdown_error_is_raised_for_recordings_that_slip_through(tmp_path: Path) -> None:
    my_vcr = _vcr(tmp_path)
    my_vcr.persister.settings = Settings(lockdown=True)
    request = vcr.request.Request("GET", "https://example.com/", None, {})
    response = {"status": {"code": 200, "message": "OK"}, "headers": {}, "body": {"string": b""}}
    with pytest.raises(LockdownError), my_vcr.use_cassette("x.json") as cassette:
        cassette.append(request, response)


def test_playback_errors_dont_show_the_live_requests_secrets(
    server: Server,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _chat_route(server)
    url = f"{server.url}/v1/chat/completions"
    with _vcr(tmp_path).use_cassette("chat.json"):
        httpx.post(url, json={"messages": [{"content": "hello"}]})

    header_key, query_key, env_key = chars(32), chars(24), chars(32)
    monkeypatch.setenv("MISTRAL_API_KEY", env_key)
    with (
        pytest.raises(CannotOverwriteExistingCassetteException) as error,
        _vcr(tmp_path).use_cassette("chat.json", record_mode="none"),
    ):
        httpx.post(
            f"{url}?key={query_key}",
            json={"messages": [{"content": f"keys {header_key} and {env_key}"}]},
            headers={"Authorization": f"Bearer {header_key}"},
        )
    message = str(error.value)
    for secret in (header_key, query_key, env_key):
        assert secret not in message
    assert "?key=<known-secret:" in message


def test_playback_errors_are_masked_without_install_too(server: Server, tmp_path: Path) -> None:
    # vcrpy is fixed for the whole process once safetape is in use.
    SafePersister()
    plain = vcr.VCR(cassette_library_dir=str(tmp_path), record_mode="none")
    key = google_key()
    with pytest.raises(CannotOverwriteExistingCassetteException) as error, plain.use_cassette("x"):
        httpx.get(f"{server.url}/v1/models?key={key}")
    assert key not in str(error.value)
