"""The real OpenAI and Anthropic SDKs, recorded and replayed through safetape.

They talk to the local test server with fake keys, so nothing here reaches a
provider. Both SDKs send requests with httpx2, which vcrpy patches too.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import anthropic
import openai
import pytest
import vcr
from vcr.errors import CannotOverwriteExistingCassetteException

from safetape import SecretFoundError, Settings, install

from .conftest import Route, Server
from .fakes import anthropic_key, chars, openai_key

CHAT = {
    "id": "chatcmpl-1",
    "object": "chat.completion",
    "created": 1764201600,
    "model": "gpt-5-mini",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "Paris."},
            "finish_reason": "stop",
        },
    ],
    "usage": {"prompt_tokens": 9, "completion_tokens": 2, "total_tokens": 11},
}

MESSAGE = {
    "id": "msg_01",
    "type": "message",
    "role": "assistant",
    "model": "claude-test",
    "content": [{"type": "text", "text": "Paris."}],
    "stop_reason": "end_turn",
    "stop_sequence": None,
    "usage": {"input_tokens": 9, "output_tokens": 2},
}


def _chunk(content: str | None, finish: str | None = None) -> dict[str, Any]:
    delta = {"content": content} if content else {}
    return {
        "id": "chatcmpl-2",
        "object": "chat.completion.chunk",
        "created": 1764201600,
        "model": "gpt-5-mini",
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
    }


def _sse(*events: tuple[str | None, Any]) -> bytes:
    out = []
    for name, data in events:
        if name:
            out.append(f"event: {name}\n")
        out.append(f"data: {data if isinstance(data, str) else json.dumps(data)}\n\n")
    return "".join(out).encode()


OPENAI_STREAM = _sse(
    (None, _chunk("Par")),
    (None, _chunk("is.")),
    (None, _chunk(None, "stop")),
    (None, "[DONE]"),
)

ANTHROPIC_STREAM = _sse(
    ("message_start", {"type": "message_start", "message": {**MESSAGE, "content": []}}),
    (
        "content_block_start",
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
    ),
    (
        "content_block_delta",
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": "Paris."},
        },
    ),
    ("content_block_stop", {"type": "content_block_stop", "index": 0}),
    (
        "message_delta",
        {
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn"},
            "usage": {"output_tokens": 2},
        },
    ),
    ("message_stop", {"type": "message_stop"}),
)

JSON = {"content-type": "application/json"}
EVENTS = {"content-type": "text/event-stream"}
# Typed loosely, since each SDK wants its own TypedDict for the same shape.
QUESTION: Any = [{"role": "user", "content": "Capital of France?"}]


def _vcr(tmp_path: Path, **settings: Any) -> Any:
    settings.setdefault("lockdown", False)
    return install(
        vcr.VCR(cassette_library_dir=str(tmp_path), serializer="json"),
        Settings(**settings),
    )


def _openai(server: Server, key: str | None = None) -> openai.OpenAI:
    return openai.OpenAI(api_key=key or openai_key(), base_url=f"{server.url}/v1", max_retries=0)


def _anthropic(server: Server, key: str | None = None) -> anthropic.Anthropic:
    return anthropic.Anthropic(api_key=key or anthropic_key(), base_url=server.url, max_retries=0)


def _stored(tmp_path: Path, name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((tmp_path / name).read_text(encoding="utf-8"))
    return data


def test_openai_chat(server: Server, tmp_path: Path) -> None:
    server.routes["/v1/chat/completions"] = Route(
        json.dumps(CHAT).encode(),
        headers={**JSON, "openai-organization": "org-test", "set-cookie": "__cf_bm=x; path=/"},
    )
    key = openai_key()
    my_vcr = _vcr(tmp_path)
    with my_vcr.use_cassette("chat.json"):
        reply = _openai(server, key).chat.completions.create(model="gpt-5-mini", messages=QUESTION)
    assert reply.choices[0].message.content == "Paris."

    text = (tmp_path / "chat.json").read_text(encoding="utf-8")
    assert key not in text
    for header in ("authorization", "openai-organization", "set-cookie"):
        assert header not in text.lower()
    request = _stored(tmp_path, "chat.json")["interactions"][0]["request"]
    assert request["body"] == {"json": {"model": "gpt-5-mini", "messages": QUESTION}}

    # A different key on replay still matches, and nothing reaches the server.
    with my_vcr.use_cassette("chat.json", record_mode="none"):
        again = _openai(server).chat.completions.create(model="gpt-5-mini", messages=QUESTION)
    assert again.choices[0].message.content == "Paris."
    assert server.hits == ["/v1/chat/completions"]


def test_openai_streaming(server: Server, tmp_path: Path) -> None:
    server.routes["/v1/chat/completions"] = Route(OPENAI_STREAM, headers=EVENTS)
    my_vcr = _vcr(tmp_path)

    def ask() -> str:
        stream: Any = _openai(server).chat.completions.create(
            model="gpt-5-mini",
            messages=QUESTION,
            stream=True,
        )
        return "".join(chunk.choices[0].delta.content or "" for chunk in stream)

    with my_vcr.use_cassette("stream.json"):
        assert ask() == "Paris."
    events = _stored(tmp_path, "stream.json")["interactions"][0]["response"]["body"]["sse"]
    assert events[0]["data"]["choices"][0]["delta"] == {"content": "Par"}
    assert events[-1] == {"data": "[DONE]"}

    with my_vcr.use_cassette("stream.json", record_mode="none"):
        assert ask() == "Paris."
    assert len(server.hits) == 1


def test_openai_async(server: Server, tmp_path: Path) -> None:
    server.routes["/v1/chat/completions"] = Route(json.dumps(CHAT).encode(), headers=JSON)
    my_vcr = _vcr(tmp_path)

    async def ask() -> str | None:
        client = openai.AsyncOpenAI(
            api_key=openai_key(),
            base_url=f"{server.url}/v1",
            max_retries=0,
        )
        async with client:
            reply = await client.chat.completions.create(model="gpt-5-mini", messages=QUESTION)
        return reply.choices[0].message.content

    with my_vcr.use_cassette("async.json"):
        assert asyncio.run(ask()) == "Paris."
    with my_vcr.use_cassette("async.json", record_mode="none"):
        assert asyncio.run(ask()) == "Paris."
    assert len(server.hits) == 1


def test_anthropic_messages(server: Server, tmp_path: Path) -> None:
    server.routes["/v1/messages"] = Route(
        json.dumps(MESSAGE).encode(),
        headers={**JSON, "anthropic-organization-id": "org-uuid"},
    )
    key = anthropic_key()
    my_vcr = _vcr(tmp_path)
    with my_vcr.use_cassette("messages.json"):
        reply = _anthropic(server, key).messages.create(
            model="claude-test",
            max_tokens=10,
            messages=QUESTION,
        )
    assert reply.content[0].text == "Paris."  # type: ignore[union-attr]
    text = (tmp_path / "messages.json").read_text(encoding="utf-8")
    assert key not in text
    assert "x-api-key" not in text.lower()
    assert "anthropic-organization-id" not in text.lower()

    with my_vcr.use_cassette("messages.json", record_mode="none"):
        again = _anthropic(server).messages.create(
            model="claude-test",
            max_tokens=10,
            messages=QUESTION,
        )
    assert again.content[0].text == "Paris."  # type: ignore[union-attr]
    assert len(server.hits) == 1


def test_anthropic_streaming_async(server: Server, tmp_path: Path) -> None:
    server.routes["/v1/messages"] = Route(ANTHROPIC_STREAM, headers=EVENTS)
    my_vcr = _vcr(tmp_path)

    async def ask() -> str:
        client = anthropic.AsyncAnthropic(
            api_key=anthropic_key(),
            base_url=server.url,
            max_retries=0,
        )
        async with client:
            stream: Any = await client.messages.create(
                model="claude-test",
                max_tokens=10,
                messages=QUESTION,
                stream=True,
            )
            parts = []
            async for event in stream:
                if event.type == "content_block_delta" and event.delta.type == "text_delta":
                    parts.append(event.delta.text)
        return "".join(parts)

    with my_vcr.use_cassette("stream.json"):
        assert asyncio.run(ask()) == "Paris."
    events = _stored(tmp_path, "stream.json")["interactions"][0]["response"]["body"]["sse"]
    assert [event["event"] for event in events][:2] == ["message_start", "content_block_start"]

    with my_vcr.use_cassette("stream.json", record_mode="none"):
        assert asyncio.run(ask()) == "Paris."
    assert len(server.hits) == 1


def test_missing_recording_through_the_sdk(server: Server, tmp_path: Path) -> None:
    server.routes["/v1/chat/completions"] = Route(json.dumps(CHAT).encode(), headers=JSON)
    with _vcr(tmp_path).use_cassette("chat.json"):
        _openai(server).chat.completions.create(model="gpt-5-mini", messages=QUESTION)

    key = openai_key()
    changed: Any = [{"role": "user", "content": f"Capital of Spain? My key is {key}"}]
    locked = _vcr(tmp_path, lockdown=True)
    raised = (CannotOverwriteExistingCassetteException, openai.APIConnectionError)
    with pytest.raises(raised) as error, locked.use_cassette("chat.json"):
        _openai(server, key).chat.completions.create(model="gpt-5-mini", messages=changed)

    # Current SDKs let vcrpy's error through. Older ones wrapped it in
    # APIConnectionError("Connection error.") with vcrpy's error as the cause.
    playback = error.value
    if isinstance(playback, openai.APIConnectionError):
        playback = playback.__cause__
    assert isinstance(playback, CannotOverwriteExistingCassetteException)
    assert "Capital of Spain" in str(playback)
    assert key not in str(playback)
    assert len(server.hits) == 1


def test_a_shapeless_key_in_a_prompt_is_caught(server: Server, tmp_path: Path) -> None:
    # An OpenAI-compatible provider whose keys have no prefix, like Mistral's.
    server.routes["/v1/chat/completions"] = Route(json.dumps(CHAT).encode(), headers=JSON)
    key = chars(32)
    leaky: Any = [{"role": "user", "content": f"Why does {key} not work?"}]
    with pytest.raises(SecretFoundError) as error, _vcr(tmp_path).use_cassette("leak.json"):
        _openai(server, key).chat.completions.create(model="mistral-small", messages=leaky)
    assert [f.rule_id for f in error.value.findings] == ["known-secret"]
    assert not (tmp_path / "leak.json").exists()
