from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
from typing import Any

import pytest
from vcr.cassette import Cassette
from vcr.persisters.filesystem import CassetteDecodeError, CassetteNotFoundError
from vcr.request import Request
from vcr.serializers import yamlserializer

from safetape import (
    LockdownError,
    SafePersister,
    SecretFoundError,
    Settings,
    StaleCassette,
    StaleCassetteWarning,
    serializer,
)

from .fakes import chars, openai_key, refresh_token

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)


def _cassette(
    body: str = '{"ok": true}',
    *,
    request_headers: dict[str, str] | None = None,
    recorded: datetime | None = NOW,
    count: int = 1,
) -> dict[str, Any]:
    headers: dict[str, list[str]] = {"content-type": ["application/json"]}
    if recorded is not None:
        headers["date"] = [format_datetime(recorded, usegmt=True)]
    requests = [
        Request("POST", f"https://api.example.com/v1/{n}", "{}", request_headers or {})
        for n in range(count)
    ]
    responses = [
        {
            "status": {"code": 200, "message": "OK"},
            "headers": dict(headers),
            "body": {"string": body.encode()},
        }
        for _ in range(count)
    ]
    return {"requests": requests, "responses": responses}


def _persister(**settings: Any) -> SafePersister:
    settings.setdefault("lockdown", False)
    return SafePersister(Settings(**settings), clock=lambda: NOW)


@pytest.mark.parametrize(
    "cassette_serializer", [serializer, yamlserializer], ids=["safetape", "yaml"]
)
def test_save_and_load(tmp_path: Path, cassette_serializer: Any) -> None:
    path = tmp_path / "nested" / "chat.cassette"
    persister = _persister()
    persister.save_cassette(
        path, _cassette(request_headers={"Authorization": "Bearer x"}), cassette_serializer
    )
    requests, responses = persister.load_cassette(path, cassette_serializer)
    assert [r.uri for r in requests] == ["https://api.example.com/v1/0"]
    assert "Authorization" not in requests[0].headers
    assert json.loads(responses[0]["body"]["string"]) == {"ok": True}
    assert [p.name for p in path.parent.iterdir()] == ["chat.cassette"]


def test_files_are_utf8_with_unix_newlines(tmp_path: Path) -> None:
    path = tmp_path / "c.json"
    _persister().save_cassette(path, _cassette('{"text": "café ✓"}'), serializer)
    raw = path.read_bytes()
    assert "café ✓".encode() in raw
    assert b"\r\n" not in raw
    _, responses = _persister().load_cassette(path, serializer)
    assert "café" in responses[0]["body"]["string"].decode()


def test_a_byte_order_mark_is_fine(tmp_path: Path) -> None:
    path = tmp_path / "c.json"
    _persister().save_cassette(path, _cassette(), serializer)
    path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes())
    requests, _ = _persister().load_cassette(path, serializer)
    assert len(requests) == 1


def test_missing_empty_and_broken_files(tmp_path: Path) -> None:
    persister = _persister()
    with pytest.raises(CassetteNotFoundError):
        persister.load_cassette(tmp_path / "missing.json", serializer)
    blank = tmp_path / "blank.json"
    blank.write_text("  \n", encoding="utf-8")
    with pytest.raises(CassetteNotFoundError):
        persister.load_cassette(blank, serializer)
    broken = tmp_path / "broken.json"
    broken.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(CassetteDecodeError, match="isn't valid UTF-8"):
        persister.load_cassette(broken, serializer)


def test_secret_stops_the_save_and_keeps_the_old_file(tmp_path: Path) -> None:
    path = tmp_path / "c.json"
    persister = _persister()
    persister.save_cassette(path, _cassette(), serializer)
    before = path.read_bytes()

    key = openai_key()
    with pytest.raises(SecretFoundError) as error:
        persister.save_cassette(path, _cassette(f'{{"echo": "{key}"}}'), serializer)

    assert path.read_bytes() == before
    assert [p.name for p in tmp_path.iterdir()] == ["c.json"]
    message = str(error.value)
    assert key not in message
    assert "interaction 1, response body: OpenAI project" in message
    assert "Nothing was written" in message
    assert error.value.path == os.fspath(path)
    assert [f.rule_id for f in error.value.findings] == ["openai-key"]


def test_error_counts_findings(tmp_path: Path) -> None:
    body = f'{{"a": "{openai_key()}", "b": "{openai_key()}"}}'
    with pytest.raises(SecretFoundError, match="2 things that look like secrets"):
        _persister().save_cassette(tmp_path / "c.json", _cassette(body), serializer)


def test_allow_list_lets_a_value_through(tmp_path: Path) -> None:
    key = openai_key()
    path = tmp_path / "c.json"
    _persister(allow=[key[:20]]).save_cassette(path, _cassette(f'{{"k": "{key}"}}'), serializer)
    assert key in path.read_text(encoding="utf-8")


def test_secrets_the_serializer_adds_are_caught(tmp_path: Path) -> None:
    key = openai_key()

    class Leaky:
        @staticmethod
        def serialize(data: Any) -> str:
            return serializer.serialize(data) + key

        @staticmethod
        def deserialize(text: str) -> Any:
            return serializer.deserialize(text)

    with pytest.raises(SecretFoundError, match="cassette file"):
        _persister().save_cassette(tmp_path / "c.json", _cassette(), Leaky)
    assert not (tmp_path / "c.json").exists()


def test_bytes_from_a_serializer_are_written_as_is(tmp_path: Path) -> None:
    class Binary:
        @staticmethod
        def serialize(data: Any) -> bytes:
            return serializer.serialize(data).encode()

    path = tmp_path / "c.json"
    _persister().save_cassette(path, _cassette(), Binary)
    assert path.read_bytes().startswith(b"{")


@pytest.mark.skipif(
    not hasattr(Cassette, "get_metadata"),
    reason="cassette metadata arrived in vcrpy 9",
)
def test_metadata_is_scanned_and_returned(tmp_path: Path) -> None:
    path = tmp_path / "c.json"
    persister = _persister()
    cassette = {**_cassette(), "metadata": {"seed": 7}}
    persister.save_cassette(path, cassette, serializer)
    *_, metadata = persister.load_cassette(path, serializer)
    assert metadata == {"seed": 7}
    with pytest.raises(SecretFoundError, match="cassette metadata"):
        persister.save_cassette(path, {**_cassette(), "metadata": {"k": openai_key()}}, serializer)


def test_failed_write_leaves_no_temp_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "c.json"
    persister = _persister()
    persister.save_cassette(path, _cassette(), serializer)
    before = path.read_bytes()

    def broken_replace(self: Path, target: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(Path, "replace", broken_replace)
    with pytest.raises(OSError, match="disk full"):
        persister.save_cassette(path, _cassette(count=2), serializer)
    assert path.read_bytes() == before
    assert [p.name for p in tmp_path.iterdir()] == ["c.json"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_file_mode_is_kept(tmp_path: Path) -> None:
    path = tmp_path / "c.json"
    persister = _persister()
    persister.save_cassette(path, _cassette(), serializer)
    assert path.stat().st_mode & 0o777 == 0o644
    path.chmod(0o600)
    persister.save_cassette(path, _cassette(count=2), serializer)
    assert path.stat().st_mode & 0o777 == 0o600


def test_extra_paths_are_loaded_too(tmp_path: Path) -> None:
    shared = tmp_path / "shared.json"
    main = tmp_path / "main.json"
    _persister().save_cassette(shared, _cassette(count=2), serializer)
    persister = SafePersister(
        Settings(lockdown=False), extra_paths=[shared, tmp_path / "gone.json"]
    )
    requests, _ = persister.load_cassette(main, serializer)
    assert len(requests) == 2
    _persister().save_cassette(main, _cassette(), serializer)
    requests, _ = persister.load_cassette(main, serializer)
    assert len(requests) == 3


def test_old_cassettes_are_reported(tmp_path: Path) -> None:
    path = tmp_path / "c.json"
    _persister().save_cassette(path, _cassette(recorded=NOW - timedelta(days=200)), serializer)
    seen: list[StaleCassette] = []
    SafePersister(Settings(), on_stale=seen.append, clock=lambda: NOW).load_cassette(
        path, serializer
    )
    assert seen == [StaleCassette(os.fspath(path), NOW - timedelta(days=200), 200)]
    assert seen[0].message.endswith(
        "was recorded 200 days ago (2026-05-10). Re-record it to catch API changes."
    )

    with pytest.warns(StaleCassetteWarning, match="200 days ago"):
        _persister().load_cassette(path, serializer)


@pytest.mark.parametrize(
    ("settings", "recorded"),
    [
        ({}, NOW - timedelta(days=30)),
        ({"stale_after_days": None}, NOW - timedelta(days=900)),
        ({}, None),
    ],
)
def test_fresh_or_undated_cassettes_are_fine(
    tmp_path: Path,
    settings: dict[str, Any],
    recorded: datetime | None,
) -> None:
    path = tmp_path / "c.json"
    _persister().save_cassette(path, _cassette(recorded=recorded), serializer)
    seen: list[StaleCassette] = []
    persister = SafePersister(Settings(**settings), on_stale=seen.append, clock=lambda: NOW)
    persister.load_cassette(path, serializer)
    assert seen == []


def test_odd_dates_are_ignored(tmp_path: Path) -> None:
    path = tmp_path / "c.json"
    cassette = _cassette()
    cassette["responses"][0]["headers"]["date"] = ["not a date"]
    _persister().save_cassette(path, cassette, serializer)
    _persister(stale_after_days=1).load_cassette(path, serializer)


def test_naive_dates_count_as_utc(tmp_path: Path) -> None:
    path = tmp_path / "c.json"
    cassette = _cassette()
    cassette["responses"][0]["headers"]["date"] = ["Mon, 01 Jan 2024 00:00:00 -0000"]
    _persister().save_cassette(path, cassette, serializer)
    with pytest.warns(StaleCassetteWarning):
        _persister().load_cassette(path, serializer)


def test_lockdown_refuses_new_recordings(tmp_path: Path) -> None:
    path = tmp_path / "c.json"
    _persister().save_cassette(path, _cassette(count=2), serializer)
    before = path.read_bytes()

    locked = _persister(lockdown=True)
    locked.load_cassette(path, serializer)
    # Rewriting what was loaded (drop_unused_requests does this) is skipped quietly.
    locked.save_cassette(path, _cassette(count=1), serializer)
    assert path.read_bytes() == before
    with pytest.raises(LockdownError, match="SAFETAPE_LOCKDOWN=0"):
        locked.save_cassette(path, _cassette(count=3), serializer)
    with pytest.raises(LockdownError):
        locked.save_cassette(tmp_path / "new.json", _cassette(), serializer)
    assert path.read_bytes() == before


def test_a_key_with_no_known_shape_is_caught_by_value(tmp_path: Path) -> None:
    # Mistral and Azure keys look like any random string, so only the value gives them away.
    key = chars(32)
    cassette = _cassette(f'{{"error": "key {key} is not valid"}}', request_headers={"api-key": key})
    with pytest.raises(SecretFoundError) as error:
        _persister().save_cassette(tmp_path / "c.json", cassette, serializer)
    assert [(f.rule_id, f.location) for f in error.value.findings] == [
        ("known-secret", "interaction 1, response body"),
    ]
    assert key not in str(error.value)
    assert not (tmp_path / "c.json").exists()


def test_environment_keys_are_caught_anywhere(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = chars(32)
    monkeypatch.setenv("COHERE_API_KEY", key)
    cassette = _cassette()
    cassette["requests"][0].body = f'{{"message": "my key is {key}"}}'
    with pytest.raises(SecretFoundError, match="interaction 1, request body: A credential"):
        _persister().save_cassette(tmp_path / "c.json", cassette, serializer)


def test_a_credential_from_one_interaction_is_caught_in_another(tmp_path: Path) -> None:
    token = refresh_token()
    cassette = _cassette(count=2)
    cassette["requests"][0] = Request(
        "POST",
        "https://oauth2.example.com/token",
        f"grant_type=refresh_token&refresh_token={token}",
        {"Content-Type": "application/x-www-form-urlencoded"},
    )
    cassette["responses"][1]["body"]["string"] = f'{{"echo": "{token}"}}'.encode()
    with pytest.raises(SecretFoundError) as error:
        _persister().save_cassette(tmp_path / "c.json", cassette, serializer)
    assert [f.location for f in error.value.findings] == ["interaction 2, response body"]


def test_allowed_values_are_not_hunted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake-key-for-tests")
    cassette = _cassette('{"note": "sk-fake-key-for-tests"}')
    _persister().save_cassette(tmp_path / "c.json", cassette, serializer)


def test_a_locked_file_gets_a_few_tries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "c.json"
    real_replace = Path.replace
    calls: list[int] = []

    def flaky_replace(self: Path, target: Any) -> Path:
        calls.append(1)
        if len(calls) < 3:
            raise PermissionError("in use")
        return real_replace(self, target)

    monkeypatch.setattr("safetape._persister._REPLACE_BACKOFF_SECONDS", 0)
    monkeypatch.setattr(Path, "replace", flaky_replace)
    _persister().save_cassette(path, _cassette(), serializer)
    assert len(calls) == 3
    assert path.exists()

    def locked(self: Path, target: Any) -> Path:
        raise PermissionError("in use")

    monkeypatch.setattr(Path, "replace", locked)
    with pytest.raises(PermissionError):
        _persister().save_cassette(path, _cassette(count=2), serializer)
    assert [p.name for p in tmp_path.iterdir()] == ["c.json"]


def test_safe_persister_fixes_vcrpy_by_itself(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    monkeypatch.setattr("safetape._persister.harden_vcrpy", lambda: calls.append(1))
    SafePersister()
    assert calls == [1]
