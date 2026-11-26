"""The pytest plugin, run inside real pytest sessions with pytest-recording."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from .conftest import Route, Server
from .fakes import openai_key

ANSWER = {"answer": 42}


def _write_tests(pytester: pytest.Pytester, server: Server, key: str) -> None:
    server.routes["/v1/chat"] = Route(
        json.dumps(ANSWER).encode(),
        headers={"content-type": "application/json", "set-cookie": "s=1"},
    )
    pytester.makepyfile(
        test_calls=f"""
        import httpx
        import pytest

        @pytest.mark.vcr
        def test_chat():
            response = httpx.post(
                "{server.url}/v1/chat",
                json={{"q": 1}},
                headers={{"Authorization": "Bearer {key}"}},
            )
            assert response.json() == {ANSWER!r}
        """,
    )


def _cassette(pytester: pytest.Pytester, suffix: str = "yaml") -> Path:
    return pytester.path / "cassettes" / "test_calls" / f"test_chat.{suffix}"


def test_recordings_are_scrubbed(pytester: pytest.Pytester, server: Server) -> None:
    key = openai_key()
    _write_tests(pytester, server, key)
    pytester.runpytest("--record-mode=once").assert_outcomes(passed=1)
    text = _cassette(pytester).read_text(encoding="utf-8")
    assert key not in text
    assert "authorization" not in text.lower()
    assert "set-cookie" not in text.lower()

    pytester.runpytest().assert_outcomes(passed=1)
    assert server.hits == ["/v1/chat"]


def test_prompts_replay_their_own_answers_in_any_order(
    pytester: pytest.Pytester,
    server: Server,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server.routes["/v1/chat"] = Route(b"", echo=True)
    pytester.makepyfile(
        test_calls=f"""
        import os
        import httpx
        import pytest

        @pytest.mark.vcr
        def test_chat():
            prompts = ["a", "b"] if os.environ.get("ORDER") != "reversed" else ["b", "a"]
            for prompt in prompts:
                reply = httpx.post("{server.url}/v1/chat", json={{"q": prompt}}).json()
                assert reply == {{"echo": {{"q": prompt}}}}
        """,
    )
    pytester.runpytest("--record-mode=once").assert_outcomes(passed=1)
    monkeypatch.setenv("ORDER", "reversed")
    pytester.runpytest().assert_outcomes(passed=1)
    assert len(server.hits) == 2


def test_json_serializer_is_the_readable_one(pytester: pytest.Pytester, server: Server) -> None:
    _write_tests(pytester, server, openai_key())
    pytester.makeconftest(
        """
        import pytest

        @pytest.fixture(scope="module")
        def vcr_config():
            return {"serializer": "json"}
        """,
    )
    pytester.runpytest("--record-mode=once").assert_outcomes(passed=1)
    stored = json.loads(_cassette(pytester, "json").read_text(encoding="utf-8"))
    assert stored["interactions"][0]["response"]["body"] == {"json": ANSWER}


def test_opting_out_with_p_no(pytester: pytest.Pytester, server: Server) -> None:
    key = openai_key()
    _write_tests(pytester, server, key)
    pytester.runpytest("--record-mode=once", "-p", "no:safetape").assert_outcomes(passed=1)
    assert key in _cassette(pytester).read_text(encoding="utf-8")


def test_secret_in_a_response_fails_the_test(pytester: pytest.Pytester, server: Server) -> None:
    key = openai_key()
    _write_tests(pytester, server, "x")
    server.routes["/v1/chat"] = Route(json.dumps({"echo": key}).encode())
    pytester.makepyfile(
        test_calls=f"""
        import httpx
        import pytest

        @pytest.mark.vcr
        def test_chat():
            httpx.post("{server.url}/v1/chat")
        """,
    )
    result = pytester.runpytest("--record-mode=once")
    result.assert_outcomes(passed=1, errors=1)
    result.stdout.fnmatch_lines(["*SecretFoundError*", "*interaction 1, response body*"])
    assert key not in result.stdout.str()
    assert not _cassette(pytester).exists()


def test_lockdown_replays_and_never_records(
    pytester: pytest.Pytester,
    server: Server,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_tests(pytester, server, openai_key())
    pytester.runpytest("--record-mode=once").assert_outcomes(passed=1)

    monkeypatch.setenv("CI", "true")
    # "rewrite" would delete the cassette first, so lockdown has to win over it.
    result = pytester.runpytest("--record-mode=rewrite")
    result.assert_outcomes(passed=1)
    result.stdout.fnmatch_lines(["safetape: lockdown is on*"])
    assert _cassette(pytester).exists()

    _cassette(pytester).unlink()
    result = pytester.runpytest("--record-mode=once")
    result.assert_outcomes(failed=1)
    assert not _cassette(pytester).exists()
    assert server.hits == ["/v1/chat"]


def test_lockdown_off_in_ini_wins_over_ci(
    pytester: pytest.Pytester,
    server: Server,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_tests(pytester, server, openai_key())
    pytester.makeini("[pytest]\nsafetape_lockdown = off\n")
    monkeypatch.setenv("CI", "true")
    result = pytester.runpytest("--record-mode=once")
    result.assert_outcomes(passed=1)
    assert "lockdown is on" not in result.stdout.str()


def test_old_cassettes_are_listed_at_the_end(pytester: pytest.Pytester, server: Server) -> None:
    _write_tests(pytester, server, openai_key())
    pytester.runpytest("--record-mode=once").assert_outcomes(passed=1)
    path = _cassette(pytester)
    text = path.read_text(encoding="utf-8")
    text = re.sub(
        r"(- )?\w{3}, \d{2} \w{3} \d{4} [\d:]{8} GMT", r"\1Mon, 05 Jan 2026 10:00:00 GMT", text
    )
    path.write_text(text, encoding="utf-8")

    result = pytester.runpytest()
    result.assert_outcomes(passed=1)
    result.stdout.fnmatch_lines(
        [
            "*= safetape =*",
            "These cassettes were recorded more than 90 days ago.*",
            f"  {Path('cassettes', 'test_calls', 'test_chat.yaml')} (* days old)",
        ],
    )

    pytester.makeini("[pytest]\nsafetape_stale_days = 0\n")
    assert "recorded more than" not in pytester.runpytest().stdout.str()


def test_ini_settings_reach_safetape(pytester: pytest.Pytester, server: Server) -> None:
    server.routes["/v1/chat"] = Route(b'{"ok": true}', headers={"x-corp-trace": "t-1"})
    pytester.makepyprojecttoml(
        """
        [tool.pytest.ini_options]
        safetape_redact_headers = ["x-corp-trace"]
        safetape_redact_query_params = ["corp_sig"]
        safetape_stale_days = 0
        """,
    )
    pytester.makepyfile(
        test_calls=f"""
        import httpx
        import pytest

        @pytest.mark.vcr
        def test_chat():
            httpx.get("{server.url}/v1/chat?corp_sig=abc&page=2")
        """,
    )
    pytester.runpytest("--record-mode=once").assert_outcomes(passed=1)
    text = _cassette(pytester).read_text(encoding="utf-8")
    assert "x-corp-trace" not in text
    assert "corp_sig" not in text
    assert "page=2" in text


@pytest.mark.parametrize(
    ("ini", "message"),
    [
        ("safetape_stale_days = soon", "safetape_stale_days should be a whole number"),
        ("safetape_lockdown = maybe", "safetape_lockdown should be auto, on or off"),
        ("safetape_allow = (", "safetape: missing ), unterminated subpattern"),
        ("safetape_rules = missing.json", "safetape: *missing.json: can't read rules file*"),
    ],
)
def test_bad_settings_stop_the_run(pytester: pytest.Pytester, ini: str, message: str) -> None:
    pytester.makeini(f"[pytest]\n{ini}\n")
    pytester.makepyfile("def test_nothing(): pass")
    result = pytester.runpytest()
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.fnmatch_lines([f"*{message}*"])


def test_bad_lockdown_variable_stops_the_run(
    pytester: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SAFETAPE_LOCKDOWN", "sometimes")
    pytester.makepyfile("def test_nothing(): pass")
    result = pytester.runpytest()
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.fnmatch_lines(["*SAFETAPE_LOCKDOWN should be on or off*"])
