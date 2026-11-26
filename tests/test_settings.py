from __future__ import annotations

import json
from pathlib import Path

import pytest

from safetape import Settings
from safetape._settings import resolve_lockdown


@pytest.mark.parametrize(
    ("value", "environ", "expected"),
    [
        (True, {}, True),
        (False, {"CI": "true", "SAFETAPE_LOCKDOWN": "1"}, False),
        (None, {}, False),
        (None, {"CI": "true"}, True),
        (None, {"CI": "1"}, True),
        (None, {"CI": "woodpecker"}, True),
        (None, {"CI": "false"}, False),
        (None, {"CI": ""}, False),
        (None, {"CI": "true", "SAFETAPE_LOCKDOWN": "off"}, False),
        (None, {"SAFETAPE_LOCKDOWN": "Yes"}, True),
    ],
)
def test_resolve_lockdown(value: bool | None, environ: dict[str, str], expected: bool) -> None:
    assert resolve_lockdown(value, environ) is expected


def test_bad_lockdown_variable() -> None:
    with pytest.raises(ValueError, match="SAFETAPE_LOCKDOWN should be on or off"):
        resolve_lockdown(None, {"SAFETAPE_LOCKDOWN": "maybe"})


def test_lockdown_reads_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CI", "true")
    assert Settings().lockdown_active
    assert not Settings(lockdown=False).lockdown_active


def test_extras_add_to_the_defaults() -> None:
    settings = Settings(
        redact_headers=["X-Corp-Auth"],
        redact_query_params=["Sig2"],
        redact_body_fields=["corp_secret"],
    )
    assert {"authorization", "x-corp-auth"} <= settings.headers
    assert {"key", "sig2"} <= settings.query_params
    assert {"refreshtoken", "corpsecret"} <= settings.body_fields


def test_rules_files_and_allow(tmp_path: Path) -> None:
    rules = {
        "version": 1,
        "allow": ["corp_0000"],
        "rules": [
            {
                "id": "corp",
                "description": "Corp token",
                "regex": "corp_[0-9]{8}",
                "keywords": ["corp_"],
            }
        ],
    }
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(rules), encoding="utf-8")
    ruleset = Settings(rules_files=[path], allow=["^corp_1"]).ruleset
    found = {hit.value for hit in ruleset.find("corp_23456789 corp_00001234 corp_12345678")}
    assert found == {"corp_23456789"}
    assert "openai-key" in {rule.id for rule in ruleset.rules}
