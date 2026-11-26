from __future__ import annotations

import base64
import json
import random
import re
from importlib import resources
from pathlib import Path
from typing import Any

import pytest

from safetape import RulesError, default_rules, load_rules
from safetape._rules import mask, parse_rules, shannon_entropy

from .fakes import SAMPLES, chars

RULES = default_rules()


def _raw_rules() -> dict[str, Any]:
    text = resources.files("safetape").joinpath("rules.json").read_text(encoding="utf-8")
    data: dict[str, Any] = json.loads(text)
    return data


def test_every_rule_has_a_sample() -> None:
    assert {rule.id for rule in RULES.rules} == set(SAMPLES)


@pytest.mark.parametrize("rule_id", sorted(SAMPLES))
def test_sample_is_found_by_its_rule(rule_id: str) -> None:
    sample = SAMPLES[rule_id]()
    hits = RULES.find(f"some text before {sample.text} and after")
    assert [hit.rule.id for hit in hits] == [rule_id]
    assert hits[0].value == sample.secret


@pytest.mark.parametrize("rule_id", sorted(SAMPLES))
def test_sample_is_found_inside_json(rule_id: str) -> None:
    sample = SAMPLES[rule_id]()
    text = json.dumps({"messages": [{"role": "user", "content": f"use {sample.text} please"}]})
    # Tool call arguments are JSON inside a JSON string, so quotes arrive escaped twice.
    nested = json.dumps({"arguments": text})
    for body in (text, nested):
        assert sample.secret in [hit.value for hit in RULES.find(body)]


# Python and JavaScript read these differently, or one of them can't read them at all.
_NOT_PORTABLE = [
    r"\(\?P",  # Python named groups
    r"\(\?<[A-Za-z]",  # JavaScript named groups
    r"\(\?>",  # atomic groups
    r"\(\?[aiLmsux-]+[:)]",  # inline flags
    r"[*+?}]\+",  # possessive quantifiers
    r"\\[AZzGpP]",  # anchors and classes only one side knows
]


@pytest.mark.parametrize("rule", _raw_rules()["rules"], ids=lambda r: r["id"])
def test_regex_is_portable(rule: dict[str, Any]) -> None:
    for construct in _NOT_PORTABLE:
        assert not re.search(construct, rule["regex"]), construct


def test_rule_ids_are_kebab_case() -> None:
    for rule in RULES.rules:
        assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", rule.id)


@pytest.mark.parametrize(
    "text",
    [
        "sk-" + "proj-" + "x" * 40,
        "sk-" + "ant-api03-" + "A" * 95,
        "AK" + "IAIOSFODNN7" + "EXAMPLE",
        '"api_key": "your-api-key-goes-here"',
        '"api_key": "REDACTED"',
        "Authorization: Bearer YOUR_TOKEN",
        "Authorization: Bearer REDACTED",
        "export OPENAI_API_KEY=sk-...",
        "postgres://app:changeme-please@localhost/db",
        "Bearer " + "fake" + chars(30),
    ],
)
def test_placeholders_are_not_secrets(text: str) -> None:
    assert RULES.find(text) == []


def _llm_traffic() -> str:
    rng = random.Random(7)
    image = base64.b64encode(rng.randbytes(150_000)).decode()
    payloads: list[Any] = [
        {
            "id": "chatcmpl-" + chars(29),
            "object": "chat.completion",
            "system_fingerprint": "fp_" + chars(10, "0123456789abcdef"),
            "choices": [
                {
                    "message": {"role": "assistant", "content": "Paris is the capital."},
                    "logprobs": {"content": [{"token": "Paris", "logprob": -0.01}]},
                },
            ],
            "usage": {"prompt_tokens": 12, "completion_tokens": 7, "total_tokens": 19},
        },
        {
            "id": "msg_01" + chars(22),
            "type": "message",
            "content": [{"type": "tool_use", "id": "toolu_01" + chars(22), "name": "get_weather"}],
            "usage": {"input_tokens": 20, "output_tokens": 15},
        },
        {"models": [{"name": "models/gemini-2.5-pro"}], "nextPageToken": chars(40)},
        {"page_token": chars(48), "next_token": chars(48)},
        {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:image/png;base64,{image}"},
                        }
                    ],
                },
            ],
        },
        "anthropic-ratelimit-tokens-reset: 2026-11-26T10:00:00Z",
        "x-request-id: req_" + chars(24),
        "The token budget is 4096 tokens and the secret is to keep prompts short.",
        "Set OPENAI_API_KEY in your shell, then run the script.",
    ]
    return "\n".join(p if isinstance(p, str) else json.dumps(p) for p in payloads)


def test_no_false_positives_in_typical_llm_traffic() -> None:
    assert RULES.find(_llm_traffic()) == []


def test_overlapping_matches_count_once() -> None:
    key = SAMPLES["openai-key"]().secret
    hits = RULES.find(f"Authorization: Bearer {key}")
    assert [hit.rule.id for hit in hits] == ["openai-key"]


def test_redact_masks_every_secret() -> None:
    first, second = SAMPLES["groq-key"]().secret, SAMPLES["github-token"]().secret
    redacted = RULES.redact(f"a {first} b {second} c")
    assert first not in redacted
    assert second not in redacted
    assert redacted.startswith("a <groq-key: gsk_... (56 chars)> b <github-token: ")
    assert RULES.redact("nothing here") == "nothing here"


def test_mask_never_shows_much() -> None:
    assert mask("short") == "[5 chars]"
    assert mask("abcdefghijklmnop") == "abcd... (16 chars)"


def test_entropy() -> None:
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == pytest.approx(2.0)


def test_allow_patterns_and_extension() -> None:
    sample = SAMPLES["groq-key"]()
    allowed = RULES.extended(allow_patterns=[re.compile(re.escape(sample.secret[:12]))])
    assert allowed.find(sample.text) == []
    assert RULES.find(sample.text) != []


def _rules_file(**overrides: Any) -> dict[str, Any]:
    rule = {
        "id": "corp-token",
        "description": "Corp token",
        "regex": "corp_[0-9]{8}",
        "keywords": ["corp_"],
    }
    data: dict[str, Any] = {"version": 1, "rules": [rule]}
    rule.update(overrides.pop("rule", {}))
    data.update(overrides)
    return data


def test_load_rules_from_file(tmp_path: Path) -> None:
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(_rules_file(allow=["corp_00000000"])), encoding="utf-8")
    ruleset = load_rules(path)
    assert [hit.rule.id for hit in ruleset.find("x corp_12345678 y")] == ["corp-token"]
    assert ruleset.find("corp_00000000") == []


def test_load_rules_reports_unreadable_file(tmp_path: Path) -> None:
    path = tmp_path / "rules.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(RulesError, match="can't read rules file"):
        load_rules(path)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ([], "expected a JSON object"),
        (_rules_file(extra=1), "unknown keys"),
        (_rules_file(version=2), "unsupported version"),
        (_rules_file(allow=[""]), "'allow' must be"),
        (_rules_file(rules={}), "'rules' must be a list"),
        (_rules_file(rules=["x"]), "expected an object"),
        (_rules_file(rule={"colour": "red"}), "unknown keys"),
        ({"version": 1, "rules": [{"id": "x"}]}, "missing keys"),
        (_rules_file(rule={"id": ""}), "non-empty strings"),
        (_rules_file(rule={"keywords": "corp_"}), "'keywords' must be"),
        (_rules_file(rule={"flags": "g"}), "'flags' can only be"),
        (_rules_file(rule={"regex": "("}), "bad regex"),
        (_rules_file(rule={"secret_group": 1}), "'secret_group' must"),
        (_rules_file(rule={"min_entropy": -1}), "'min_entropy' must"),
        (_rules_file(suspicious_headers=[]), "expected an object"),
        (_rules_file(suspicious_headers={"other": 1}), "unknown keys"),
        (_rules_file(suspicious_headers={"min_length": 3}), "suspicious_headers"),
    ],
)
def test_bad_rules_are_rejected(data: Any, message: str) -> None:
    with pytest.raises(RulesError, match=message):
        parse_rules(data)


def test_duplicate_rule_ids_are_rejected() -> None:
    data = _rules_file()
    data["rules"].append(dict(data["rules"][0]))
    with pytest.raises(RulesError, match="used twice"):
        parse_rules(data)


def test_header_check() -> None:
    check = RULES.header_check
    assert check is not None
    assert check.flags("X-Portkey-Session-Token", chars(32))
    assert not check.flags("x-request-id", chars(32))
    assert not check.flags("x-ratelimit-remaining-tokens", chars(32))
    assert not check.flags("x-session-token", "short")
    assert not check.flags("x-session-token", "a" * 20 + "1")
