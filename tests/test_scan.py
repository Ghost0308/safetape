from __future__ import annotations

import gzip
import importlib.util
import io
import zlib
from typing import Any

import pytest

from safetape import default_rules
from safetape._bodies import MAX_DECOMPRESSED_BYTES, UnscannableBody, text_for_scan, to_bytes
from safetape._scan import scan_interaction, scan_text

from .fakes import chars, google_key, openai_key

RULES = default_rules()


def _interaction(
    *,
    uri: str = "https://api.example.com/v1/chat",
    request_headers: dict[str, Any] | None = None,
    request_body: Any = None,
    response_headers: dict[str, Any] | None = None,
    response_body: Any = b"{}",
) -> dict[str, Any]:
    return {
        "request": {
            "method": "POST",
            "uri": uri,
            "body": request_body,
            "headers": request_headers or {},
        },
        "response": {
            "status": {"code": 200, "message": "OK"},
            "headers": response_headers or {},
            "body": {"string": response_body},
        },
    }


def test_clean_interaction_has_no_findings() -> None:
    interaction = _interaction(
        request_headers={"content-type": ["application/json"]},
        request_body='{"model": "gpt-5", "messages": []}',
        response_body=b'{"id": "chatcmpl-1"}',
    )
    assert scan_interaction(1, interaction, RULES) == []


def test_findings_name_where_the_secret_is_without_showing_it() -> None:
    key = openai_key()
    interaction = _interaction(
        uri=f"https://api.example.com/v1/chat?k={key}",
        request_headers={"X-Custom": [f"Bearer {key}"]},
        request_body=f'{{"note": "{key}"}}',
        response_body=f"line one\nline two {key}".encode(),
    )
    findings = scan_interaction(3, interaction, RULES)
    assert [f.location for f in findings] == [
        "interaction 3, request URL",
        "interaction 3, request body",
        "interaction 3, request header X-Custom",
        "interaction 3, response body, line 2",
    ]
    for finding in findings:
        assert finding.rule_id == "openai-key"
        assert key not in str(finding)
        assert key not in repr(finding)
        assert finding.preview == f"sk-p... ({len(key)} chars)"


def test_status_message_and_unknown_keys_are_scanned() -> None:
    key = google_key()
    interaction = _interaction()
    interaction["response"]["status"]["message"] = f"bad key {key}"
    interaction["extra"] = {"note": key}
    locations = [f.location for f in scan_interaction(1, interaction, RULES)]
    assert locations == ["interaction 1, response status.message", "interaction 1, extra.note"]


def test_suspicious_header_values_are_flagged() -> None:
    interaction = _interaction(
        request_headers={"X-Portkey-Session-Token": [chars(32)], "x-request-id": [chars(32)]},
        response_headers={"anthropic-ratelimit-tokens-reset": ["2026-11-26T10:00:00Z"]},
    )
    findings = scan_interaction(1, interaction, RULES)
    assert [(f.rule_id, f.location) for f in findings] == [
        ("suspicious-header", "interaction 1, request header X-Portkey-Session-Token"),
    ]


def test_bytes_header_values_are_scanned() -> None:
    key = openai_key()
    interaction = _interaction(request_headers={"x-thing": key.encode()})
    assert [f.rule_id for f in scan_interaction(1, interaction, RULES)] == ["openai-key"]


@pytest.mark.parametrize(
    ("coding", "compress"),
    [
        ("gzip", gzip.compress),
        ("deflate", zlib.compress),
        ("deflate", lambda data: zlib.compress(data, wbits=-zlib.MAX_WBITS)),
    ],
)
def test_compressed_bodies_are_opened(coding: str, compress: Any) -> None:
    key = openai_key()
    interaction = _interaction(
        response_headers={"Content-Encoding": [coding]},
        response_body=compress(f'{{"key": "{key}"}}'.encode()),
    )
    assert [f.rule_id for f in scan_interaction(1, interaction, RULES)] == ["openai-key"]


def test_body_that_only_claims_to_be_compressed_is_scanned_as_is() -> None:
    key = openai_key()
    interaction = _interaction(
        response_headers={"content-encoding": ["gzip"]},
        response_body=key.encode(),
    )
    assert [f.rule_id for f in scan_interaction(1, interaction, RULES)] == ["openai-key"]


def test_unknown_compression_fails_closed() -> None:
    interaction = _interaction(
        response_headers={"content-encoding": ["x-made-up"]},
        response_body=b"\x00\x01\x02",
    )
    (finding,) = scan_interaction(1, interaction, RULES)
    assert finding.rule_id == "unscannable-body"
    assert "x-made-up" in finding.description


@pytest.mark.skipif(
    importlib.util.find_spec("brotli") is not None
    or importlib.util.find_spec("brotlicffi") is not None,
    reason="a brotli library is installed",
)
def test_brotli_without_a_library_fails_closed() -> None:
    interaction = _interaction(response_headers={"content-encoding": ["br"]}, response_body=b"\x8b")
    assert [f.rule_id for f in scan_interaction(1, interaction, RULES)] == ["unscannable-body"]


def test_decompression_has_a_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("safetape._bodies.MAX_DECOMPRESSED_BYTES", 1000)
    with pytest.raises(UnscannableBody, match="bigger than"):
        text_for_scan(gzip.compress(b"a" * 5000), {"content-encoding": "gzip"})
    assert MAX_DECOMPRESSED_BYTES > 1000


def test_body_shapes() -> None:
    assert text_for_scan(None, None) == ""
    assert text_for_scan("text", {"content-encoding": "gzip"}) == "text"
    assert text_for_scan(io.BytesIO(b"file"), None) == "file"
    assert text_for_scan([b"a", "b", b"c"], None) == "abc"
    assert text_for_scan(b"\xff ok", None) == "� ok"
    assert to_bytes(bytearray(b"x")) == b"x"
    assert to_bytes(iter([b"x", b"y"])) == b"xy"
    assert to_bytes([104, 105]) == b"hi"
    assert to_bytes(3.5) == b"3.5"


def test_scan_text_counts_lines() -> None:
    key = openai_key()
    (finding,) = scan_text(f"a\nb\nc {key}", RULES, "somewhere")
    assert finding.location == "somewhere, line 3"


def test_old_content_key_and_odd_shapes() -> None:
    key = openai_key()
    interaction: dict[str, Any] = {
        "request": "not a mapping",
        "response": {"headers": "odd", "body": {"content": key}, "items": [key]},
    }
    locations = [f.location for f in scan_interaction(1, interaction, RULES)]
    assert locations == ["interaction 1, response body content", "interaction 1, response items"]
