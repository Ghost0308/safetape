"""Look for secrets in a cassette's interactions."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from ._bodies import UnscannableBody, text_for_scan
from ._rules import Ruleset, mask


@dataclass(frozen=True)
class Finding:
    """Something that looks like a secret. It never holds the secret itself."""

    rule_id: str
    description: str
    location: str
    preview: str

    def __str__(self) -> str:
        return f"{self.location}: {self.description} [{self.rule_id}] {self.preview}"


def scan_text(text: str, ruleset: Ruleset, location: str) -> list[Finding]:
    """Findings for one piece of text. Multi-line text gets line numbers."""
    findings = []
    multiline = "\n" in text
    for hit in ruleset.find(text):
        where = location
        if multiline:
            where = f"{location}, line {text.count(chr(10), 0, hit.start) + 1}"
        findings.append(Finding(hit.rule.id, hit.rule.description, where, mask(hit.value)))
    return findings


def scan_interaction(
    number: int, interaction: Mapping[str, Any], ruleset: Ruleset
) -> list[Finding]:
    """Findings for one interaction in vcrpy's serialized shape.

    ``number`` counts from 1, so locations match what people see in the file.
    """
    findings: list[Finding] = []
    prefix = f"interaction {number}"
    for side in ("request", "response"):
        part = interaction.get(side)
        if not isinstance(part, Mapping):
            continue
        headers = part.get("headers") if isinstance(part.get("headers"), Mapping) else None
        for key, value in part.items():
            where = f"{prefix}, {side}"
            if key == "headers" and isinstance(value, Mapping):
                findings += _scan_headers(value, ruleset, where)
            elif key == "body":
                findings += _scan_body(value, headers, ruleset, f"{where} body")
            elif key == "uri":
                findings += scan_text(str(value), ruleset, f"{where} URL")
            else:
                for text, path in _strings(value, f"{where} {key}"):
                    findings += scan_text(text, ruleset, path)
    for key, value in interaction.items():
        if key not in ("request", "response"):
            for text, path in _strings(value, f"{prefix}, {key}"):
                findings += scan_text(text, ruleset, path)
    return findings


def _scan_headers(headers: Mapping[str, Any], ruleset: Ruleset, where: str) -> list[Finding]:
    findings: list[Finding] = []
    for name, values in headers.items():
        location = f"{where} header {name}"
        findings += scan_text(str(name), ruleset, location)
        items = values if isinstance(values, (list, tuple)) else [values]
        for item in items:
            text = item.decode("utf-8", "replace") if isinstance(item, bytes) else str(item)
            found = scan_text(text, ruleset, location)
            if not found and ruleset.header_check and ruleset.header_check.flags(str(name), text):
                found = [
                    Finding(
                        "suspicious-header",
                        "High-entropy value in a header whose name sounds secret",
                        location,
                        mask(text.strip()),
                    ),
                ]
            findings += found
    return findings


def _scan_body(
    body: Any,
    headers: Mapping[str, Any] | None,
    ruleset: Ruleset,
    where: str,
) -> list[Finding]:
    # Responses keep the body under "string" (or "content" in very old cassettes).
    if isinstance(body, Mapping):
        findings: list[Finding] = []
        for key, value in body.items():
            findings += _scan_body(
                value, headers, ruleset, where if key == "string" else f"{where} {key}"
            )
        return findings
    try:
        text = text_for_scan(body, headers)
    except UnscannableBody as problem:
        return [Finding("unscannable-body", str(problem), where, "")]
    return scan_text(text, ruleset, where)


def _strings(value: Any, path: str) -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield value, path
    elif isinstance(value, bytes):
        yield value.decode("utf-8", "replace"), path
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield str(key), path
            yield from _strings(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item, path)
