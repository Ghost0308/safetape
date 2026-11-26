"""Look for secrets in a cassette's interactions."""

from __future__ import annotations

from collections.abc import Collection, Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from ._bodies import UnscannableBody, text_for_scan
from ._rules import Ruleset, mask

KNOWN_RULE_ID = "known-secret"
KNOWN_DESCRIPTION = (
    "A credential this test run uses (sent in a stripped header, parameter or body field, "
    "or set in an environment variable)"
)


@dataclass(frozen=True)
class Finding:
    """Something that looks like a secret. It never holds the secret itself."""

    rule_id: str
    description: str
    location: str
    preview: str

    def __str__(self) -> str:
        return f"{self.location}: {self.description} [{self.rule_id}] {self.preview}"


def scan_text(
    text: str,
    ruleset: Ruleset,
    location: str,
    known: Collection[str] = (),
) -> list[Finding]:
    """Findings for one piece of text. Multi-line text gets line numbers.

    ``known`` holds exact credential values to look for, whatever they look like.
    """
    found: list[tuple[int, str, str, str]] = []
    spans: list[tuple[int, int]] = []
    for hit in ruleset.find(text):
        found.append((hit.start, hit.rule.id, hit.rule.description, mask(hit.value)))
        spans.append((hit.start, hit.end))
    for value in sorted(known, key=len, reverse=True):
        start = text.find(value)
        while start != -1:
            end = start + len(value)
            if not any(s < end and start < e for s, e in spans):
                found.append((start, KNOWN_RULE_ID, KNOWN_DESCRIPTION, mask(value)))
                spans.append((start, end))
            start = text.find(value, end)

    findings = []
    multiline = "\n" in text
    for start, rule_id, description, preview in sorted(found):
        where = location
        if multiline:
            where = f"{location}, line {text.count(chr(10), 0, start) + 1}"
        findings.append(Finding(rule_id, description, where, preview))
    return findings


def scan_interaction(
    number: int,
    interaction: Mapping[str, Any],
    ruleset: Ruleset,
    known: Collection[str] = (),
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
                findings += _scan_headers(value, ruleset, where, known)
            elif key == "body":
                findings += _scan_body(value, headers, ruleset, f"{where} body", known)
            elif key == "uri":
                findings += scan_text(str(value), ruleset, f"{where} URL", known)
            else:
                for text, path in _strings(value, f"{where} {key}"):
                    findings += scan_text(text, ruleset, path, known)
    for key, value in interaction.items():
        if key not in ("request", "response"):
            for text, path in _strings(value, f"{prefix}, {key}"):
                findings += scan_text(text, ruleset, path, known)
    return findings


def _scan_headers(
    headers: Mapping[str, Any],
    ruleset: Ruleset,
    where: str,
    known: Collection[str],
) -> list[Finding]:
    findings: list[Finding] = []
    for name, values in headers.items():
        location = f"{where} header {name}"
        findings += scan_text(str(name), ruleset, location, known)
        items = values if isinstance(values, (list, tuple)) else [values]
        for item in items:
            text = item.decode("utf-8", "replace") if isinstance(item, bytes) else str(item)
            found = scan_text(text, ruleset, location, known)
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
    known: Collection[str],
) -> list[Finding]:
    # Responses keep the body under "string" (or "content" in very old cassettes).
    if isinstance(body, Mapping):
        findings: list[Finding] = []
        for key, value in body.items():
            location = where if key == "string" else f"{where} {key}"
            findings += _scan_body(value, headers, ruleset, location, known)
        return findings
    try:
        text = text_for_scan(body, headers)
    except UnscannableBody as problem:
        return [Finding("unscannable-body", str(problem), where, "")]
    return scan_text(text, ruleset, where, known)


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
