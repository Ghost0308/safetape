"""Load secret rules from JSON and find matches in text."""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

RULES_FORMAT_VERSION = 1

_RULE_KEYS = frozenset(
    {"id", "description", "regex", "keywords", "flags", "secret_group", "min_entropy"},
)
_REQUIRED_RULE_KEYS = frozenset({"id", "description", "regex", "keywords"})
_TOP_LEVEL_KEYS = frozenset({"version", "about", "allow", "suspicious_headers", "rules"})
_HEADER_KEYS = frozenset({"name_regex", "name_exclude_regex", "min_length", "min_entropy"})


class RulesError(ValueError):
    """A rules file is malformed."""


@dataclass(frozen=True)
class Rule:
    """One way of recognising a secret."""

    id: str
    description: str
    pattern: re.Pattern[str]
    keywords: tuple[str, ...]
    secret_group: int = 0
    min_entropy: float = 0.0


@dataclass(frozen=True)
class HeaderCheck:
    """Flags high-entropy values in headers whose names sound secret."""

    name_pattern: re.Pattern[str]
    exclude_pattern: re.Pattern[str] | None
    min_length: int
    min_entropy: float

    def flags(self, name: str, value: str) -> bool:
        lowered = name.lower()
        if not self.name_pattern.search(lowered):
            return False
        if self.exclude_pattern is not None and self.exclude_pattern.search(lowered):
            return False
        value = value.strip()
        return (
            len(value) >= self.min_length
            and any(c.isalpha() for c in value)
            and any(c.isdigit() for c in value)
            and shannon_entropy(value) >= self.min_entropy
        )


@dataclass(frozen=True)
class Hit:
    """Where a rule matched. ``value`` is the secret itself, so never print it."""

    rule: Rule
    start: int
    end: int
    value: str


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character."""
    if not value:
        return 0.0
    total = len(value)
    return -sum(n / total * math.log2(n / total) for n in Counter(value).values())


# Values this short are shown only as a length.
_SHORT_VALUE = 8


def mask(value: str) -> str:
    """A preview of a secret that is safe to show in an error message."""
    if len(value) <= _SHORT_VALUE:
        return f"[{len(value)} chars]"
    return f"{value[:4]}... ({len(value)} chars)"


class Ruleset:
    """An ordered list of rules plus the values that are always fine."""

    def __init__(
        self,
        rules: Sequence[Rule],
        *,
        allow_terms: Iterable[str] = (),
        allow_patterns: Iterable[re.Pattern[str]] = (),
        header_check: HeaderCheck | None = None,
    ) -> None:
        self.rules = tuple(rules)
        self.allow_terms = tuple(term.lower() for term in allow_terms)
        self.allow_patterns = tuple(allow_patterns)
        self.header_check = header_check

    def is_allowed(self, value: str) -> bool:
        lowered = value.lower()
        if any(term in lowered for term in self.allow_terms):
            return True
        return any(pattern.search(value) for pattern in self.allow_patterns)

    def find(self, text: str) -> list[Hit]:
        """Every secret in ``text``, in order. Overlapping matches count once."""
        lowered = text.lower()
        kept: list[Hit] = []
        for rule in self.rules:
            if rule.keywords and not any(keyword in lowered for keyword in rule.keywords):
                continue
            for match in rule.pattern.finditer(text):
                start, end = match.span(rule.secret_group)
                if start < 0:
                    continue
                value = text[start:end]
                if rule.min_entropy and shannon_entropy(value) < rule.min_entropy:
                    continue
                if self.is_allowed(value):
                    continue
                if any(start < hit.end and hit.start < end for hit in kept):
                    continue
                kept.append(Hit(rule, start, end, value))
        kept.sort(key=lambda hit: hit.start)
        return kept

    def redact(self, text: str) -> str:
        """``text`` with every secret swapped for its masked preview."""
        hits = self.find(text)
        if not hits:
            return text
        parts: list[str] = []
        position = 0
        for hit in hits:
            parts.append(text[position : hit.start])
            parts.append(f"<{hit.rule.id}: {mask(hit.value)}>")
            position = hit.end
        parts.append(text[position:])
        return "".join(parts)

    def extended(
        self,
        *,
        rules: Sequence[Rule] = (),
        allow_terms: Iterable[str] = (),
        allow_patterns: Iterable[re.Pattern[str]] = (),
    ) -> Ruleset:
        """A copy with more rules and allowed values added."""
        return Ruleset(
            self.rules + tuple(rules),
            allow_terms=self.allow_terms + tuple(allow_terms),
            allow_patterns=self.allow_patterns + tuple(allow_patterns),
            header_check=self.header_check,
        )


def default_rules() -> Ruleset:
    """The rules that ship with safetape."""
    text = resources.files("safetape").joinpath("rules.json").read_text(encoding="utf-8")
    return parse_rules(json.loads(text), origin="safetape/rules.json")


def load_rules(path: str | Path) -> Ruleset:
    """Rules from a JSON file in the same format as safetape's own."""
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RulesError(f"{path}: can't read rules file: {error}") from error
    return parse_rules(data, origin=str(path))


def parse_rules(data: Any, *, origin: str = "rules") -> Ruleset:
    if not isinstance(data, Mapping):
        raise RulesError(f"{origin}: expected a JSON object at the top level")
    unknown = set(data) - _TOP_LEVEL_KEYS
    if unknown:
        raise RulesError(f"{origin}: unknown keys {sorted(unknown)}")
    if data.get("version") != RULES_FORMAT_VERSION:
        raise RulesError(f"{origin}: unsupported version {data.get('version')!r}")

    allow = data.get("allow", [])
    if not isinstance(allow, list) or not all(isinstance(term, str) and term for term in allow):
        raise RulesError(f"{origin}: 'allow' must be a list of non-empty strings")

    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list):
        raise RulesError(f"{origin}: 'rules' must be a list")
    rules = [_parse_rule(raw, f"{origin} rule {number}") for number, raw in enumerate(raw_rules)]
    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            raise RulesError(f"{origin}: rule id {rule.id!r} is used twice")
        seen.add(rule.id)

    header_check = None
    if "suspicious_headers" in data:
        header_check = _parse_header_check(data["suspicious_headers"], origin)
    return Ruleset(rules, allow_terms=allow, header_check=header_check)


def _parse_rule(raw: Any, where: str) -> Rule:
    if not isinstance(raw, Mapping):
        raise RulesError(f"{where}: expected an object")
    unknown = set(raw) - _RULE_KEYS
    if unknown:
        raise RulesError(f"{where}: unknown keys {sorted(unknown)}")
    missing = _REQUIRED_RULE_KEYS - set(raw)
    if missing:
        raise RulesError(f"{where}: missing keys {sorted(missing)}")

    rule_id, description, regex = raw["id"], raw["description"], raw["regex"]
    if not all(isinstance(v, str) and v for v in (rule_id, description, regex)):
        raise RulesError(f"{where}: 'id', 'description' and 'regex' must be non-empty strings")

    keywords = raw["keywords"]
    if not isinstance(keywords, list) or not all(isinstance(k, str) and k for k in keywords):
        raise RulesError(f"{where}: 'keywords' must be a list of non-empty strings")

    flags = raw.get("flags", "")
    if flags not in ("", "i"):
        raise RulesError(f'{where}: \'flags\' can only be "" or "i"')
    # ASCII mode keeps \b, \d, \w and \s the same as in JavaScript.
    re_flags = re.ASCII | (re.IGNORECASE if flags == "i" else 0)
    try:
        pattern = re.compile(regex, re_flags)
    except re.error as error:
        raise RulesError(f"{where}: bad regex: {error}") from error

    secret_group = raw.get("secret_group", 0)
    if type(secret_group) is not int or not 0 <= secret_group <= pattern.groups:
        raise RulesError(f"{where}: 'secret_group' must name a group in the regex")

    min_entropy = raw.get("min_entropy", 0.0)
    if type(min_entropy) not in (int, float) or min_entropy < 0:
        raise RulesError(f"{where}: 'min_entropy' must be a number of at least 0")

    return Rule(
        id=rule_id,
        description=description,
        pattern=pattern,
        keywords=tuple(k.lower() for k in keywords),
        secret_group=secret_group,
        min_entropy=float(min_entropy),
    )


def _parse_header_check(raw: Any, origin: str) -> HeaderCheck:
    where = f"{origin} suspicious_headers"
    if not isinstance(raw, Mapping):
        raise RulesError(f"{where}: expected an object")
    unknown = set(raw) - _HEADER_KEYS
    if unknown:
        raise RulesError(f"{where}: unknown keys {sorted(unknown)}")
    try:
        name_pattern = re.compile(raw["name_regex"], re.ASCII)
        exclude = raw.get("name_exclude_regex")
        exclude_pattern = re.compile(exclude, re.ASCII) if exclude else None
        min_length = int(raw.get("min_length", 16))
        min_entropy = float(raw.get("min_entropy", 3.5))
    except (KeyError, TypeError, ValueError, re.error) as error:
        raise RulesError(f"{where}: {error}") from error
    return HeaderCheck(name_pattern, exclude_pattern, min_length, min_entropy)
