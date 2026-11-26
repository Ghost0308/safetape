"""Fake secrets, built at runtime.

No file in this repo spells out a whole key in a real format, so gitleaks and
GitHub push protection never see one. Prefixes are split up for the same reason.
"""

from __future__ import annotations

import random
import string
from collections.abc import Callable
from dataclasses import dataclass

_rng = random.Random(20261126)

LETTERS = string.ascii_letters
UPPER = string.ascii_uppercase
DIGITS = string.digits
ALNUM = LETTERS + DIGITS
URLSAFE = ALNUM + "_-"
HEX = DIGITS + "abcdef"


def chars(n: int, alphabet: str = ALNUM) -> str:
    """Random characters that always mix letters and digits."""
    while True:
        value = "".join(_rng.choice(alphabet) for _ in range(n))
        has_letter = any(c.isalpha() for c in value) or not any(c.isalpha() for c in alphabet)
        has_digit = any(c.isdigit() for c in value) or not any(c.isdigit() for c in alphabet)
        if has_letter and has_digit:
            return value


@dataclass(frozen=True)
class Sample:
    text: str
    secret: str


def _plain(make: Callable[[], str]) -> Callable[[], Sample]:
    def build() -> Sample:
        value = make()
        return Sample(value, value)

    return build


def _in_context(before: str, make: Callable[[], str], after: str = "") -> Callable[[], Sample]:
    def build() -> Sample:
        value = make()
        return Sample(before + value + after, value)

    return build


# One generator per rule in rules.json, keyed by rule id.
SAMPLES: dict[str, Callable[[], Sample]] = {
    "openai-key": _plain(lambda: "sk-" + "proj-" + chars(64, URLSAFE)),
    "openai-legacy-key": _plain(lambda: "sk-" + chars(20) + "T3Blbk" + "FJ" + chars(20)),
    "anthropic-key": _plain(lambda: "sk-" + "ant-" + "api03-" + chars(93, URLSAFE) + "AA"),
    "openrouter-key": _plain(lambda: "sk-" + "or-v1-" + chars(64, HEX)),
    "sk-style-key": _plain(lambda: "sk-" + chars(48)),
    "google-api-key": _plain(lambda: "AI" + "za" + chars(35, URLSAFE)),
    "google-oauth-token": _plain(lambda: "ya29" + "." + chars(120, URLSAFE)),
    "groq-key": _plain(lambda: "gsk" + "_" + chars(52)),
    "xai-key": _plain(lambda: "xai" + "-" + chars(80)),
    "huggingface-token": _plain(lambda: "hf" + "_" + chars(34)),
    "perplexity-key": _plain(lambda: "pplx" + "-" + chars(48)),
    "replicate-token": _plain(lambda: "r8" + "_" + chars(37)),
    "fireworks-key": _plain(lambda: "fw" + "_" + chars(24)),
    "nvidia-key": _plain(lambda: "nvapi" + "-" + chars(64, URLSAFE)),
    "langsmith-key": _plain(lambda: "lsv2" + "_pt_" + chars(32, HEX) + "_" + chars(10, HEX)),
    "aws-access-key-id": _plain(lambda: "AK" + "IA" + chars(16, UPPER + DIGITS)),
    "aws-bedrock-api-key": _plain(lambda: "AB" + "SK" + chars(100, ALNUM + "+/")),
    "github-token": _plain(lambda: "gh" + "p_" + chars(36)),
    "github-fine-grained-token": _plain(
        lambda: "github" + "_pat_" + chars(22) + "_" + chars(59),
    ),
    "slack-token": _plain(
        lambda: "xo" + "xb-" + chars(12, DIGITS) + "-" + chars(12, DIGITS) + "-" + chars(24),
    ),
    "stripe-live-key": _plain(lambda: "sk" + "_live_" + chars(24)),
    "private-key": _plain(lambda: "-----BEGIN " + "RSA PRIVATE" + " KEY-----"),
    "jwt": _plain(
        lambda: (
            "ey" + "J" + chars(30, URLSAFE) + ".ey" + "J" + chars(40, URLSAFE) + "." + chars(43)
        ),
    ),
    "url-credentials": _in_context("postgres://app:", lambda: chars(20), "@db.internal:5432/main"),
    "bearer-token": _in_context("Authorization: Bearer ", lambda: chars(40)),
    "secret-assignment": _in_context('{"api_key": "', lambda: chars(32), '"}'),
}


def openai_key() -> str:
    return SAMPLES["openai-key"]().secret


def anthropic_key() -> str:
    return SAMPLES["anthropic-key"]().secret


def google_key() -> str:
    return SAMPLES["google-api-key"]().secret


def refresh_token() -> str:
    return "1//" + chars(60, URLSAFE)
