"""Mask secrets in text that's about to be shown to someone."""

from __future__ import annotations

import functools
import re
from collections.abc import Collection

from ._presets import REDACTED
from ._rules import mask
from ._settings import Settings


def redact_text(text: str, settings: Settings, known: Collection[str] = ()) -> str:
    """``text`` with known credentials, credential query values and pattern matches masked."""
    for value in sorted(known, key=len, reverse=True):
        if value in text:
            text = text.replace(value, f"<known-secret: {mask(value)}>")
    text = _query_values(settings.query_params).sub(rf"\g<1>{REDACTED}", text)
    return settings.ruleset.redact(text)


@functools.lru_cache(maxsize=8)
def _query_values(names: frozenset[str]) -> re.Pattern[str]:
    alternatives = "|".join(re.escape(name) for name in sorted(names, key=len, reverse=True))
    # Braces are left out so source code like ?key={api_key} in a traceback stays readable.
    return re.compile(rf"([?&;](?:{alternatives})=)[^&#\s'\"<>(){{}}\[\]]+", re.IGNORECASE)
