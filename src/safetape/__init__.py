"""Keep API keys out of recorded LLM test cassettes."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

__version__ = "0.1.1"

# Names are imported the first time they're used. Importing vcrpy as soon as
# pytest loads safetape's plugin would stop pytest-recording from having
# vcr.matchers' asserts rewritten, which pytest reports as a warning.
_EXPORTS = {
    "REDACTED": "._presets",
    "Finding": "._scan",
    "LockdownError": "._errors",
    "RulesError": "._rules",
    "Ruleset": "._rules",
    "SafePersister": "._persister",
    "SafetapeError": "._errors",
    "SecretFoundError": "._errors",
    "Settings": "._settings",
    "StaleCassette": "._persister",
    "StaleCassetteWarning": "._persister",
    "default_rules": "._rules",
    "install": "._install",
    "load_rules": "._rules",
    "serializer": ".serializer",
}

__all__ = [
    "REDACTED",
    "Finding",
    "LockdownError",
    "RulesError",
    "Ruleset",
    "SafePersister",
    "SafetapeError",
    "SecretFoundError",
    "Settings",
    "StaleCassette",
    "StaleCassetteWarning",
    "__version__",
    "default_rules",
    "install",
    "load_rules",
    "serializer",
]


def __getattr__(name: str) -> Any:
    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module 'safetape' has no attribute {name!r}")
    module = importlib.import_module(module_name, __name__)
    value = module if name == "serializer" else getattr(module, name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *_EXPORTS})


if TYPE_CHECKING:
    from . import serializer
    from ._errors import LockdownError, SafetapeError, SecretFoundError
    from ._install import install
    from ._persister import SafePersister, StaleCassette, StaleCassetteWarning
    from ._presets import REDACTED
    from ._rules import RulesError, Ruleset, default_rules, load_rules
    from ._scan import Finding
    from ._settings import Settings
