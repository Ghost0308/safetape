"""Keep API keys out of recorded LLM test cassettes."""

from . import serializer
from ._errors import LockdownError, SafetapeError, SecretFoundError
from ._install import install
from ._persister import SafePersister, StaleCassette, StaleCassetteWarning
from ._rules import RulesError, Ruleset, default_rules, load_rules
from ._scan import Finding
from ._scrub import REDACTED
from ._settings import Settings

__version__ = "0.0.1"

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
