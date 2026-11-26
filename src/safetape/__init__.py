"""Keep API keys out of recorded LLM test cassettes."""

from ._rules import RulesError, Ruleset, default_rules, load_rules
from ._scan import Finding
from ._scrub import REDACTED
from ._settings import Settings

__version__ = "0.0.1"

__all__ = [
    "REDACTED",
    "Finding",
    "RulesError",
    "Ruleset",
    "Settings",
    "__version__",
    "default_rules",
    "load_rules",
]
