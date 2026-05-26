"""necromancer-patterns — shared credential/secret-detection patterns.

Single source of truth for the credential-detection regex rules used across the
necromancer suite. Re-exports the rule primitives and the high-level matching
API so consumers can ``from necromancer_patterns import match, get_rules, Rule``.
"""

from __future__ import annotations

from .matcher import Match, match, match_rule
from .patterns import (
    AWS_ACCESS_KEY,
    GENERIC_HIGH_ENTROPY,
    STRIPE_SECRET_KEY,
    Rule,
    available_pattern_sets,
    get_rules,
    shannon_entropy,
)

__version__ = "0.1.0"

__all__ = [
    "Match",
    "Rule",
    "AWS_ACCESS_KEY",
    "STRIPE_SECRET_KEY",
    "GENERIC_HIGH_ENTROPY",
    "available_pattern_sets",
    "get_rules",
    "match",
    "match_rule",
    "shannon_entropy",
    "__version__",
]
