"""necromancer-patterns — shared credential/secret-detection patterns.

Single source of truth for the credential-detection regex rules used across the
necromancer suite. Re-exports the rule primitives and the high-level matching
API so consumers can ``from necromancer_patterns import match, get_rules, Rule``.
"""

from __future__ import annotations

from .matcher import Match, match, match_rule
from .patterns import (
    ANTHROPIC_API_KEY,
    AWS_ACCESS_KEY,
    AZURE_DEVOPS_PAT,
    CLOUD_RULES,
    GCP_SERVICE_ACCOUNT_KEY,
    GENERIC_HIGH_ENTROPY,
    GITHUB_PAT,
    HUGGINGFACE_TOKEN,
    OPENAI_API_KEY,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    STRIPE_SECRET_KEY,
    Rule,
    available_pattern_sets,
    get_rules,
    shannon_entropy,
)

__version__ = "0.2.0"

__all__ = [
    "Match",
    "Rule",
    "SEVERITY_CRITICAL",
    "SEVERITY_HIGH",
    "AWS_ACCESS_KEY",
    "STRIPE_SECRET_KEY",
    "GENERIC_HIGH_ENTROPY",
    "GITHUB_PAT",
    "GCP_SERVICE_ACCOUNT_KEY",
    "AZURE_DEVOPS_PAT",
    "OPENAI_API_KEY",
    "HUGGINGFACE_TOKEN",
    "ANTHROPIC_API_KEY",
    "CLOUD_RULES",
    "available_pattern_sets",
    "get_rules",
    "match",
    "match_rule",
    "shannon_entropy",
    "__version__",
]
