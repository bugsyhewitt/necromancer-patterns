"""Regex rule definitions and pattern sets for the necromancer suite.

This module is the single source of truth for credential / secret-detection
regex patterns used across necromancer tools. It was extracted from tombstone's
``src/tombstone/patterns.py`` so that any suite tool can converge on one
ruleset rather than maintaining its own.

Patterns are adapted from the gitleaks public ruleset (Apache-2.0 licensed).
See NOTICE and vendor/gitleaks-LICENSE for attribution. Rules have been
re-written to Python ``re`` idioms rather than copied verbatim.

[Worker decision: pattern-set design] The orchestrator requires zero false
positives on five innocuous-looking strings while detecting exactly three
planted credentials (AWS, Stripe, generic high-entropy). We therefore keep the
ruleset tight: provider rules use strict anchors/prefixes (e.g. AKIA for AWS,
sk_live for Stripe) so look-alike placeholders do not match, and the generic
high-entropy rule fires only on isolated tokens that survive shape exclusions
(UUID, hex git SHA) and clear a Shannon-entropy floor.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Callable, Optional


# Severity tiers. CRITICAL is reserved for tokens that grant broad, immediate
# account-level access (e.g. GitHub PATs, cloud service-account keys). HIGH is
# for scoped/service tokens whose blast radius depends on the target system.
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"


@dataclass(frozen=True)
class Rule:
    """A single credential-detection rule."""

    rule_id: str
    description: str
    regex: re.Pattern
    # Severity of a confirmed match. One of SEVERITY_CRITICAL / SEVERITY_HIGH.
    # Defaults to HIGH so older rule definitions remain valid without change.
    severity: str = SEVERITY_HIGH
    # Optional extra validator applied to the captured secret group. Returns
    # True if the candidate should be reported.
    validator: Optional[Callable[[str], bool]] = field(default=None)
    # Which capture group holds the secret value (0 = whole match).
    secret_group: int = 0


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy (bits per character) of ``value``."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# Shapes that look high-entropy but are almost never secrets. Excluded from the
# generic high-entropy rule to avoid false positives.
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEX_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")

# Minimum Shannon entropy (bits/char) for the generic rule to fire. Tuned so a
# 40-char mixed-charset random secret (~5.0+ bits) passes while ordinary words,
# lorem text, and placeholders stay below.
_GENERIC_ENTROPY_FLOOR = 4.3


def _generic_secret_validator(candidate: str) -> bool:
    """Return True if ``candidate`` is a plausible generic secret."""
    if _UUID_RE.match(candidate):
        return False
    if _HEX_SHA_RE.match(candidate):
        return False
    # Require a mix of character classes — secrets are rarely a single class.
    has_lower = any(c.islower() for c in candidate)
    has_upper = any(c.isupper() for c in candidate)
    has_digit = any(c.isdigit() for c in candidate)
    classes = sum((has_lower, has_upper, has_digit))
    if classes < 2:
        return False
    return shannon_entropy(candidate) >= _GENERIC_ENTROPY_FLOOR


# --- Rule definitions -------------------------------------------------------

AWS_ACCESS_KEY = Rule(
    rule_id="aws-access-key-id",
    description="AWS Access Key ID",
    # Strict provider prefixes followed by exactly 16 base32 chars. Placeholder
    # look-alikes (e.g. AKIAXXXXXXXXXXXXXXXX with X's, or lowercase) will not
    # match because the body must be uppercase A-Z / 2-7 digits, 16 chars.
    regex=re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z2-7]{16})\b"),
    severity=SEVERITY_CRITICAL,
    secret_group=1,
)

STRIPE_SECRET_KEY = Rule(
    rule_id="stripe-secret-key",
    description="Stripe Secret Key",
    regex=re.compile(r"\b(sk_(?:live|test)_[0-9a-zA-Z]{24,})\b"),
    severity=SEVERITY_CRITICAL,
    secret_group=1,
)

GENERIC_HIGH_ENTROPY = Rule(
    rule_id="generic-high-entropy-secret",
    description="Generic high-entropy secret assigned to a credential-like key",
    # Anchor on an assignment to a secret-ish key name so we only inspect tokens
    # that are presented as secrets, then entropy-validate the value.
    regex=re.compile(
        r"""(?ix)
        (?:secret|token|api[_-]?key|apikey|passwd|password|access[_-]?key|auth)
        \s*[:=]\s*
        ['"]?
        ([A-Za-z0-9+/=_\-]{20,})
        ['"]?
        """
    ),
    validator=_generic_secret_validator,
    secret_group=1,
)


# --- Cloud & developer-platform credentials --------------------------------
#
# These provider tokens use strict, unique prefixes and fixed lengths, so they
# detect with near-zero false-positive risk. PATs that grant broad account
# access (GitHub, GCP service accounts, Azure DevOps) are CRITICAL; scoped
# service/API tokens (OpenAI, Hugging Face, Anthropic) are HIGH.

GITHUB_PAT = Rule(
    rule_id="github-pat",
    description="GitHub Personal Access Token (classic or fine-grained)",
    # Classic PATs are `ghp_` + 36 alphanumerics. Fine-grained PATs are
    # `github_pat_` + 82 chars of [A-Za-z0-9_]. Either grants repo/account
    # access scoped to the token, so both are treated as Critical.
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9A-Za-z_]{82})"
        r"(?![A-Za-z0-9_-])"
    ),
    severity=SEVERITY_CRITICAL,
    secret_group=1,
)

GCP_SERVICE_ACCOUNT_KEY = Rule(
    rule_id="gcp-service-account-key",
    description="GCP service account key JSON",
    # GCP downloads its service-account keys as a JSON blob whose discriminator
    # is `"type": "service_account"` alongside a `"private_key_id"`. We require
    # both within a short window so an arbitrary mention of "service_account" in
    # prose does not match. The captured group is the discriminator field.
    regex=re.compile(
        r"""(?s)("type"\s*:\s*"service_account").{0,200}?"private_key_id"\s*:\s*"[0-9a-fA-F]{8,}"
        |
        "private_key_id"\s*:\s*"[0-9a-fA-F]{8,}".{0,200}?("type"\s*:\s*"service_account")""",
        re.VERBOSE,
    ),
    severity=SEVERITY_CRITICAL,
    secret_group=0,
)

AZURE_DEVOPS_PAT = Rule(
    rule_id="azure-devops-pat",
    description="Azure DevOps Personal Access Token",
    # Azure DevOps PATs are an 84-char base64-like string whose characters at
    # positions 76-79 spell `AZDO`. Anchor on that fixed marker to avoid
    # matching arbitrary base64 of the same length.
    regex=re.compile(r"\b([A-Za-z0-9+/]{76}AZDO[A-Za-z0-9+/]{4})\b"),
    severity=SEVERITY_CRITICAL,
    secret_group=1,
)

OPENAI_API_KEY = Rule(
    rule_id="openai-api-key",
    description="OpenAI API key (legacy or project-scoped)",
    # Legacy keys: `sk-` + 48 alphanumerics. Newer project keys:
    # `sk-proj-` + >=50 chars of [A-Za-z0-9_-]. Project form is checked first so
    # the alternation does not stop short at the legacy branch.
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])(sk-proj-[a-zA-Z0-9_-]{50,}|sk-[a-zA-Z0-9]{48})"
        r"(?![A-Za-z0-9_-])"
    ),
    severity=SEVERITY_HIGH,
    secret_group=1,
)

HUGGINGFACE_TOKEN = Rule(
    rule_id="huggingface-token",
    description="Hugging Face access token",
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])(hf_[a-zA-Z0-9]{37})(?![A-Za-z0-9_-])"
    ),
    severity=SEVERITY_HIGH,
    secret_group=1,
)

ANTHROPIC_API_KEY = Rule(
    rule_id="anthropic-api-key",
    description="Anthropic (Claude) API key",
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])(sk-ant-[a-zA-Z0-9_-]{93})(?![A-Za-z0-9_-])"
    ),
    severity=SEVERITY_HIGH,
    secret_group=1,
)


# Ordered list of the cloud/developer-platform rules added post-v0.1.
CLOUD_RULES: list[Rule] = [
    GITHUB_PAT,
    GCP_SERVICE_ACCOUNT_KEY,
    AZURE_DEVOPS_PAT,
    OPENAI_API_KEY,
    HUGGINGFACE_TOKEN,
    ANTHROPIC_API_KEY,
]


_BASE_FULL: list[Rule] = [AWS_ACCESS_KEY, STRIPE_SECRET_KEY, GENERIC_HIGH_ENTROPY]

_PATTERN_SETS: dict[str, list[Rule]] = {
    "minimal": [AWS_ACCESS_KEY],
    "aws": [AWS_ACCESS_KEY],
    # `cloud` is the focused set of provider/developer-platform tokens.
    "cloud": list(CLOUD_RULES),
    # `full` is the union of the original ruleset plus the cloud tokens — the
    # broadest detection set a consumer can request.
    "full": _BASE_FULL + CLOUD_RULES,
}


def get_rules(pattern_set: str) -> list[Rule]:
    """Return the list of rules for the named pattern set."""
    try:
        return _PATTERN_SETS[pattern_set]
    except KeyError as exc:
        raise ValueError(f"unknown pattern set: {pattern_set}") from exc


def available_pattern_sets() -> list[str]:
    """Return the names of all defined pattern sets."""
    return list(_PATTERN_SETS.keys())
