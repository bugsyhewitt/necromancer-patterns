# necromancer-patterns

Shared credential and secret detection patterns for the [necromancer suite](https://github.com/bugsyhewitt).

This package is the **single source of truth** for the credential/secret-detection
regex rules used across necromancer tools. Tools that need to recognise leaked
AWS keys, Stripe keys, or generic high-entropy secrets depend on this library
instead of maintaining their own pattern lists.

The ruleset was originally developed inside [`tombstone`](https://github.com/bugsyhewitt/tombstone)
and extracted here so the whole suite can converge on one tested implementation.

## Install

```bash
pip install "necromancer-patterns @ git+https://github.com/bugsyhewitt/necromancer-patterns"
```

Or, for local suite development:

```bash
pip install -e /path/to/necromancer-patterns
```

## Usage

High-level: hand it text, get matches back.

```python
from necromancer_patterns import match

for m in match('export AWS_KEY=AKIAIOSFODNN7EXAMPLE'):
    print(m.rule_id, m.secret, m.start, m.end)
# aws-access-key-id AKIAIOSFODNN7EXAMPLE 15 35
```

`match(text, pattern_set="full")` returns a list of `Match` objects. Validators
(UUID / git-SHA exclusion, Shannon-entropy floor) are applied automatically, so
look-alikes and low-entropy strings are filtered out.

Low-level: iterate the rules yourself (this is what tombstone's line-by-line
git-history scanner does).

```python
from necromancer_patterns import get_rules

for rule in get_rules("full"):
    for hit in rule.regex.finditer(line):
        secret = hit.group(rule.secret_group)
        if rule.validator and not rule.validator(secret):
            continue
        ...  # report
```

## Pattern sets

| Set | Rules |
|---|---|
| `minimal` | AWS access key |
| `aws` | AWS access key |
| `cloud` | GitHub PAT, GCP service-account key, Azure DevOps PAT, OpenAI, Hugging Face, Anthropic |
| `full` | All of the above: AWS, Stripe, generic high-entropy, plus the six `cloud` rules |

```python
from necromancer_patterns import available_pattern_sets
available_pattern_sets()  # ['minimal', 'aws', 'cloud', 'full']
```

## Rules

Each rule carries a `severity` of `CRITICAL` (tokens granting broad account
access) or `HIGH` (scoped service/API tokens).

| `rule_id` | Severity | Detects |
|---|---|---|
| `aws-access-key-id` | CRITICAL | AWS access keys (`AKIA`/`ASIA`/… + 16 base32 chars) |
| `stripe-secret-key` | CRITICAL | Stripe secret keys (`sk_live_` / `sk_test_` + body) |
| `generic-high-entropy-secret` | HIGH | High-entropy values assigned to credential-like keys, excluding UUIDs and git SHAs, above a Shannon-entropy floor |
| `github-pat` | CRITICAL | GitHub PATs — classic (`ghp_` + 36) and fine-grained (`github_pat_` + 82) |
| `gcp-service-account-key` | CRITICAL | GCP service-account key JSON (`"type": "service_account"` co-located with `"private_key_id"`) |
| `azure-devops-pat` | CRITICAL | Azure DevOps PATs (84-char base64-like string with the `AZDO` marker at positions 76–79) |
| `openai-api-key` | HIGH | OpenAI keys — legacy (`sk-` + 48) and project-scoped (`sk-proj-` + 50+) |
| `huggingface-token` | HIGH | Hugging Face access tokens (`hf_` + 37) |
| `anthropic-api-key` | HIGH | Anthropic (Claude) API keys (`sk-ant-` + 93) |

Provider rules use strict prefixes/anchors and fixed lengths so placeholder
look-alikes do not match. The generic rule only inspects tokens presented as
secrets (assigned to a `secret`/`token`/`api_key`/… key) and entropy-validates
the value.

## Public API

```python
from necromancer_patterns import (
    match,                  # match(text, pattern_set="full") -> list[Match]
    match_rule,             # match_rule(rule, text) -> Iterator[Match]
    Match,                  # rule_id, description, secret, start, end + to_dict()
    Rule,                   # rule_id, description, regex, severity, validator, secret_group
    get_rules,              # get_rules(pattern_set) -> list[Rule]
    available_pattern_sets, # -> list[str]
    shannon_entropy,        # shannon_entropy(value) -> float
    SEVERITY_CRITICAL, SEVERITY_HIGH,
    AWS_ACCESS_KEY, STRIPE_SECRET_KEY, GENERIC_HIGH_ENTROPY,
    GITHUB_PAT, GCP_SERVICE_ACCOUNT_KEY, AZURE_DEVOPS_PAT,
    OPENAI_API_KEY, HUGGINGFACE_TOKEN, ANTHROPIC_API_KEY,
    CLOUD_RULES,            # ordered list of the six cloud/dev-platform rules
)
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Attribution

Patterns are adapted (not copied) from the gitleaks public ruleset (Apache-2.0).
See [`NOTICE`](./NOTICE) and [`vendor/gitleaks-LICENSE`](./vendor/gitleaks-LICENSE).

## License

MIT — see [`LICENSE`](./LICENSE).
