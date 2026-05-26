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
| `full` | AWS access key, Stripe secret key, generic high-entropy secret |

```python
from necromancer_patterns import available_pattern_sets
available_pattern_sets()  # ['minimal', 'aws', 'full']
```

## Rules

| `rule_id` | Detects |
|---|---|
| `aws-access-key-id` | AWS access keys (`AKIA`/`ASIA`/… + 16 base32 chars) |
| `stripe-secret-key` | Stripe secret keys (`sk_live_` / `sk_test_` + body) |
| `generic-high-entropy-secret` | High-entropy values assigned to credential-like keys, excluding UUIDs and git SHAs, above a Shannon-entropy floor |

Provider rules use strict prefixes/anchors so placeholder look-alikes do not
match. The generic rule only inspects tokens presented as secrets (assigned to a
`secret`/`token`/`api_key`/… key) and entropy-validates the value.

## Public API

```python
from necromancer_patterns import (
    match,                  # match(text, pattern_set="full") -> list[Match]
    match_rule,             # match_rule(rule, text) -> Iterator[Match]
    Match,                  # rule_id, description, secret, start, end + to_dict()
    Rule,                   # rule_id, description, regex, validator, secret_group
    get_rules,              # get_rules(pattern_set) -> list[Rule]
    available_pattern_sets, # -> list[str]
    shannon_entropy,        # shannon_entropy(value) -> float
    AWS_ACCESS_KEY, STRIPE_SECRET_KEY, GENERIC_HIGH_ENTROPY,
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
