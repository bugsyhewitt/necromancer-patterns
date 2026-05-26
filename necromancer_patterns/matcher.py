"""High-level matching API over the shared rule set.

``match(text)`` is the convenience entry point most consumers want: hand it a
string, get back a list of :class:`Match` objects describing each credential
the active rule set found, with validators already applied.

Lower-level consumers (e.g. tombstone's line-by-line git-history scanner) can
keep iterating ``get_rules(...)`` directly and applying ``rule.regex`` /
``rule.validator`` themselves; this module is built on exactly that primitive
so behaviour is identical.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from .patterns import Rule, get_rules


@dataclass(frozen=True)
class Match:
    """A single credential match within a piece of text."""

    rule_id: str
    description: str
    secret: str
    # Character offsets of the captured secret within the searched text.
    start: int
    end: int

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "secret": self.secret,
            "start": self.start,
            "end": self.end,
        }


def match_rule(rule: Rule, text: str) -> Iterator[Match]:
    """Yield every :class:`Match` produced by a single ``rule`` over ``text``."""
    for m in rule.regex.finditer(text):
        secret = m.group(rule.secret_group)
        if not secret:
            continue
        if rule.validator and not rule.validator(secret):
            continue
        yield Match(
            rule_id=rule.rule_id,
            description=rule.description,
            secret=secret,
            start=m.start(rule.secret_group),
            end=m.end(rule.secret_group),
        )


def match(text: str, pattern_set: str = "full") -> list[Match]:
    """Return all credential matches in ``text`` for the named ``pattern_set``.

    Matches are returned in (rule order, then in-text order). Validators are
    applied, so e.g. UUIDs and low-entropy strings are excluded from the
    generic high-entropy rule exactly as in tombstone's scanner.
    """
    rules = get_rules(pattern_set)
    results: list[Match] = []
    for rule in rules:
        results.extend(match_rule(rule, text))
    return results
