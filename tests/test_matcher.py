"""Unit tests for the high-level match() API."""

from necromancer_patterns import Match, match


def test_match_returns_match_objects():
    results = match("key=AKIAIOSFODNN7EXAMPLE")
    assert len(results) == 1
    assert isinstance(results[0], Match)
    assert results[0].rule_id == "aws-access-key-id"
    assert results[0].secret == "AKIAIOSFODNN7EXAMPLE"


def test_match_reports_offsets():
    text = "key=AKIAIOSFODNN7EXAMPLE"
    m = match(text)[0]
    assert text[m.start : m.end] == m.secret


def test_match_finds_multiple_rules_in_one_text():
    key = "sk" + "_" + "live" + "_" + "9Hq2WkPmZ7tRb4Ld8Xn3Vc6q"
    text = f'aws=AKIAIOSFODNN7EXAMPLE stripe="{key}"'
    rule_ids = {m.rule_id for m in match(text)}
    assert rule_ids == {"aws-access-key-id", "stripe-secret-key"}


def test_match_applies_validators():
    # UUID assigned to a secret-like key must NOT be reported.
    assert match('secret = "550e8400-e29b-41d4-a716-446655440000"') == []


def test_match_clean_text_returns_empty():
    assert match("the quick brown fox jumps over the lazy dog") == []


def test_match_respects_pattern_set():
    # The 'aws' set has only the AWS rule, so a stripe key is not reported.
    key = "sk" + "_" + "live" + "_" + "9Hq2WkPmZ7tRb4Ld8Xn3Vc6q"
    assert match(f'k="{key}"', pattern_set="aws") == []


def test_match_to_dict_shape():
    m = match("key=AKIAIOSFODNN7EXAMPLE")[0]
    d = m.to_dict()
    assert set(d) == {"rule_id", "description", "secret", "start", "end"}
