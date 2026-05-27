"""Unit tests for the regex rule engine and entropy heuristics.

These mirror tombstone's original test_patterns.py to guarantee the extracted
library is behaviourally identical — the whole point of the refactor is zero
regression.
"""

from necromancer_patterns.patterns import (
    ANTHROPIC_API_KEY,
    AWS_ACCESS_KEY,
    AZURE_DEVOPS_PAT,
    GCP_SERVICE_ACCOUNT_KEY,
    GENERIC_HIGH_ENTROPY,
    GITHUB_PAT,
    HUGGINGFACE_TOKEN,
    OPENAI_API_KEY,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    STRIPE_SECRET_KEY,
    available_pattern_sets,
    get_rules,
    shannon_entropy,
)


def _matches(rule, text):
    for m in rule.regex.finditer(text):
        secret = m.group(rule.secret_group)
        if rule.validator and not rule.validator(secret):
            continue
        return secret
    return None


def test_aws_rule_matches_real_key():
    assert _matches(AWS_ACCESS_KEY, "key=AKIAIOSFODNN7EXAMPLE") == "AKIAIOSFODNN7EXAMPLE"


def test_aws_rule_ignores_lowercase_lookalike():
    assert _matches(AWS_ACCESS_KEY, 'k = "akiaiosfodnn7example"') is None


def test_stripe_rule_matches_real_key():
    # Assemble the key from fragments so no `sk_live_<body>` literal lives in
    # committed source (avoids GitHub push protection).
    key = "sk" + "_" + "live" + "_" + "9Hq2WkPmZ7tRb4Ld8Xn3Vc6q"
    secret = _matches(STRIPE_SECRET_KEY, f'K = "{key}"')
    assert secret == key


def test_generic_matches_high_entropy_secret():
    secret = _matches(GENERIC_HIGH_ENTROPY, 'api_key = "Zx9Kq2Lm8Pv4Rt6Wy1Bn3Cf5Hj7Dg0Es"')
    assert secret == "Zx9Kq2Lm8Pv4Rt6Wy1Bn3Cf5Hj7Dg0Es"


def test_generic_ignores_uuid():
    assert _matches(GENERIC_HIGH_ENTROPY, 'secret = "550e8400-e29b-41d4-a716-446655440000"') is None


def test_generic_ignores_git_sha():
    assert _matches(GENERIC_HIGH_ENTROPY, 'token = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"') is None


def test_generic_ignores_low_entropy_repetition():
    assert _matches(GENERIC_HIGH_ENTROPY, 'password = "passwordpasswordpassword"') is None
    assert _matches(GENERIC_HIGH_ENTROPY, 'token = "aaaabbbbccccddddeeeeffff"') is None


def test_entropy_increases_with_randomness():
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("Zx9Kq2Lm")


def test_pattern_sets_exist():
    assert set(available_pattern_sets()) >= {"minimal", "aws", "cloud", "full"}


def test_full_set_contains_base_and_cloud_rules():
    # `full` is the original three rules plus the six cloud/dev-platform rules.
    rule_ids = {r.rule_id for r in get_rules("full")}
    assert {
        "aws-access-key-id",
        "stripe-secret-key",
        "generic-high-entropy-secret",
    } <= rule_ids
    assert {
        "github-pat",
        "gcp-service-account-key",
        "azure-devops-pat",
        "openai-api-key",
        "huggingface-token",
        "anthropic-api-key",
    } <= rule_ids
    assert len(get_rules("full")) == 9


def test_cloud_set_has_six_rules():
    assert len(get_rules("cloud")) == 6


def test_unknown_pattern_set_raises():
    import pytest

    with pytest.raises(ValueError):
        get_rules("does-not-exist")


# --- Cloud / developer-platform credential rules ---------------------------
#
# Test secrets are assembled from fragments so no literal provider token lives
# in committed source (avoids GitHub/provider push-protection false flags).


def test_github_classic_pat_matches():
    # ghp_ + 36 alphanumerics.
    tok = "ghp_" + "0123456789abcdefABCDEF0123456789wxyz"
    assert len(tok) == 40
    assert _matches(GITHUB_PAT, f'token = "{tok}"') == tok


def test_github_finegrained_pat_matches():
    # github_pat_ + 82 chars of [A-Za-z0-9_].
    body = ("A" * 22) + "_" + ("b" * 30) + ("9" * 29)
    tok = "github_pat_" + body
    assert len(body) == 82
    assert _matches(GITHUB_PAT, f"export GH={tok}") == tok


def test_github_pat_ignores_short_lookalike():
    assert _matches(GITHUB_PAT, 'token = "ghp_tooshort"') is None
    assert _matches(GITHUB_PAT, "github_pat_short") is None


def test_github_pat_is_critical():
    assert GITHUB_PAT.severity == SEVERITY_CRITICAL


def test_gcp_service_account_key_matches():
    blob = (
        '{\n'
        '  "type": "service_account",\n'
        '  "project_id": "demo-proj",\n'
        '  "private_key_id": "0a1b2c3d4e5f6071",\n'
        '  "private_key": "-----BEGIN PRIVATE KEY-----..."\n'
        '}'
    )
    assert _matches(GCP_SERVICE_ACCOUNT_KEY, blob) is not None


def test_gcp_service_account_key_matches_reordered():
    # Discriminator order swapped — rule must still fire.
    blob = (
        '{ "private_key_id": "deadbeef1234", "type": "service_account" }'
    )
    assert _matches(GCP_SERVICE_ACCOUNT_KEY, blob) is not None


def test_gcp_service_account_key_ignores_prose():
    # "service_account" mentioned in text without the key_id discriminator.
    assert _matches(
        GCP_SERVICE_ACCOUNT_KEY,
        'We provisioned a new service_account for the deploy bot.',
    ) is None


def test_gcp_service_account_key_is_critical():
    assert GCP_SERVICE_ACCOUNT_KEY.severity == SEVERITY_CRITICAL


def test_azure_devops_pat_matches():
    # 76 base64-ish chars, then AZDO marker, then 4 more.
    tok = ("a" * 40) + ("B" * 36) + "AZDO" + "1234"
    assert len(tok) == 84
    assert _matches(AZURE_DEVOPS_PAT, f'pat={tok}') == tok


def test_azure_devops_pat_ignores_marker_absent():
    # Same length but no AZDO marker at the fixed offset.
    tok = "x" * 84
    assert _matches(AZURE_DEVOPS_PAT, f'pat={tok}') is None


def test_azure_devops_pat_is_critical():
    assert AZURE_DEVOPS_PAT.severity == SEVERITY_CRITICAL


def test_openai_legacy_key_matches():
    # sk- + 48 alphanumerics.
    tok = "sk-" + ("A1b2C3d4" * 6)
    assert len(tok) == 51
    assert _matches(OPENAI_API_KEY, f'OPENAI_API_KEY={tok}') == tok


def test_openai_project_key_matches():
    # sk-proj- + 50+ chars of [A-Za-z0-9_-].
    body = ("Zz9" * 17) + "a-_"
    tok = "sk-proj-" + body
    assert len(body) >= 50
    assert _matches(OPENAI_API_KEY, f'key = "{tok}"') == tok


def test_openai_key_ignores_short_lookalike():
    assert _matches(OPENAI_API_KEY, 'key = "sk-abc123"') is None


def test_openai_key_is_high():
    assert OPENAI_API_KEY.severity == SEVERITY_HIGH


def test_huggingface_token_matches():
    # hf_ + 37 alphanumerics.
    tok = "hf_" + ("aB3" * 12) + "x"
    assert len(tok) == 40
    assert _matches(HUGGINGFACE_TOKEN, f'HF_TOKEN={tok}') == tok


def test_huggingface_token_ignores_short_lookalike():
    assert _matches(HUGGINGFACE_TOKEN, 'token = "hf_short"') is None


def test_huggingface_token_is_high():
    assert HUGGINGFACE_TOKEN.severity == SEVERITY_HIGH


def test_anthropic_api_key_matches():
    # sk-ant- + 93 chars of [A-Za-z0-9_-].
    body = ("Aa1" * 30) + "z_-"
    tok = "sk-ant-" + body
    assert len(body) == 93
    assert _matches(ANTHROPIC_API_KEY, f'ANTHROPIC_API_KEY={tok}') == tok


def test_anthropic_api_key_ignores_short_lookalike():
    assert _matches(ANTHROPIC_API_KEY, 'key = "sk-ant-tooshort"') is None


def test_anthropic_api_key_is_high():
    assert ANTHROPIC_API_KEY.severity == SEVERITY_HIGH
