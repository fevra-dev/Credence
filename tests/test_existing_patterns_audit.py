"""Audit test — documents what credential patterns already exist in v0.1.0.
This test exists to lock the audit findings into CI; delete after Task 4 ships."""

from credence.secrets.secret_extractor import SecretExtractor


def test_v01_pattern_inventory():
    """Confirm the v0.1.0 pattern inventory the v0.2 plan was built on."""
    extractor = SecretExtractor()
    expected_present = {
        "aws_access_key",
        "aws_secret_key",
        "gcp_api_key",
        "github_token",
        "slack_token",
        "slack_webhook",
        "stripe_key",
        "sendgrid_key",
        "postgres_url",
        "mysql_url",
        "mongodb_url",
        "private_key",
        "jwt_token",
        "generic_api_key",
        "generic_password",
    }
    present = set(extractor.PATTERNS.keys())
    missing = expected_present - present
    assert not missing, f"Audit drift: expected patterns missing: {missing}"
