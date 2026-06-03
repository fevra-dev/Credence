"""Tests for v0.2 additions to data models."""

from credence.models import Category, ScanResult, Severity


def test_scan_result_has_optional_attack_class():
    """ScanResult should accept an optional OWASP LLM Top 10 ID."""
    result = ScanResult(
        url="https://example.com/.env",
        path=".env",
        target="https://example.com",
        status_code=200,
        vulnerable=True,
        severity=Severity.CRITICAL,
        category=Category.ENV,
        description="Environment file exposed",
        evidence="Found: API_KEY=sk-...",
        attack_class="LLM06",
    )
    assert result.attack_class == "LLM06"


def test_scan_result_has_optional_atlas_technique():
    """ScanResult should accept an optional MITRE ATLAS technique ID."""
    result = ScanResult(
        url="https://example.com/.git/config",
        path=".git/config",
        target="https://example.com",
        status_code=200,
        vulnerable=True,
        severity=Severity.CRITICAL,
        category=Category.GIT,
        description="Git config exposed",
        evidence="[remote \"origin\"]",
        atlas_technique="AML.T0019",
    )
    assert result.atlas_technique == "AML.T0019"


def test_scan_result_metadata_defaults_to_none():
    """attack_class and atlas_technique default to None."""
    result = ScanResult(
        url="https://example.com/x",
        path="x",
        target="https://example.com",
        status_code=200,
        vulnerable=True,
        severity=Severity.LOW,
        category=Category.SENSITIVE,
        description="x",
        evidence="x",
    )
    assert result.attack_class is None
    assert result.atlas_technique is None
