"""Tests for v0.3 additions to data models — verification status fields."""

import asyncio

from gitexpose.models import Category, ScanResult, Severity
from gitexpose.secrets.secret_extractor import SecretExtractor


def test_scan_result_has_optional_verification_status():
    result = ScanResult(
        url="https://example.com/.env",
        path=".env",
        target="https://example.com",
        status_code=200,
        vulnerable=True,
        severity=Severity.CRITICAL,
        category=Category.ENV,
        description="x",
        evidence="x",
        verification_status="verified",
        verification_detail="200",
    )
    assert result.verification_status == "verified"
    assert result.verification_detail == "200"


def test_scan_result_verification_defaults_to_skipped():
    result = ScanResult(
        url="x",
        path="x",
        target="x",
        status_code=200,
        vulnerable=True,
        severity=Severity.LOW,
        category=Category.SENSITIVE,
        description="x",
        evidence="x",
    )
    assert result.verification_status == "skipped"
    assert result.verification_detail is None


def test_secret_dict_has_verification_keys():
    extractor = SecretExtractor()
    secrets = asyncio.run(extractor.extract("GROQ_API_KEY=gsk_" + "a" * 52))
    assert secrets, "expected at least one secret"
    for s in secrets:
        assert "verification_status" in s
        assert "verification_detail" in s
        assert s["verification_status"] == "skipped"
        assert s["verification_detail"] is None
