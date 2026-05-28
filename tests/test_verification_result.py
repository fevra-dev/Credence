"""Tests for VerificationStatus enum and VerificationResult dataclass."""

import pytest

from gitexpose.verification.result import VerificationResult, VerificationStatus


def test_status_enum_values():
    assert VerificationStatus.VERIFIED.value == "verified"
    assert VerificationStatus.DEAD.value == "dead"
    assert VerificationStatus.ERROR.value == "error"
    assert VerificationStatus.SKIPPED.value == "skipped"
    assert VerificationStatus.UNVERIFIABLE.value == "unverifiable"


def test_status_is_string_enum():
    """Each enum value should serialize as its string in JSON contexts."""
    assert VerificationStatus.VERIFIED == "verified"
    assert f"{VerificationStatus.DEAD}" == "VerificationStatus.DEAD"
    # Critical: when cast to str via .value, gives the raw string
    assert VerificationStatus.VERIFIED.value == "verified"


def test_verification_result_holds_status_and_detail():
    r = VerificationResult(status=VerificationStatus.VERIFIED, detail="200")
    assert r.status == VerificationStatus.VERIFIED
    assert r.detail == "200"


def test_verification_result_detail_optional():
    r = VerificationResult(status=VerificationStatus.DEAD)
    assert r.detail is None
