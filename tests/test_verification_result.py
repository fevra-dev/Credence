"""Tests for VerificationStatus enum and VerificationResult dataclass."""

import pytest

from credence.verification.result import VerificationResult, VerificationStatus


def test_status_enum_values():
    assert VerificationStatus.VERIFIED.value == "verified"
    assert VerificationStatus.DEAD.value == "dead"
    assert VerificationStatus.ERROR.value == "error"
    assert VerificationStatus.SKIPPED.value == "skipped"
    assert VerificationStatus.UNVERIFIABLE.value == "unverifiable"


def test_status_is_string_enum():
    """Each enum value must serialize as its raw string in JSON contexts.

    This is the actual product contract (reporters emit `verification_status`
    into JSON/SARIF). We assert str-equality and JSON serialization, NOT
    ``str()``/``f"{...}"`` — the ``(str, Enum)`` ``__str__``/``__format__``
    output changed across Python 3.10/3.11/3.12 and is not what the product uses.
    """
    import json

    assert VerificationStatus.VERIFIED == "verified"        # str-enum identity
    assert VerificationStatus.DEAD.value == "dead"
    # What reporters actually rely on: a str-enum serializes to its raw value.
    assert json.dumps(VerificationStatus.DEAD) == '"dead"'
    assert json.dumps({"s": VerificationStatus.ERROR}) == '{"s": "error"}'


def test_verification_result_holds_status_and_detail():
    r = VerificationResult(status=VerificationStatus.VERIFIED, detail="200")
    assert r.status == VerificationStatus.VERIFIED
    assert r.detail == "200"


def test_verification_result_detail_optional():
    r = VerificationResult(status=VerificationStatus.DEAD)
    assert r.detail is None
