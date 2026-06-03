"""Tests for CVSS v3.1 base-score computation and severity bucketing."""

import pytest

from credence.supply_chain.cvss import base_score_from_vector, bucket, severity_from_osv


@pytest.mark.parametrize("vector, expected", [
    # Official CVSS 3.1 examples
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),    # critical
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),    # high
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),    # low
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),    # scope changed
])
def test_base_score_known_vectors(vector, expected):
    assert base_score_from_vector(vector) == pytest.approx(expected, abs=0.05)


def test_bucket_thresholds():
    assert bucket(9.8) == "CRITICAL"
    assert bucket(7.5) == "HIGH"
    assert bucket(5.0) == "MEDIUM"
    assert bucket(1.8) == "LOW"


def test_severity_from_osv_prefers_qualitative():
    osv = {"database_specific": {"severity": "HIGH"}}
    sev, score = severity_from_osv(osv)
    assert sev == "HIGH"
    assert score is None


def test_severity_from_osv_uses_cvss_vector():
    osv = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    sev, score = severity_from_osv(osv)
    assert sev == "CRITICAL"
    assert score == pytest.approx(9.8, abs=0.05)


def test_severity_from_osv_defaults_medium():
    sev, score = severity_from_osv({})
    assert sev == "MEDIUM"
    assert score is None
