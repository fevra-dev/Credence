"""Tests for known-bad AI package version detection."""

from pathlib import Path

from credence.advanced.known_bad_versions import (
    KNOWN_BAD_VERSIONS,
    scan_requirements,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_corpus_contains_litellm_teampcp_versions():
    assert "1.82.7" in KNOWN_BAD_VERSIONS["litellm"]
    assert "1.82.8" in KNOWN_BAD_VERSIONS["litellm"]


def test_teampcp_fixture_yields_three_critical_findings():
    text = (FIXTURES / "requirements_teampcp.txt").read_text()
    findings = scan_requirements(text)
    assert len(findings) == 3
    packages = {f["package"] for f in findings}
    assert packages == {"litellm", "telnyx", "xinference"}
    for f in findings:
        assert f["severity"] == "CRITICAL"
        assert f["attack_class"] == "LLM05"


def test_clean_requirements_yields_no_findings():
    findings = scan_requirements("requests==2.31.0\nflask==3.0.0\n")
    assert findings == []


def test_safe_litellm_version_not_flagged():
    findings = scan_requirements("litellm==1.83.0\n")
    assert findings == []


def test_findings_include_evidence_with_package_and_version():
    text = (FIXTURES / "requirements_teampcp.txt").read_text()
    findings = scan_requirements(text)
    litellm_finding = next(f for f in findings if f["package"] == "litellm")
    assert "1.82.7" in litellm_finding["evidence"]
