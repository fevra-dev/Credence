"""Tests for slopsquatting (LLM-hallucinated package name) detection."""

from pathlib import Path

from credence.advanced.slopsquatting import (
    KNOWN_SLOPSQUATS,
    check,
    scan_requirements,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_corpus_contains_canonical_examples():
    assert "huggingface-cli" in KNOWN_SLOPSQUATS  # 30K downloads from Alibaba readme
    assert "openai-sdk" in KNOWN_SLOPSQUATS
    assert "anthropicc" in KNOWN_SLOPSQUATS


def test_check_returns_true_for_known_slop():
    assert check("huggingface-cli") is True
    assert check("HUGGINGFACE-CLI") is True  # case-insensitive
    assert check("huggingface_cli") is True  # underscore normalized


def test_check_returns_false_for_legit_packages():
    assert check("requests") is False
    assert check("flask") is False
    assert check("openai") is False  # legitimate
    assert check("anthropic") is False


def test_scan_fixture_yields_three_critical_findings():
    text = (FIXTURES / "requirements_slopsquat.txt").read_text()
    findings = scan_requirements(text)
    packages = {f["package"] for f in findings}
    assert packages == {"huggingface-cli", "openai-sdk", "anthropicc"}
    for f in findings:
        assert f["severity"] == "CRITICAL"
        assert f["attack_class"] == "LLM05"
        assert f["type"] == "slopsquatting"


def test_corpus_size_at_least_fifteen():
    assert len(KNOWN_SLOPSQUATS) >= 15
