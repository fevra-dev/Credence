"""Tests for unpinned AI middleware detection."""

from pathlib import Path

from credence.advanced.dependency_pinning import DependencyPinningScanner

FIXTURES = Path(__file__).parent / "fixtures"


def test_clean_requirements_has_no_findings():
    text = (FIXTURES / "requirements_clean.txt").read_text()
    findings = DependencyPinningScanner().scan(text, source="requirements.txt")
    assert findings == []


def test_unpinned_ai_middleware_flagged():
    text = (FIXTURES / "requirements_unpinned.txt").read_text()
    findings = DependencyPinningScanner().scan(text, source="requirements.txt")
    types = {f["type"] for f in findings}
    assert "unpinned_ai_middleware" in types
    flagged_packages = {f["package"] for f in findings}
    assert flagged_packages == {"litellm", "langchain", "openai", "crewai"}


def test_each_finding_has_severity_and_metadata():
    text = (FIXTURES / "requirements_unpinned.txt").read_text()
    findings = DependencyPinningScanner().scan(text, source="requirements.txt")
    for f in findings:
        assert f["severity"] == "HIGH"
        assert f["attack_class"] == "LLM05"
        assert f["atlas_technique"] == "AML.T0019"


def test_non_ai_packages_unpinned_are_not_flagged():
    """unpinned `requests` is real-world bad practice but not an AI-middleware risk."""
    findings = DependencyPinningScanner().scan(
        "requests\nflask\n", source="requirements.txt"
    )
    assert findings == []


def test_pep508_environment_markers_handled():
    """Lines with PEP 508 markers must still be parsed."""
    text = (
        "openai>=1.0; python_version>='3.8'\n"
        "anthropic==0.8.0; python_version<'3.12'\n"
    )
    findings = DependencyPinningScanner().scan(text, source="requirements.txt")
    flagged = {f["package"] for f in findings}
    assert "openai" in flagged       # unpinned with marker — must flag
    assert "anthropic" not in flagged  # pinned with marker — must not flag
