"""End-to-end smoke test: synthetic repo with planted findings."""

from pathlib import Path

from gitexpose.advanced.local_fs_scanner import LocalFilesystemScanner

REPO = Path(__file__).parent / "fixtures" / "synthetic_repo"


def test_smoke_finds_known_bad_litellm():
    findings = LocalFilesystemScanner().scan(REPO)
    assert any(
        f["type"] == "known_malicious_package_version"
        and f["package"] == "litellm"
        for f in findings
    )


def test_smoke_finds_unpinned_crewai():
    findings = LocalFilesystemScanner().scan(REPO)
    assert any(
        f["type"] == "unpinned_ai_middleware" and f["package"] == "crewai"
        for f in findings
    )


def test_smoke_finds_groq_in_continue_yaml():
    findings = LocalFilesystemScanner().scan(REPO)
    assert any(
        f["type"] == "groq_api_key"
        and ".continue/agents/new-config.yaml" in f.get("source", "")
        for f in findings
    )


def test_smoke_finds_anthropic_in_claude_credentials():
    findings = LocalFilesystemScanner().scan(REPO)
    assert any(
        f["type"] == "anthropic_api_key"
        and "claude/.credentials.json" in f.get("source", "")
        for f in findings
    )


def test_smoke_emits_credential_cluster_for_continue_yaml():
    """new-config.yaml has both groq and openai keys → cluster."""
    findings = LocalFilesystemScanner().scan(REPO)
    clusters = [f for f in findings if f["type"] == "credential_cluster"]
    assert any(
        ".continue/agents/new-config.yaml" in c.get("source", "") for c in clusters
    )


def test_smoke_emits_multi_provider_for_continue_yaml():
    """.continue/agents/*.yaml is an aggregator path → multi-provider finding."""
    findings = LocalFilesystemScanner().scan(REPO)
    assert any(
        f["type"] == "multi_provider_credential_file"
        and ".continue/agents/" in f.get("source", "")
        for f in findings
    )


def test_smoke_clean_module_has_no_findings():
    findings = LocalFilesystemScanner().scan(REPO)
    sources_with_findings = {f.get("source", "") for f in findings}
    assert "clean_module.py" not in sources_with_findings


def test_smoke_severity_distribution():
    findings = LocalFilesystemScanner().scan(REPO)
    severities = [f.get("severity") for f in findings]
    assert "CRITICAL" in severities
