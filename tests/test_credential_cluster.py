"""Tests for paired-secret cluster detection and multi-provider-key file flagging."""

from credence.advanced.credential_cluster import process


def _secret(type_: str, source: str = "x.env") -> dict:
    return {"type": type_, "source": source, "severity": "CRITICAL", "value": "..."}


def test_no_cluster_when_only_one_secret_per_file():
    findings = [_secret("groq_api_key", "a.env"), _secret("openai_api_key", "b.env")]
    out = process(findings)
    assert all(f["type"] != "credential_cluster" for f in out)


def test_cluster_emitted_when_two_distinct_types_same_file():
    findings = [
        _secret("groq_api_key", "shared.env"),
        _secret("openai_api_key", "shared.env"),
    ]
    out = process(findings)
    cluster = [f for f in out if f["type"] == "credential_cluster"]
    assert len(cluster) == 1
    assert cluster[0]["severity"] == "CRITICAL"
    assert cluster[0]["source"] == "shared.env"
    assert "groq_api_key" in cluster[0]["member_types"]
    assert "openai_api_key" in cluster[0]["member_types"]


def test_originals_remain_in_output():
    findings = [
        _secret("groq_api_key", "shared.env"),
        _secret("openai_api_key", "shared.env"),
    ]
    out = process(findings)
    types = [f["type"] for f in out]
    assert "groq_api_key" in types
    assert "openai_api_key" in types


def test_cluster_member_findings_references():
    findings = [
        _secret("groq_api_key", "shared.env"),
        _secret("openai_api_key", "shared.env"),
    ]
    out = process(findings)
    cluster = next(f for f in out if f["type"] == "credential_cluster")
    assert len(cluster["member_findings"]) == 2


def test_multi_provider_file_flagged_for_oai_config_list():
    findings = [
        _secret("groq_api_key", "OAI_CONFIG_LIST"),
        _secret("openai_api_key", "OAI_CONFIG_LIST"),
    ]
    out = process(findings)
    multi = [f for f in out if f["type"] == "multi_provider_credential_file"]
    assert len(multi) == 1
    assert multi[0]["severity"] == "CRITICAL"
    assert "OAI_CONFIG_LIST" in multi[0]["source"]


def test_multi_provider_not_flagged_for_unrelated_path_with_two_secrets():
    """Two secrets in random.txt -> credential_cluster, NOT multi_provider_credential_file."""
    findings = [
        _secret("groq_api_key", "random.txt"),
        _secret("openai_api_key", "random.txt"),
    ]
    out = process(findings)
    assert any(f["type"] == "credential_cluster" for f in out)
    assert not any(f["type"] == "multi_provider_credential_file" for f in out)


def test_cluster_dedupes_same_type_same_file():
    """Two findings of the SAME type in same file -> no cluster (need >=2 *distinct* types)."""
    findings = [
        _secret("groq_api_key", "x.env"),
        _secret("groq_api_key", "x.env"),
    ]
    out = process(findings)
    assert not any(f["type"] == "credential_cluster" for f in out)


def test_includes_atlas_metadata_on_cluster_finding():
    findings = [
        _secret("groq_api_key", "shared.env"),
        _secret("openai_api_key", "shared.env"),
    ]
    out = process(findings)
    cluster = next(f for f in out if f["type"] == "credential_cluster")
    assert cluster["attack_class"] == "LLM06"
    assert cluster["atlas_technique"] == "AML.T0019"


def test_langsmith_v2_recognized_as_secret():
    """Regression: langsmith_api_key_v2 was being excluded from cluster detection
    because its name doesn't end in _api_key (ends in _v2)."""
    findings = [
        _secret("langsmith_api_key_v2", "shared.env"),
        _secret("openai_api_key", "shared.env"),
    ]
    out = process(findings)
    assert any(f["type"] == "credential_cluster" for f in out)


def test_langsmith_legacy_recognized_as_secret():
    findings = [
        _secret("langsmith_api_key_legacy", "shared.env"),
        _secret("openai_api_key", "shared.env"),
    ]
    out = process(findings)
    assert any(f["type"] == "credential_cluster" for f in out)


def test_elevenlabs_context_bound_recognized_as_secret():
    """Regression: elevenlabs_context_bound has no recognized suffix.
    Must be in the explicit allow-list."""
    findings = [
        _secret("elevenlabs_context_bound", "shared.env"),
        _secret("openai_api_key", "shared.env"),
    ]
    out = process(findings)
    assert any(f["type"] == "credential_cluster" for f in out)


def test_db_connection_strings_recognized_as_secrets():
    """postgres_url / mongodb_url contain credentials and must trigger clusters."""
    findings = [
        _secret("postgres_url", "shared.env"),
        _secret("openai_api_key", "shared.env"),
    ]
    out = process(findings)
    assert any(f["type"] == "credential_cluster" for f in out)


def test_non_secret_findings_still_excluded():
    """Sanity: non-secret types must still NOT trigger cluster detection."""
    findings = [
        {"type": "unpinned_ai_middleware", "source": "x.txt", "package": "openai"},
        {"type": "pth_persistence", "source": "x.txt"},
    ]
    out = process(findings)
    assert not any(f["type"] == "credential_cluster" for f in out)
