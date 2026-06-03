"""Cross-source orphan signal: hash-only registry, frequency bands, no raw values."""
import json
import json as _json
from pathlib import Path

from credence.advanced.secret_registry import (
    SecretRegistry, frequency_band, KNOWN_EXAMPLE_KEYS, enrich,
)
from credence.agent_exposure.sarif import to_sarif


def test_frequency_bands():
    assert frequency_band(1) == "orphan_candidate"
    assert frequency_band(3) == "low"
    assert frequency_band(10) == "moderate"
    assert frequency_band(40) == "high"
    assert frequency_band(99) == "replicated"


def test_registry_stores_only_hashes(tmp_path):
    reg_path = tmp_path / "registry.json"
    reg = SecretRegistry(reg_path)
    reg.observe("AKIAREALSECRETVALUE123", "repo-a")
    reg.save()
    raw = reg_path.read_text()
    assert "AKIAREALSECRETVALUE123" not in raw
    data = json.loads(raw)
    assert all(len(k) == 64 for k in data)


def test_observe_counts_distinct_sources(tmp_path):
    reg = SecretRegistry(tmp_path / "r.json")
    assert reg.observe("secretX", "repo-a") == 1
    assert reg.observe("secretX", "repo-a") == 1
    assert reg.observe("secretX", "repo-b") == 2


def test_known_example_key_is_downgraded():
    findings = [{"type": "aws_access_key", "value_full": "AKIAIOSFODNN7EXAMPLE",
                 "severity": "HIGH", "source": "demo.py"}]
    enrich(findings, registry=None)
    assert findings[0]["severity"] == "INFO"
    assert findings[0]["source_frequency"] == "known_example"


def test_enrich_without_registry_still_tags_hash():
    findings = [{"type": "github_token", "value_full": "ghp_realtokenvalue000",
                 "severity": "HIGH", "source": "a.py"}]
    enrich(findings, registry=None)
    assert len(findings[0]["secret_value_hash"]) == 64


def test_enrich_with_registry_tags_orphan(tmp_path):
    reg = SecretRegistry(tmp_path / "r.json")
    findings = [{"type": "github_token", "value_full": "ghp_uniqueonce999",
                 "severity": "HIGH", "source": "a.py"}]
    enrich(findings, registry=reg)
    assert findings[0]["source_frequency"] == "orphan_candidate"


def test_non_secret_findings_are_untouched():
    findings = [{"type": "unpinned_ai_middleware", "severity": "LOW", "source": "req.txt"}]
    enrich(findings, registry=None)
    assert "secret_value_hash" not in findings[0]


def test_valueless_url_finding_is_not_hashed():
    # A non-credential *_url finding with no raw value must NOT be hashed/persisted
    # (the registry's secret set is intentionally narrower than the cluster's).
    findings = [{"type": "redirect_url", "severity": "LOW", "source": "app.py"}]
    enrich(findings, registry=None)
    assert "secret_value_hash" not in findings[0]


def test_db_connection_url_with_value_is_still_a_secret():
    # postgres_url etc. carry a raw value_full, so they still qualify via that branch.
    findings = [{"type": "postgres_url", "value_full": "postgresql://u:p@h:5432/db",
                 "severity": "HIGH", "source": "settings.py"}]
    enrich(findings, registry=None)
    assert len(findings[0]["secret_value_hash"]) == 64


def test_enrich_multi_source_progression(tmp_path):
    # Round-trip through enrich()->observe()->frequency_band as the SAME secret is
    # seen in progressively more distinct sources. The band reflects the live
    # cross-source count, not a stale value, and survives registry reload.
    reg = SecretRegistry(tmp_path / "r.json")
    secret = "ghp_progressionsecret123"

    def observe_from(source: str) -> str:
        f = [{"type": "github_token", "value_full": secret,
              "severity": "HIGH", "source": source}]
        enrich(f, registry=reg)
        return f[0]["source_frequency"]

    assert observe_from("repo-0") == "orphan_candidate"   # 1 distinct source
    assert observe_from("repo-1") == "low"                # 2 distinct sources
    for i in range(2, 6):
        observe_from(f"repo-{i}")                          # up to 6 distinct
    assert observe_from("repo-6") == "moderate"           # 7 distinct → moderate

    # Reload from disk and confirm the persisted count continues (not reset).
    reg2 = SecretRegistry(tmp_path / "r.json")
    f = [{"type": "github_token", "value_full": secret, "severity": "HIGH", "source": "repo-7"}]
    enrich(f, registry=reg2)
    assert f[0]["source_frequency"] == "moderate"          # 8 distinct sources


def test_sarif_emits_partial_fingerprint():
    findings = [{
        "type": "github_token", "severity": "HIGH", "source": "a.py",
        "description": "leak", "secret_value_hash": "a" * 64,
        "source_frequency": "orphan_candidate",
    }]
    doc = _json.loads(to_sarif(findings, "0.8.0"))
    result = doc["runs"][0]["results"][0]
    assert result["partialFingerprints"]["secretValueHash/v1"] == "a" * 64
    assert result["properties"]["source_frequency"] == "orphan_candidate"


def test_supply_chain_scan_tracks_when_enabled(tmp_path):
    from credence.advanced.local_fs_scanner import LocalFilesystemScanner
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.py").write_text('github_token = "ghp_' + "a" * 36 + '"\n')
    reg = tmp_path / "reg.json"
    findings = LocalFilesystemScanner().scan(repo, track=True, registry_path=str(reg))
    assert reg.is_file()
    secret = next((f for f in findings if f.get("secret_value_hash")), None)
    assert secret is not None
    assert secret["source_frequency"] == "orphan_candidate"


# --- v0.8.1 audit regression (F-004) ---

def test_registry_file_and_dir_are_not_world_readable(tmp_path):
    # F-004: the registry holds secret hashes + source file paths; on a shared host
    # a 0644 file leaks which files contain secrets. Must be 0600 file / 0700 dir.
    import os
    import stat
    reg_dir = tmp_path / "sub"
    reg_path = reg_dir / "registry.json"
    reg = SecretRegistry(reg_path)
    reg.observe("AKIAREALSECRETVALUE123", "services/auth/config.py")
    reg.save()
    fmode = stat.S_IMODE(os.stat(reg_path).st_mode)
    dmode = stat.S_IMODE(os.stat(reg_dir).st_mode)
    assert fmode & 0o077 == 0, f"registry file is group/other-accessible: {oct(fmode)}"
    assert dmode & 0o077 == 0, f"registry dir is group/other-accessible: {oct(dmode)}"
