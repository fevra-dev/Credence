"""Cross-source orphan signal: hash-only registry, frequency bands, no raw values."""
import json
from pathlib import Path

from gitexpose.advanced.secret_registry import (
    SecretRegistry, frequency_band, KNOWN_EXAMPLE_KEYS, enrich,
)


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


import json as _json
from gitexpose.agent_exposure.sarif import to_sarif


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
    from gitexpose.advanced.local_fs_scanner import LocalFilesystemScanner
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.py").write_text('github_token = "ghp_' + "a" * 36 + '"\n')
    reg = tmp_path / "reg.json"
    findings = LocalFilesystemScanner().scan(repo, track=True, registry_path=str(reg))
    assert reg.is_file()
    secret = next((f for f in findings if f.get("secret_value_hash")), None)
    assert secret is not None
    assert secret["source_frequency"] == "orphan_candidate"
