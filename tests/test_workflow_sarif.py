# tests/test_workflow_sarif.py
import json
from credence.workflow_audit.sarif import to_sarif


FINDINGS = [
    {"rule_id": "WF-EXFIL-001", "title": "Secret to sink", "severity": "HIGH",
     "confidence": "HIGH", "file_path": ".github/workflows/s.yml", "job": "b",
     "step_index": 0, "line": 7, "message": "secret to evil.example",
     "frameworks": {"cicd_sec": ["CICD-SEC-4"], "mitre": ["T1567"]},
     "source": "working_tree", "suppressed": False, "fingerprint": "deadbeefcafe0001",
     "identity_flags": [], "persists_in_history_only": False, "remediation": "rotate"},
    {"rule_id": "WF-CFG-003", "title": "Unpinned", "severity": "MEDIUM",
     "confidence": "MEDIUM", "file_path": ".github/workflows/s.yml", "line": 3,
     "message": "unpinned", "frameworks": {"cicd_sec": [], "mitre": []},
     "source": "working_tree", "suppressed": True, "suppression_reason": "ok",
     "fingerprint": "deadbeefcafe0002", "identity_flags": [],
     "persists_in_history_only": False, "remediation": ""},
]


def test_sarif_is_valid_shape():
    doc = json.loads(to_sarif(FINDINGS))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "credence-workflow-audit"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {"WF-EXFIL-001", "WF-CFG-003"} <= rule_ids


def test_sarif_results_carry_fingerprints_tags_and_suppressions():
    run = json.loads(to_sarif(FINDINGS))["runs"][0]
    exfil = [r for r in run["results"] if r["ruleId"] == "WF-EXFIL-001"][0]
    assert exfil["partialFingerprints"]["credence/v1"] == "deadbeefcafe0001"
    assert "CICD-SEC-4" in exfil["properties"]["tags"]
    cfg = [r for r in run["results"] if r["ruleId"] == "WF-CFG-003"][0]
    assert cfg["suppressions"][0]["kind"] == "inSource"
