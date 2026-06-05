# tests/test_workflow_report.py
from credence.workflow_audit.report import render_report


FINDINGS = [
    {"rule_id": "WF-EXFIL-001", "title": "Secret to sink", "severity": "HIGH",
     "confidence": "HIGH", "file_path": ".github/workflows/s.yml", "job": "b",
     "step_index": 0, "line": 7, "message": "secret to evil.example",
     "frameworks": {"cicd_sec": ["CICD-SEC-4"], "mitre": ["T1567"]},
     "source": "history", "commit_short": "abc1234", "author": "ci-bot",
     "identity_flags": ["author_committer_mismatch"], "suppressed": False,
     "persists_in_history_only": True, "remediation": "rotate"},
    {"rule_id": "WF-CFG-003", "title": "Unpinned", "severity": "MEDIUM",
     "confidence": "MEDIUM", "file_path": ".github/workflows/s.yml", "job": "b",
     "line": 3, "message": "unpinned action", "frameworks": {"cicd_sec": [], "mitre": []},
     "source": "working_tree", "suppressed": True, "suppression_reason": "approved",
     "identity_flags": [], "persists_in_history_only": False, "remediation": ""},
]


def test_report_groups_and_shows_history_context():
    out = render_report(FINDINGS)
    assert "WF-EXFIL-001" in out
    assert "HIGH" in out
    assert "abc1234" in out and "ci-bot" in out               # history attribution
    assert "author_committer_mismatch" in out                # identity context
    assert "deletion" in out.lower() or "history" in out.lower()


def test_report_has_suppressed_section_separate():
    out = render_report(FINDINGS)
    assert "Suppressed" in out and "approved" in out
    # suppressed finding not double-counted in active section header
    assert "1 active" in out or "Active findings: 1" in out


def test_report_empty():
    assert "No workflow threats" in render_report([])
