# tests/test_workflow_rules_registry.py
from credence.workflow_audit.models import (
    Severity, Confidence, Platform, WorkflowFinding,
)
from credence.workflow_audit.allowlist import Suppression
from credence.workflow_audit.rules import (
    RuleContext, register, RULES, apply_suppressions, make_finding,
)


def _f(rule_id, sev, line=5):
    return WorkflowFinding(
        rule_id=rule_id, title="t", severity=sev, confidence=Confidence.HIGH,
        platform=Platform.GITHUB_ACTIONS, file_path="x", message="m", line=line)


def test_make_finding_attaches_frameworks_and_defaults():
    f = make_finding("WF-CFG-002", "Excessive perms", Severity.MEDIUM,
                     Confidence.HIGH, file_path="x", message="m",
                     cicd_sec=["CICD-SEC-5"], mitre=[])
    assert f.cicd_sec == ["CICD-SEC-5"]
    assert f.platform == Platform.GITHUB_ACTIONS


def test_low_severity_finding_suppressed_when_matching_directive_near():
    ctx = RuleContext(suppressions=[Suppression("WF-CFG-003", line=5, reason="ok")])
    out = apply_suppressions([_f("WF-CFG-003", Severity.LOW, line=5)], ctx)
    assert out[0].suppressed is True
    assert out[0].suppression_reason == "ok"


def test_high_exfil_finding_never_suppressed():
    ctx = RuleContext(suppressions=[Suppression("WF-EXFIL-001", line=5, reason="x")])
    out = apply_suppressions([_f("WF-EXFIL-001", Severity.HIGH, line=5)], ctx)
    assert out[0].suppressed is False   # high/crit exec/exfil/inj ignore suppression


def test_suppression_requires_line_proximity():
    ctx = RuleContext(suppressions=[Suppression("WF-CFG-003", line=99, reason="x")])
    out = apply_suppressions([_f("WF-CFG-003", Severity.LOW, line=5)], ctx)
    assert out[0].suppressed is False   # far-away directive does not apply
