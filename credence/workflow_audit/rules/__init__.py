# credence/workflow_audit/rules/__init__.py
"""Rule registry + central suppression. Each rule is a callable
(wf, resolved, ctx) -> Iterable[WorkflowFinding]. Suppression is visible-only:
findings are flagged suppressed (never deleted), and high/crit exec/exfil/inj
rules ignore suppression entirely (spec §6, v0.8.1 lesson)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Set

from ..models import (
    Confidence, Platform, ResolvedStep, Severity, Workflow, WorkflowFinding,
)
from ..allowlist import Suppression

# rule-id prefixes whose High/Crit findings are NON-suppressible
_NON_SUPPRESSIBLE_PREFIXES = ("WF-EXEC", "WF-EXFIL", "WF-INJ")
_SUPPRESS_LINE_WINDOW = 2   # directive must be within +/- N lines of the finding


@dataclass
class RuleContext:
    platform: Platform = Platform.GITHUB_ACTIONS
    extra_hosts: Set[str] = field(default_factory=set)
    suppressions: List[Suppression] = field(default_factory=list)
    source: str = "working_tree"


RULES: List[Callable[..., Iterable[WorkflowFinding]]] = []


def register(fn: Callable[..., Iterable[WorkflowFinding]]):
    RULES.append(fn)
    return fn


def make_finding(rule_id, title, severity, confidence, *, file_path, message,
                 job=None, step_index=None, step_name=None, line=0, snippet="",
                 cicd_sec=None, mitre=None, remediation="",
                 platform=Platform.GITHUB_ACTIONS) -> WorkflowFinding:
    return WorkflowFinding(
        rule_id=rule_id, title=title, severity=severity, confidence=confidence,
        platform=platform, file_path=file_path, message=message, job=job,
        step_index=step_index, step_name=step_name, line=line, snippet=snippet,
        cicd_sec=list(cicd_sec or []), mitre=list(mitre or []),
        remediation=remediation,
    )


def _is_non_suppressible(f: WorkflowFinding) -> bool:
    high = f.severity in (Severity.HIGH, Severity.CRITICAL)
    return high and f.rule_id.startswith(_NON_SUPPRESSIBLE_PREFIXES)


def apply_suppressions(findings, ctx: RuleContext) -> List[WorkflowFinding]:
    for f in findings:
        if _is_non_suppressible(f):
            continue
        for s in ctx.suppressions:
            if s.rule_id == f.rule_id and abs(s.line - f.line) <= _SUPPRESS_LINE_WINDOW:
                f.suppressed = True
                f.suppression_reason = s.reason
                break
    return findings


def run_rules(wf: Workflow, resolved: Dict[str, List[ResolvedStep]],
              ctx: RuleContext) -> List[WorkflowFinding]:
    findings: List[WorkflowFinding] = []
    for fn in RULES:
        findings.extend(fn(wf, resolved, ctx))
    return apply_suppressions(findings, ctx)


# Import rule modules for their @register side effects. Keep at bottom to avoid
# circular imports (modules import make_finding/register from this package).
from . import exec_rules, exfil_rules, inject_rules, config_rules  # noqa: E402,F401
