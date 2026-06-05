# credence/workflow_audit/rules/inject_rules.py
"""Pillar 1 injection rules: WF-INJ-001 (untrusted context in run:),
WF-INJ-002 (untrusted input -> GITHUB_ENV / GITHUB_PATH)."""

from __future__ import annotations

import re
from typing import Dict, Iterable, List

from ..models import Confidence, ResolvedStep, Severity, Workflow
from ..platforms import untrusted_contexts
from . import RuleContext, make_finding, register


def _script_bodies(rs: ResolvedStep) -> List[str]:
    """run: text, plus actions/github-script inline `script:` (F-013)."""
    bodies = []
    if rs.step.run:
        bodies.append(rs.step.run)
    uses = (rs.step.uses or "")
    if "actions/github-script" in uses:
        script = rs.step.with_.get("script")
        if isinstance(script, str):
            bodies.append(script)
    return bodies


@register
def wf_inj_001(wf: Workflow, resolved: Dict[str, List[ResolvedStep]],
               ctx: RuleContext) -> Iterable:
    out: List = []
    for job_id, steps in resolved.items():
        for rs in steps:
            for body in _script_bodies(rs):
                found = untrusted_contexts(body)
                if found:
                    out.append(make_finding(
                        "WF-INJ-001", "Script injection via untrusted context",
                        Severity.HIGH, Confidence.HIGH, file_path=wf.path,
                        message=f"Untrusted context interpolated into a script body: {found[0]}",
                        job=job_id, step_index=rs.step.index, step_name=rs.step.name,
                        line=rs.step.line, snippet=body[:200],
                        cicd_sec=["CICD-SEC-4"], mitre=["T1059"],
                        remediation="Bind the value to an env: var and reference $VAR (quoted).",
                    ))
                    break
    return out


_GH_ENV_RE = re.compile(r">>?\s*\"?\$\{?(?:GITHUB_ENV|GITHUB_PATH)\b")


@register
def wf_inj_002(wf: Workflow, resolved: Dict[str, List[ResolvedStep]],
               ctx: RuleContext) -> Iterable:
    out: List = []
    for job_id, steps in resolved.items():
        for rs in steps:
            run = rs.step.run or ""
            if _GH_ENV_RE.search(run) and untrusted_contexts(run):
                out.append(make_finding(
                    "WF-INJ-002", "Untrusted input written to GITHUB_ENV/GITHUB_PATH",
                    Severity.HIGH, Confidence.MEDIUM, file_path=wf.path,
                    message="Untrusted context written to $GITHUB_ENV/$GITHUB_PATH (env/PATH injection)",
                    job=job_id, step_index=rs.step.index, step_name=rs.step.name,
                    line=rs.step.line, snippet=run[:200],
                    cicd_sec=["CICD-SEC-4"], mitre=["T1059"],
                    remediation="Sanitize untrusted input; never write it to GITHUB_ENV/GITHUB_PATH.",
                ))
    return out
