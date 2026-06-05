# credence/workflow_audit/rules/exfil_rules.py
"""Pillar 1 exfiltration rules: WF-EXFIL-001 (secret -> outbound sink),
WF-EXFIL-002 (env/secret dump to network or log)."""

from __future__ import annotations

import re
from typing import Dict, Iterable, List

from ..models import Confidence, ResolvedStep, Severity, Workflow
from ..allowlist import is_platform_host
from ..shellutil import outbound_sinks, references_vars
from . import RuleContext, make_finding, register

_DIRECT_SECRET_RE = re.compile(r"\$\{\{\s*secrets\.[A-Za-z0-9_-]+\s*\}\}")
# write to a *foreign* path via the platform API (issues/gists/dispatches)
_PLATFORM_WRITE_RE = re.compile(r"/(?:gists|repos/[^/\s]+/[^/\s]+/(?:issues|dispatches))")


def _step_has_secret(rs: ResolvedStep) -> bool:
    run = rs.normalized_run
    if _DIRECT_SECRET_RE.search(run):
        return True
    return references_vars(run, set(rs.secret_vars.keys()))


@register
def wf_exfil_001(wf: Workflow, resolved: Dict[str, List[ResolvedStep]],
                 ctx: RuleContext) -> Iterable:
    out: List = []
    for job_id, steps in resolved.items():
        for rs in steps:
            if not _step_has_secret(rs):
                continue
            for sink in outbound_sinks(rs.normalized_run):
                sev = None
                host = sink["host"]
                if sink["dns"] or sink["dynamic"]:
                    sev = Severity.HIGH
                elif host and is_platform_host(host):
                    if _PLATFORM_WRITE_RE.search(rs.normalized_run):
                        sev = Severity.MEDIUM   # platform-channel abuse (could be legit)
                elif host:
                    sev = Severity.HIGH
                if sev is None:
                    continue
                out.append(make_finding(
                    "WF-EXFIL-001", "Secret value sent to outbound sink",
                    sev, Confidence.HIGH if sev == Severity.HIGH else Confidence.MEDIUM,
                    file_path=wf.path,
                    message=f"Secret-tainted value reaches {sink['tool']} "
                            f"({'DNS' if sink['dns'] else (host or 'dynamic host')})",
                    job=job_id, step_index=rs.step.index, step_name=rs.step.name,
                    line=rs.step.line, snippet=rs.normalized_run[:200],
                    cicd_sec=["CICD-SEC-4"], mitre=["T1567", "T1041"],
                    remediation="Never send secrets to external hosts; scope/rotate the secret.",
                ))
                break  # one finding per step is enough
    return out
