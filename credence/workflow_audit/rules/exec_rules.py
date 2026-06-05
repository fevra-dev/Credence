# credence/workflow_audit/rules/exec_rules.py
"""Pillar 1 execution rules: WF-EXEC-001 (runtime-decoded shell exec),
WF-EXEC-002 (remote script piped to shell)."""

from __future__ import annotations

import re
from typing import Dict, Iterable, List

from ..models import Confidence, ResolvedStep, Severity, Workflow
from ..shellutil import has_decode_to_shell
from . import RuleContext, make_finding, register

from ..allowlist import is_installer_host
from ..shellutil import remote_pipe_to_shell

_EXEC_FILE_RE = re.compile(r"\b(?:bash|sh|zsh|dash|source|\.)\s+([\w./~-]+)")


@register
def wf_exec_001(wf: Workflow, resolved: Dict[str, List[ResolvedStep]],
                ctx: RuleContext) -> Iterable:
    out: List = []
    for job_id, steps in resolved.items():
        for rs in steps:
            run = rs.normalized_run
            if not run:
                continue
            hit = has_decode_to_shell(run)
            if not hit:
                # cross-step: this step executes a previously decoded file (taint)
                for m in _EXEC_FILE_RE.finditer(run):
                    if m.group(1) in rs.tainted_files:
                        hit = True
                        break
            if hit:
                out.append(make_finding(
                    "WF-EXEC-001", "Runtime-decoded shell execution",
                    Severity.HIGH, Confidence.HIGH,
                    file_path=wf.path, message="Encoded payload decoded and executed at runtime",
                    job=job_id, step_index=rs.step.index, step_name=rs.step.name,
                    line=rs.step.line, snippet=run[:200],
                    cicd_sec=["CICD-SEC-4"], mitre=["T1027", "T1059"],
                    remediation="Do not decode-and-execute at runtime; commit reviewed scripts.",
                ))
    return out


@register
def wf_exec_002(wf: Workflow, resolved: Dict[str, List[ResolvedStep]],
                ctx: RuleContext) -> Iterable:
    out: List = []
    for job_id, steps in resolved.items():
        for rs in steps:
            host = remote_pipe_to_shell(rs.normalized_run)
            if host is None and "|" not in (rs.normalized_run or ""):
                continue
            if host is None:
                continue
            installer = is_installer_host(host, ctx.extra_hosts)
            sev = Severity.INFO if installer else Severity.HIGH
            out.append(make_finding(
                "WF-EXEC-002", "Remote script piped to shell",
                sev, Confidence.MEDIUM,
                file_path=wf.path,
                message=f"Remote script from {host} piped to a shell",
                job=job_id, step_index=rs.step.index, step_name=rs.step.name,
                line=rs.step.line, snippet=rs.normalized_run[:200],
                cicd_sec=["CICD-SEC-3", "CICD-SEC-4"], mitre=["T1059"],
                remediation="Pin and verify install scripts; avoid curl|bash from untrusted hosts.",
            ))
    return out
