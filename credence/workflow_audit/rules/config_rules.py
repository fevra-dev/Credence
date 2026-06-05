# credence/workflow_audit/rules/config_rules.py
"""Pillar 3 blast-radius rules WF-CFG-001..006."""

from __future__ import annotations

import re
from typing import Dict, Iterable, List

from ..models import Confidence, ResolvedStep, Severity, Workflow
from ..platforms import (
    CANONICAL_PRIVILEGED_TRIGGERS, PRIVILEGED_TRIGGERS, is_pr_controlled_ref,
)
from . import RuleContext, make_finding, register

_SHA_RE = re.compile(r"@[0-9a-f]{40}$")
_FIRST_PARTY = ("actions/", "github/")


@register
def wf_cfg_001(wf: Workflow, resolved, ctx: RuleContext) -> Iterable:
    triggers = set(wf.on_events)
    privileged = triggers & PRIVILEGED_TRIGGERS
    if not privileged:
        return []
    out: List = []
    canonical = bool(triggers & CANONICAL_PRIVILEGED_TRIGGERS)
    for job in wf.jobs:
        for step in job.steps:
            if step.uses and "actions/checkout" in step.uses:
                ref = str(step.with_.get("ref", ""))
                if is_pr_controlled_ref(ref):
                    out.append(make_finding(
                        "WF-CFG-001", "Privileged trigger checks out untrusted PR code",
                        Severity.HIGH,
                        Confidence.HIGH if canonical else Confidence.MEDIUM,
                        file_path=wf.path,
                        message=f"{', '.join(sorted(privileged))} + checkout of PR-controlled ref",
                        job=job.job_id, step_index=step.index, step_name=step.name,
                        line=step.line, snippet=ref[:120],
                        cicd_sec=["CICD-SEC-4"], mitre=["T1195"],
                        remediation="Do not checkout PR head under privileged triggers; use the workflow_run split.",
                    ))
    return out


def _is_broad(perms) -> bool:
    if perms == "write-all":
        return True
    if isinstance(perms, dict):
        return perms.get("id-token") == "write" and perms.get("contents") == "write"
    return False


@register
def wf_cfg_002(wf: Workflow, resolved, ctx: RuleContext) -> Iterable:
    # absent at both workflow and job level, OR explicitly broad
    if wf.permissions_absent and all(j.permissions_absent for j in wf.jobs):
        return [make_finding(
            "WF-CFG-002", "No explicit permissions (broad default token)",
            Severity.MEDIUM, Confidence.HIGH, file_path=wf.path,
            message="No permissions: block; GITHUB_TOKEN inherits broad default",
            line=1, cicd_sec=["CICD-SEC-5"], mitre=[],
            remediation="Add a least-privilege permissions: block (start from contents: read).")]
    out: List = []
    if _is_broad(wf.permissions):
        out.append(make_finding(
            "WF-CFG-002", "Excessive workflow permissions", Severity.MEDIUM,
            Confidence.HIGH, file_path=wf.path, message="Workflow grants broad permissions",
            line=1, cicd_sec=["CICD-SEC-5"], mitre=[],
            remediation="Scope permissions to the minimum required."))
    for j in wf.jobs:
        if _is_broad(j.permissions):
            out.append(make_finding(
                "WF-CFG-002", "Excessive job permissions", Severity.MEDIUM,
                Confidence.HIGH, file_path=wf.path,
                message=f"Job '{j.job_id}' grants broad permissions", job=j.job_id,
                line=j.line, cicd_sec=["CICD-SEC-5"], mitre=[],
                remediation="Scope job permissions to the minimum required."))
    return out


@register
def wf_cfg_003(wf: Workflow, resolved, ctx: RuleContext) -> Iterable:
    out: List = []
    for job in wf.jobs:
        for step in job.steps:
            uses = step.uses or ""
            if not uses or "@" not in uses or uses.startswith("./") or uses.startswith("docker://"):
                if uses.startswith("docker://"):
                    out.append(make_finding(
                        "WF-CFG-003", "Docker action reference (unpinnable trust)",
                        Severity.MEDIUM, Confidence.MEDIUM, file_path=wf.path,
                        message=f"docker:// action: {uses}", job=job.job_id,
                        step_index=step.index, line=step.line,
                        cicd_sec=["CICD-SEC-3"], mitre=["T1195.2"],
                        remediation="Prefer SHA-pinned first-party actions over docker:// images."))
                continue
            if uses.startswith(_FIRST_PARTY):
                continue            # first-party @tag -> Low, not surfaced at default
            ref = uses.split("@", 1)[1]
            if _SHA_RE.search(uses):
                continue            # SHA-pinned third party -> clean (impostor check is best-effort, Plan 3)
            looks_branch = not re.match(r"v?\d", ref)
            out.append(make_finding(
                "WF-CFG-003", "Unpinned third-party action",
                Severity.MEDIUM if looks_branch else Severity.LOW,
                Confidence.MEDIUM, file_path=wf.path,
                message=f"Third-party action not SHA-pinned: {uses}", job=job.job_id,
                step_index=step.index, line=step.line,
                cicd_sec=["CICD-SEC-3"], mitre=["T1195.2"],
                remediation="Pin third-party actions to a full commit SHA."))
    return out
