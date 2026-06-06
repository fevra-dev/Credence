"""Orchestrator: discover CI files, run rules on the working tree and (optionally)
git history, merge to List[Dict] findings with stable fingerprints. Fail-loud on
unparseable-but-real workflow files (F-009)."""

from __future__ import annotations

import fnmatch
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Set

from .allowlist import parse_suppressions
from .models import Confidence, Platform, Severity, WorkflowFinding
from .parser import parse_action, parse_workflow
from .platforms import ACTION_GLOBS, WORKFLOW_GLOBS
from .taint import resolve_job
from .rules import RuleContext, run_rules
from .history import scan_history

_MAX_FILE_BYTES = 2 * 1024 * 1024   # workflow YAML is normally < 50 KB (F-003)


def _fingerprint(f: WorkflowFinding) -> str:
    basis = f"{f.rule_id}|{f.file_path}|{f.job}|{f.source}|{f.commit or ''}|{f.snippet}"
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:16]


def _is_action_path(rel: str) -> bool:
    """Match action.yml/action.yaml at:
      - root level (action.yml, action.yaml)
      - anywhere under .github/actions/ (including directly in that dir)

    NOTE: fnmatch does NOT treat '**' as recursive — it acts like '*' which
    requires at least one intervening path character, so
    '.github/actions/**/action.yml' misses '.github/actions/action.yml'.
    We fix this by checking the path structure directly.
    """
    if rel in ("action.yml", "action.yaml"):
        return True
    # Under .github/actions/ at any depth, filename is action.yml or action.yaml
    parts = rel.split("/")
    if len(parts) >= 3 and parts[0] == ".github" and parts[1] == "actions":
        return parts[-1] in ("action.yml", "action.yaml")
    return False


def _discover(root: Path) -> List[Path]:
    out: List[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(rel, g) for g in WORKFLOW_GLOBS) or _is_action_path(rel):
            out.append(p)
    return out


def _scan_file(path: Path, root: Path, extra_hosts: Set[str]) -> List[WorkflowFinding]:
    rel = path.relative_to(root).as_posix()
    # Bound memory: read at most the cap; a multi-MB workflow file is anomalous
    # and could be DoS bait (F-003).
    try:
        with path.open("r", errors="replace") as fh:
            text = fh.read(_MAX_FILE_BYTES + 1)
    except OSError:
        return []
    if len(text) > _MAX_FILE_BYTES:
        return [WorkflowFinding(
            rule_id="WF-SIZE-001", title="Workflow file too large to scan",
            severity=Severity.LOW, confidence=Confidence.HIGH,
            platform=Platform.GITHUB_ACTIONS, file_path=rel,
            message=f"File exceeds the {_MAX_FILE_BYTES // (1024 * 1024)} MB scan cap; "
                    f"skipped (possible DoS bait)",
            line=1, cicd_sec=["CICD-SEC-7"],
            remediation="Workflow files should be small; investigate oversized YAML.")]
    is_action = _is_action_path(rel)
    wf = parse_action(text, path=rel) if is_action else parse_workflow(text, path=rel)
    if not wf.parse_ok:
        return [WorkflowFinding(
            rule_id="WF-PARSE-001",
            title="Unparseable workflow GitHub may still execute",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            platform=Platform.GITHUB_ACTIONS, file_path=rel,
            message="File did not parse as YAML; rule coverage degraded (fail-loud, F-009)",
            line=1, cicd_sec=["CICD-SEC-7"],
            remediation="Validate the workflow YAML; malformed files can still run.")]
    ctx = RuleContext(suppressions=parse_suppressions(text), extra_hosts=extra_hosts)
    resolved = {j.job_id: resolve_job(wf, j) for j in wf.jobs}
    return run_rules(wf, resolved, ctx)


def scan(path, *, history: bool = True, include_unreachable: bool = False,
         since: Optional[str] = None, max_commits: Optional[int] = None,
         extra_hosts: Optional[Set[str]] = None) -> List[Dict]:
    root = Path(path)
    extra_hosts = extra_hosts or set()
    findings: List[WorkflowFinding] = []
    wt_paths: Set[str] = set()
    for f in _discover(root):
        rel = f.relative_to(root).as_posix()
        wt_paths.add(rel)
        findings.extend(_scan_file(f, root, extra_hosts))
    for f in findings:
        f.source = "working_tree"
    if history and (root / ".git").exists():
        findings.extend(scan_history(
            root, since=since, max_commits=max_commits,
            include_unreachable=include_unreachable,
            working_tree_paths=wt_paths, extra_hosts=extra_hosts, dedup=True))
    for f in findings:
        f.fingerprint = _fingerprint(f)
    return [f.to_dict() for f in findings]
