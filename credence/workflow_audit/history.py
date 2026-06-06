"""Git-history forensics: walk all CI-config blobs across history, run the
rules over each, attribute commit/author/identity. Mirrors the subprocess
approach of credence/git_history/scanner.py. Zero network."""

from __future__ import annotations

import copy as _copy
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .models import Severity, Workflow, WorkflowFinding
from .parser import parse_action, parse_workflow
from .taint import resolve_job
from .rules import RuleContext, run_rules

_WF_PREFIX = ".github/workflows/"
_ACTION_SUFFIX = ("/action.yml", "/action.yaml")
_SEP = "\x01"
# Use a printable field separator safe for subprocess args (not \x00 which subprocess rejects)
_FS = "\x1f"   # ASCII Unit Separator — rare in names, passes subprocess arg safely
# _PRETTY includes _SEP at the start (to mark commit header lines), then 6 FS-delimited fields
_PRETTY = f"{_SEP}%H{_FS}%an{_FS}%ae{_FS}%cn{_FS}%ce{_FS}%aI"
# For single-commit show, use the fields without the leading SEP and without SHA
_PRETTY_META = f"%an{_FS}%ae{_FS}%cn{_FS}%ce{_FS}%aI"

_BOTISH = ("bot", "ci-bot", "[bot]", "github-actions")

_GIT_TIMEOUT = 120          # bound any single git call (F-002: no-timeout hang DoS)
_MAX_BLOB_BYTES = 2 * 1024 * 1024   # skip historical blobs larger than this (F-003)
# Harden git invoked inside an UNTRUSTED repo against hostile .git/config / hooks /
# fsmonitor / ext transports (F-004); -c overrides take precedence over repo config.
_GIT_HARDEN = ["-c", "core.fsmonitor=", "-c", "core.hooksPath=/dev/null",
               "-c", "protocol.ext.allow=never"]


def _git_env() -> dict:
    env = dict(os.environ)
    env["GIT_CONFIG_NOSYSTEM"] = "1"     # ignore /etc/gitconfig
    env["GIT_TERMINAL_PROMPT"] = "0"     # never prompt
    env["GIT_ALLOW_PROTOCOL"] = "file:git:http:https:ssh"   # block ext transports
    return env


def _git(repo: Path, *args, timeout: int = _GIT_TIMEOUT):
    """Hardened, time-bounded git. Returns CompletedProcess, or None on timeout."""
    full = ["git", "-C", str(repo), *_GIT_HARDEN, *args]
    try:
        return subprocess.run(full, capture_output=True, text=True,
                              errors="replace", env=_git_env(), timeout=timeout)
    except FileNotFoundError:
        raise ValueError("git executable not found on PATH")
    except subprocess.TimeoutExpired:
        return None


@dataclass
class _Commit:
    sha: str
    author: str
    author_email: str
    committer: str
    committer_email: str
    date: str


def _is_ci_path(path: str) -> bool:
    return (path.startswith(_WF_PREFIX) and path.endswith((".yml", ".yaml"))) \
        or path.endswith(_ACTION_SUFFIX)


def _blob(repo: Path, sha: str, path: str) -> Optional[str]:
    # Bound memory: skip historical blobs over the cap (F-003) before `git show`
    # buffers the whole object into memory.
    size = _git(repo, "cat-file", "-s", f"{sha}:{path}")
    if size is None or size.returncode != 0:
        return None
    try:
        if int(size.stdout.strip()) > _MAX_BLOB_BYTES:
            return None
    except ValueError:
        pass
    out = _git(repo, "show", f"{sha}:{path}")
    if out is None or out.returncode != 0:
        return None
    return out.stdout


def _parse(path: str, text: str) -> Workflow:
    if path.endswith(_ACTION_SUFFIX):
        return parse_action(text, path=path)
    return parse_workflow(text, path=path)


def _run_over_blob(wf: Workflow, ctx: RuleContext) -> List[WorkflowFinding]:
    resolved = {j.job_id: resolve_job(wf, j) for j in wf.jobs}
    return run_rules(wf, resolved, ctx)


def _iter_commit_files(repo: Path, since, max_commits):
    args = ["log", "--all", "--reverse", "--no-color",
            "--name-status", f"--pretty=format:{_PRETTY}"]
    if since:
        args += ["--since", since]
    if max_commits:
        args += [f"--max-count={int(max_commits)}"]
    proc = _git(repo, *args)
    if proc is None:
        return
    commit: Optional[_Commit] = None
    for line in proc.stdout.splitlines():
        if line.startswith(_SEP):
            # line[1:] strips the SEP, then split on _FS gives: sha, an, ae, cn, ce, date
            parts = line[1:].split(_FS)
            if len(parts) == 6:
                sha, an, ae, cn, ce, date = parts
                commit = _Commit(sha, an, ae, cn, ce, date)
        elif line and commit and line[0] in ("A", "M"):
            parts = line.split("\t")
            if len(parts) >= 2 and _is_ci_path(parts[-1]):
                yield commit, parts[-1]


def _author_first_commits(repo: Path) -> Dict[str, str]:
    """Map author-email -> sha of their earliest commit across all history."""
    proc = _git(repo, "log", "--all", "--reverse", "--no-color",
                f"--pretty=format:%H{_FS}%ae")
    if proc is None:
        return {}
    first: Dict[str, str] = {}
    for line in proc.stdout.splitlines():
        if _FS in line:
            sha, ae = line.split(_FS, 1)
            first.setdefault(ae, sha)
    return first


def _identity_flags(commit: _Commit, first_by_email: Dict[str, str]) -> List[str]:
    flags: List[str] = []
    if commit.author_email != commit.committer_email or commit.author != commit.committer:
        flags.append("author_committer_mismatch")
    low = (commit.author + " " + commit.author_email).lower()
    if any(b in low for b in _BOTISH):
        flags.append("bot_authored_content_change")
    if first_by_email.get(commit.author_email) == commit.sha:
        flags.append("first_time_contributor_touching_workflows")
    if commit.author_email and ("noreply" in commit.author_email
                                or commit.author_email.count("@") != 1):
        flags.append("author_email_domain_anomaly")
    return flags


def _dedup_earliest(findings: List[WorkflowFinding]) -> List[WorkflowFinding]:
    seen = {}
    for f in findings:                       # findings already in --reverse (earliest-first) order
        key = (f.rule_id, f.file_path, f.job, f.snippet)
        if key not in seen:
            seen[key] = f
    return list(seen.values())


def _hist_findings(findings: List[WorkflowFinding],
                   working_tree_paths) -> List[WorkflowFinding]:
    out: List[WorkflowFinding] = []
    if working_tree_paths is None:
        return out
    for f in findings:
        high = f.severity in (Severity.HIGH, Severity.CRITICAL)
        content = f.rule_id.startswith(("WF-EXEC", "WF-EXFIL", "WF-INJ"))
        if high and content and f.file_path not in working_tree_paths:
            h = _copy.copy(f)
            h.rule_id = "WF-HIST-001"
            h.title = "Malicious pipeline persists in history after deletion"
            h.persists_in_history_only = True
            h.message = (f"{f.rule_id} fired on commit {f.commit_short} for a file "
                         f"no longer in the working tree (deletion != erasure)")
            h.cicd_sec = ["CICD-SEC-4"]
            out.append(h)
    return out


def _dangling_commits(repo: Path) -> List[str]:
    shas: List[str] = []
    out = _git(repo, "fsck", "--no-reflogs", "--lost-found")
    if out is not None:
        for line in (out.stdout + out.stderr).splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[1] == "commit":
                shas.append(parts[2])
    rl = _git(repo, "reflog", "--all", "--format=%H")
    if rl is not None:
        shas.extend(s for s in rl.stdout.split() if s)
    return list(dict.fromkeys(shas))


def _commit_meta(repo: Path, sha: str) -> Optional[_Commit]:
    out = _git(repo, "show", "-s", f"--pretty=format:{_PRETTY_META}", sha)
    if out is None or out.returncode != 0 or _FS not in out.stdout:
        return None
    parts = out.stdout.split(_FS)
    if len(parts) != 5:
        return None
    an, ae, cn, ce, date = parts
    return _Commit(sha, an, ae, cn, ce, date)


def _ci_paths_at(repo: Path, sha: str) -> List[str]:
    out = _git(repo, "ls-tree", "-r", "--name-only", sha)
    if out is None:
        return []
    return [p for p in out.stdout.splitlines() if _is_ci_path(p)]


def scan_history(repo_path, *, since: Optional[str] = None,
                 max_commits: Optional[int] = None,
                 working_tree_paths: Optional[set] = None,
                 extra_hosts: Optional[set] = None,
                 dedup: bool = False,
                 include_unreachable: bool = False) -> List[WorkflowFinding]:
    repo = Path(repo_path)
    findings: List[WorkflowFinding] = []
    first_by_email = _author_first_commits(repo)

    for commit, path in _iter_commit_files(repo, since, max_commits):
        text = _blob(repo, commit.sha, path)
        if text is None:
            continue
        wf = _parse(path, text)
        ctx = RuleContext(source="history", extra_hosts=extra_hosts or set())
        for f in _run_over_blob(wf, ctx):
            f.source = "history"
            f.commit = commit.sha
            f.commit_short = commit.sha[:7]
            f.author = commit.author
            f.committer = commit.committer
            f.commit_date = commit.date
            f.identity_flags = _identity_flags(commit, first_by_email)
            findings.append(f)

    if include_unreachable:
        seen_shas = {f.commit for f in findings if f.commit}
        for sha in _dangling_commits(repo):
            if sha in seen_shas:
                continue
            commit = _commit_meta(repo, sha)
            if not commit:
                continue
            for path in _ci_paths_at(repo, sha):
                text = _blob(repo, sha, path)
                if text is None:
                    continue
                wf = _parse(path, text)
                ctx = RuleContext(source="history", extra_hosts=extra_hosts or set())
                for f in _run_over_blob(wf, ctx):
                    f.source = "history"
                    f.commit, f.commit_short = sha, sha[:7]
                    f.author, f.committer, f.commit_date = (
                        commit.author, commit.committer, commit.date)
                    f.identity_flags = _identity_flags(commit, first_by_email)
                    findings.append(f)

    if dedup:
        findings = _dedup_earliest(findings)
    findings += _hist_findings(findings, working_tree_paths)
    return findings
