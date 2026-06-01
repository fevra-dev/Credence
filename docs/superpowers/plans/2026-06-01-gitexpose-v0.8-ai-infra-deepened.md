# GitExpose v0.8 "AI-Infra Layer, Deepened" Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add four high-precision AI-infra finding capabilities (git-metadata credentials, agent debug-print AST, MCP security score, orphan cross-source signal) plus a shared `--fail-on` severity exit gate, all local/stdlib-only, shipping as GitExpose v0.8.0.

**Architecture:** Every feature emits the existing **finding-dict** shape (`{type, severity, source, description, attack_class, atlas_technique, ...}`) and flows through the existing `supply-chain` (→ `LocalFilesystemScanner` → `credential_cluster.process`) and `agent-audit` (→ `agent_exposure.scan` → `analyze_configs`) pipelines and shared console/json/sarif reporters. No new plumbing, no new runtime deps, no network calls.

**Tech Stack:** Python 3.9+, stdlib only (`configparser`, `ast`, `hashlib`, `base64`, `json`), Click CLI, pytest. SARIF 2.1.0 output via the existing `agent_exposure/sarif.py` emitter.

**Spec:** `docs/superpowers/specs/2026-06-01-gitexpose-v0.8-design.md`

**Build order (locked):** Task 1 (`--fail-on` foundation) → Task 2 (git-metadata) → Task 3 (debug-print) → Task 4 (MCP score) → Task 5 (orphan signal + SARIF) → Task 6 (supply-chain SARIF output) → Task 7 (release: version/docs/smoke).

**Conventions to follow (observed in the codebase):**
- Tests are flat files `tests/test_<area>.py`; fixtures live in `tests/fixtures/<name>_v0X/`.
- Local scanners are pure functions/classes returning `List[Dict]`; one bad file never aborts a scan (per-file try/except).
- `severity` values are the strings `"CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO"`.
- Commit messages use the project's `type(scope): subject` style (e.g. `feat(v0.8): ...`).
- Run the full suite with `python -m pytest -q`.

---

## Task 1: `--fail-on` severity exit-gate foundation

**Files:**
- Create: `gitexpose/cli_gating.py`
- Modify: `gitexpose/cli_advanced.py` (add decorator import + apply to `supply-chain`, `agent-audit`, `git-history`; replace their `sys.exit` lines)
- Test: `tests/test_cli_fail_on.py`

The gate: collect findings, print them all as today, then exit `1` only if any finding's severity is `>=` the `--fail-on` threshold; else exit `0`. Default threshold `HIGH`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli_fail_on.py
"""--fail-on severity gating: findings always print; exit code is thresholded."""
from gitexpose.cli_gating import exit_code_for, SEVERITY_ORDER


def test_severity_order_is_total():
    assert SEVERITY_ORDER["CRITICAL"] > SEVERITY_ORDER["HIGH"] > SEVERITY_ORDER["MEDIUM"]
    assert SEVERITY_ORDER["MEDIUM"] > SEVERITY_ORDER["LOW"] > SEVERITY_ORDER["INFO"]


def test_no_findings_is_clean_exit():
    assert exit_code_for([], "high") == 0


def test_high_finding_trips_default_high_gate():
    findings = [{"severity": "HIGH"}]
    assert exit_code_for(findings, "high") == 1


def test_low_finding_does_not_trip_high_gate():
    findings = [{"severity": "LOW"}]
    assert exit_code_for(findings, "high") == 0


def test_low_finding_trips_info_gate():
    findings = [{"severity": "LOW"}]
    assert exit_code_for(findings, "info") == 1


def test_missing_severity_treated_as_info():
    # A finding with no severity must not silently fail a high gate.
    assert exit_code_for([{"type": "x"}], "high") == 0
    # ...but an info gate catches everything, including unmarked findings.
    assert exit_code_for([{"type": "x"}], "info") == 1


def test_critical_trips_every_gate():
    for floor in ("info", "low", "medium", "high", "critical"):
        assert exit_code_for([{"severity": "CRITICAL"}], floor) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli_fail_on.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'gitexpose.cli_gating'`

- [ ] **Step 3: Write minimal implementation**

```python
# gitexpose/cli_gating.py
"""Shared --fail-on severity exit gate for local subcommands.

Findings are always printed by the caller; this module only decides the process
exit code. A finding trips the gate when its severity rank is >= the threshold.
Findings without a severity are treated as INFO (rank 0) so they only trip the
loosest gate (--fail-on info), never the default HIGH gate.
"""
from __future__ import annotations

from typing import Dict, List

import click

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

FAIL_ON_CHOICES = ["info", "low", "medium", "high", "critical"]


def exit_code_for(findings: List[Dict], fail_on: str) -> int:
    """Return 1 if any finding's severity >= the fail_on threshold, else 0."""
    floor = SEVERITY_ORDER[fail_on.upper()]
    for f in findings:
        rank = SEVERITY_ORDER.get((f.get("severity") or "INFO").upper(), 0)
        if rank >= floor:
            return 1
    return 0


def add_fail_on_arg(func):
    """Attach the shared --fail-on option to a Click command.

    Default 'high': only HIGH/CRITICAL findings fail CI. Use 'info' to fail on
    any finding (the pre-v0.8 behaviour); 'critical' to fail on CRITICAL only.
    """
    return click.option(
        "--fail-on",
        type=click.Choice(FAIL_ON_CHOICES),
        default="high",
        show_default=True,
        help="Minimum finding severity that makes the command exit non-zero.",
    )(func)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_cli_fail_on.py -v`
Expected: PASS (7 passed)

- [ ] **Step 5: Wire the gate into the three local subcommands**

In `gitexpose/cli_advanced.py`, add the import near the top-level imports (alongside the existing `from .agent_exposure ...` style imports at module scope; place it with the other `from .` imports):

```python
from .cli_gating import add_fail_on_arg, exit_code_for
```

Apply the decorator and thread the parameter into each of the three commands. For **`supply-chain`** (currently `@add_verify_args` at line ~855, signature ends `..., no_verify_banner: bool):`):

```python
@add_verify_args
@add_fail_on_arg
def supply_chain(path: str, output: str, out_file: str, offline: bool,
                 osv_timeout: float, osv_max: int, verify: bool,
                 verify_concurrency: int, verify_timeout: float,
                 verify_only_severity: str, no_verify_banner: bool,
                 fail_on: str):
```

Replace its final line `sys.exit(1 if findings else 0)` (line ~1017) with:

```python
    sys.exit(exit_code_for(findings, fail_on))
```

For **`agent-audit`** (def at line ~1026, signature `def agent_audit(path: str, output: str, out_file: str, max_bytes: int):`):

```python
@cli.command("agent-audit")
@click.argument("path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option("-o", "--output", type=click.Choice(["console", "json", "sarif"]), default="console")
@click.option("--out-file", type=click.Path(), help="Write output to file instead of stdout")
@click.option("--max-bytes", type=int, default=1024 * 1024, metavar="N",
              help="Per-file size cap (default 1 MB).")
@add_fail_on_arg
def agent_audit(path: str, output: str, out_file: str, max_bytes: int, fail_on: str):
```

Replace its final `sys.exit(1 if findings else 0)` (line ~1069) with:

```python
    sys.exit(exit_code_for(findings, fail_on))
```

For **`git-history`** (def at line ~1080), add `@add_fail_on_arg` after `@add_verify_args`, add `fail_on: str` as the final parameter, and replace its final `sys.exit(1 if findings else 0)` (line ~1148) with:

```python
    sys.exit(exit_code_for(findings, fail_on))
```

- [ ] **Step 6: Write the CLI integration test**

```python
# append to tests/test_cli_fail_on.py
from click.testing import CliRunner
from gitexpose.cli_advanced import cli


def test_agent_audit_default_high_gate_passes_on_low(tmp_path):
    # A repo with no HIGH+ agent findings exits 0 under default --fail-on high.
    (tmp_path / "README.md").write_text("# nothing sensitive here\n")
    res = CliRunner().invoke(cli, ["agent-audit", str(tmp_path)])
    assert res.exit_code == 0


def test_agent_audit_fail_on_info_is_stricter(tmp_path):
    # Same repo, --fail-on info still exits 0 because there are zero findings.
    (tmp_path / "README.md").write_text("# nothing\n")
    res = CliRunner().invoke(cli, ["agent-audit", str(tmp_path), "--fail-on", "info"])
    assert res.exit_code == 0
```

- [ ] **Step 7: Run the full gating test + a quick smoke of the three commands' --help**

Run: `python -m pytest tests/test_cli_fail_on.py -v`
Expected: PASS (9 passed)

Run: `python -m gitexpose.cli_advanced supply-chain --help | grep -- --fail-on && python -m gitexpose.cli_advanced agent-audit --help | grep -- --fail-on`
Expected: both print a `--fail-on [info|low|medium|high|critical]` line.

- [ ] **Step 8: Commit**

```bash
git add gitexpose/cli_gating.py gitexpose/cli_advanced.py tests/test_cli_fail_on.py
git commit -m "feat(v0.8): --fail-on severity exit gate (default high) across local subcommands"
```

---

## Task 2: Git-metadata credential spine

**Files:**
- Create: `gitexpose/advanced/git_config_scanner.py`
- Modify: `gitexpose/advanced/local_fs_scanner.py` (call the scanner once per scan)
- Test: `tests/test_git_config_scanner.py`
- Fixtures: `tests/fixtures/git_meta_v08/` (created inside the test via `tmp_path`, no committed fixture files needed)

Three finding types from structural INI parsing — **never invoke git** (CVE-2025-41390).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_git_config_scanner.py
"""Git-metadata credential scanner: structural configparser, never shells out to git."""
import base64
from pathlib import Path

from gitexpose.advanced.git_config_scanner import scan


def _write_git_config(root: Path, body: str) -> None:
    (root / ".git").mkdir(parents=True, exist_ok=True)
    (root / ".git" / "config").write_text(body)


def test_remote_url_with_ghp_token(tmp_path):
    _write_git_config(tmp_path, (
        '[remote "origin"]\n'
        '\turl = https://ghp_AbCdEf0123456789AbCdEf0123456789AbCd@github.com/o/r.git\n'
    ))
    out = scan(tmp_path)
    types = {f["type"] for f in out}
    assert "git_config_credential_url" in types
    f = next(f for f in out if f["type"] == "git_config_credential_url")
    assert f["severity"] == "CRITICAL"
    assert "ghp_" not in f["description"]  # token value must be masked in description
    assert f["attack_class"] and f["atlas_technique"]


def test_remote_url_clean_has_no_finding(tmp_path):
    _write_git_config(tmp_path, '[remote "origin"]\n\turl = https://github.com/o/r.git\n')
    assert scan(tmp_path) == []


def test_extraheader_basic_auth_base64(tmp_path):
    pat = "x:" + "g" * 52  # ":" + Azure DevOps PAT shape
    b64 = base64.b64encode(pat.encode()).decode()
    _write_git_config(tmp_path, (
        '[http "https://dev.azure.com/org"]\n'
        f'\textraHeader = AUTHORIZATION: Basic {b64}\n'
    ))
    out = scan(tmp_path)
    assert any(f["type"] == "git_config_extraheader_credential" for f in out)


def test_extraheader_garbage_base64_does_not_crash(tmp_path):
    _write_git_config(tmp_path, (
        '[http "https://dev.azure.com/org"]\n'
        '\textraHeader = AUTHORIZATION: Basic !!!not-base64!!!\n'
    ))
    # Must not raise; may or may not emit, but never crashes.
    scan(tmp_path)


def test_gitmodules_token_url_flagged_as_committed(tmp_path):
    (tmp_path / ".gitmodules").write_text(
        '[submodule "lib"]\n'
        '\tpath = lib\n'
        '\turl = https://glpat-AbCdEf0123456789AbCd@gitlab.com/o/lib.git\n'
    )
    out = scan(tmp_path)
    f = next(f for f in out if f["type"] == "gitmodules_credential_url")
    assert f["committed_to_history"] is True


def test_generic_userpass_url_is_low_confidence(tmp_path):
    _write_git_config(tmp_path, (
        '[remote "origin"]\n'
        '\turl = https://alice:s3cr3tpassword@gitea.example.com/o/r.git\n'
    ))
    out = scan(tmp_path)
    f = next(f for f in out if f["type"] == "git_config_generic_token_url")
    assert f["severity"] in ("LOW", "INFO")


def test_no_git_subprocess_on_malicious_fsmonitor(tmp_path, monkeypatch):
    # CVE-2025-41390: a malicious core.fsmonitor must never be executed.
    # Guard: if any subprocess is spawned during scan, fail loudly.
    import subprocess
    def _boom(*a, **k):
        raise AssertionError("scan() invoked a subprocess — CVE-2025-41390 risk")
    monkeypatch.setattr(subprocess, "run", _boom)
    monkeypatch.setattr(subprocess, "Popen", _boom)
    monkeypatch.setattr(subprocess, "check_output", _boom)
    _write_git_config(tmp_path, (
        "[core]\n\tfsmonitor = \"touch /tmp/pwned\"\n"
        '[remote "origin"]\n'
        '\turl = https://ghp_AbCdEf0123456789AbCdEf0123456789AbCd@github.com/o/r.git\n'
    ))
    out = scan(tmp_path)  # must complete with no subprocess
    assert any(f["type"] == "git_config_credential_url" for f in out)


def test_missing_git_dir_returns_empty(tmp_path):
    assert scan(tmp_path) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_git_config_scanner.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'gitexpose.advanced.git_config_scanner'`

- [ ] **Step 3: Write minimal implementation**

```python
# gitexpose/advanced/git_config_scanner.py
"""Structural git-metadata credential scanner.

Parses .git/config and .gitmodules with configparser ONLY — never invokes git
(CVE-2025-41390: a malicious core.fsmonitor in .git/config yields RCE when any
tool runs a git subprocess in the directory). Emits finding-dicts in the shared
shape so reporters and the cluster post-processor handle them uniformly.

Finding types:
  - git_config_credential_url        token in [remote] url=         (CRITICAL)
  - git_config_extraheader_credential Azure DevOps Basic header      (HIGH)
  - gitmodules_credential_url         token in [submodule] url=      (CRITICAL)
  - git_config_generic_token_url      user:pass@host, no known prefix (LOW)
"""
from __future__ import annotations

import base64
import binascii
import configparser
import re
from pathlib import Path
from typing import Dict, List, Optional

_OWASP = "LLM06"
_ATLAS = "AML.T0012"

# Provider token prefixes with high discriminability (low FP).
_PREFIX_RE = re.compile(r"(ghp_|github_pat_|ghs_|glpat-|hf_)[A-Za-z0-9_\-]{8,}")
# user:password@host — credential-bearing URL with no recognised prefix.
_USERPASS_RE = re.compile(r"https?://[^/\s:@]+:[^/\s@]+@[^/\s]+")


def _mask(token: str) -> str:
    if len(token) <= 8:
        return token[:2] + "*" * (len(token) - 2)
    return token[:4] + "*" * (len(token) - 8) + token[-4:]


def _read(path: Path) -> Optional[configparser.ConfigParser]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error:
        return None
    return parser


def _classify_url(url: str) -> Optional[Dict]:
    """Return (partial) finding fields for a credential-bearing URL, or None."""
    m = _PREFIX_RE.search(url)
    if m:
        return {
            "severity": "CRITICAL",
            "_token": m.group(0),
            "_generic": False,
        }
    m = _USERPASS_RE.search(url)
    if m:
        return {
            "severity": "LOW",
            "_token": m.group(0).split("@")[0].split("//")[-1],
            "_generic": True,
        }
    return None


def _finding(ftype: str, severity: str, source: str, description: str,
             committed: bool = False) -> Dict:
    f = {
        "type": ftype,
        "severity": severity,
        "source": source,
        "description": description,
        "attack_class": _OWASP,
        "atlas_technique": _ATLAS,
    }
    if committed:
        f["committed_to_history"] = True
    return f


def _scan_remote_like(parser, source: str, *, submodule: bool) -> List[Dict]:
    out: List[Dict] = []
    for section in parser.sections():
        if not parser.has_option(section, "url"):
            continue
        url = parser.get(section, "url")
        cls = _classify_url(url)
        if cls is None:
            continue
        masked = _mask(cls["_token"])
        if submodule:
            out.append(_finding(
                "gitmodules_credential_url", cls["severity"], source,
                f"Submodule {section} embeds a credential-bearing URL ({masked}@...).",
                committed=True,
            ))
        elif cls["_generic"]:
            out.append(_finding(
                "git_config_generic_token_url", "LOW", source,
                f"Remote {section} URL contains user:password credentials "
                f"({masked}@...). Generic form — verify manually.",
            ))
        else:
            out.append(_finding(
                "git_config_credential_url", "CRITICAL", source,
                f"Remote {section} URL embeds an access token ({masked}). "
                "Token persists in git metadata across clone/package operations.",
            ))
    return out


def _scan_extraheader(parser, source: str) -> List[Dict]:
    out: List[Dict] = []
    for section in parser.sections():
        if not parser.has_option(section, "extraheader"):
            continue
        value = parser.get(section, "extraheader")
        m = re.search(r"Basic\s+([A-Za-z0-9+/=]+)", value, re.IGNORECASE)
        if not m:
            continue
        try:
            decoded = base64.b64decode(m.group(1), validate=True).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        # Azure DevOps PATs are stored as ":<pat>"; any decoded non-empty secret counts.
        secret = decoded.split(":", 1)[-1].strip()
        if len(secret) >= 8:
            out.append(_finding(
                "git_config_extraheader_credential", "HIGH", source,
                f"{section} stores a Basic-auth credential in http.extraHeader "
                f"({_mask(secret)}). Common Azure DevOps PAT vector.",
            ))
    return out


def scan(root) -> List[Dict]:
    root = Path(root)
    out: List[Dict] = []

    git_config = root / ".git" / "config"
    if git_config.is_file():
        parser = _read(git_config)
        if parser is not None:
            out.extend(_scan_remote_like(parser, ".git/config", submodule=False))
            out.extend(_scan_extraheader(parser, ".git/config"))

    gitmodules = root / ".gitmodules"
    if gitmodules.is_file():
        parser = _read(gitmodules)
        if parser is not None:
            out.extend(_scan_remote_like(parser, ".gitmodules", submodule=True))
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_git_config_scanner.py -v`
Expected: PASS (8 passed)

- [ ] **Step 5: Wire into LocalFilesystemScanner**

In `gitexpose/advanced/local_fs_scanner.py`, add the import near the other `from .` imports (after the `from . import skill_security` line at ~line 16):

```python
from .git_config_scanner import scan as scan_git_metadata
```

In `LocalFilesystemScanner.scan` (the method at line ~49), insert the call after the per-file loop but **before** the `cluster_process` return (replace the existing final two lines):

```python
        # v0.8 — structural git-metadata credential scan (once per root, never via git)
        findings.extend(scan_git_metadata(root))
        # v0.2 — cluster post-processor adds blast-radius findings
        from .credential_cluster import process as cluster_process
        return cluster_process(findings)
```

- [ ] **Step 6: Write the integration test**

```python
# append to tests/test_git_config_scanner.py
from gitexpose.advanced.local_fs_scanner import LocalFilesystemScanner


def test_local_fs_scanner_surfaces_git_metadata(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text(
        '[remote "origin"]\n'
        '\turl = https://ghp_AbCdEf0123456789AbCdEf0123456789AbCd@github.com/o/r.git\n'
    )
    findings = LocalFilesystemScanner().scan(tmp_path)
    assert any(f["type"] == "git_config_credential_url" for f in findings)
```

- [ ] **Step 7: Run both test files**

Run: `python -m pytest tests/test_git_config_scanner.py tests/test_local_fs_scanner.py -v`
Expected: PASS (all)

- [ ] **Step 8: Commit**

```bash
git add gitexpose/advanced/git_config_scanner.py gitexpose/advanced/local_fs_scanner.py tests/test_git_config_scanner.py
git commit -m "feat(v0.8): git-metadata credential spine (config/extraHeader/gitmodules), CVE-2025-41390-safe"
```

---

## Task 3: Agent debug-print AST detector

**Files:**
- Create: `gitexpose/agent_exposure/debug_print.py`
- Modify: `gitexpose/agent_exposure/scan.py` (add the detector to the merged scan)
- Test: `tests/test_agent_debug_print.py`

Detect `print(...)` / `logging.*(...)` whose arguments reference credential-named **variables** (not string literals). Pure stdlib `ast`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_agent_debug_print.py
"""Agent debug-print AST detector: flags print/logging of credential-named vars."""
from pathlib import Path

from gitexpose.agent_exposure.debug_print import scan


def _py(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body)
    return p


def test_print_of_api_key_var_is_flagged(tmp_path):
    _py(tmp_path, "skill.py", "api_key = get_key()\nprint(api_key)\n")
    out = scan(tmp_path)
    assert any(f["type"] == "agent_skill_credential_print" for f in out)
    assert out[0]["severity"] == "HIGH"


def test_fstring_with_credential_var_is_flagged(tmp_path):
    _py(tmp_path, "tool.py", 'token = "x"\nprint(f"using {token}")\n')
    out = scan(tmp_path)
    assert any(f["type"] == "agent_skill_credential_print" for f in out)


def test_logging_info_of_secret_is_flagged(tmp_path):
    _py(tmp_path, "agent.py", "import logging\nclient_secret = s()\nlogging.info(client_secret)\n")
    out = scan(tmp_path)
    assert any(f["type"] == "agent_skill_credential_print" for f in out)


def test_string_literal_mentioning_api_key_is_not_flagged(tmp_path):
    _py(tmp_path, "skill.py", 'print("api_key is configured")\n')
    assert scan(tmp_path) == []


def test_print_of_unrelated_var_is_not_flagged(tmp_path):
    _py(tmp_path, "skill.py", "count = 3\nprint(count)\n")
    assert scan(tmp_path) == []


def test_malformed_python_does_not_crash(tmp_path):
    _py(tmp_path, "broken.py", "def (:\n  print(api_key\n")
    assert scan(tmp_path) == []  # no crash, no finding


def test_non_python_files_ignored(tmp_path):
    (tmp_path / "notes.md").write_text("print(api_key)\n")
    assert scan(tmp_path) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_agent_debug_print.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'gitexpose.agent_exposure.debug_print'`

- [ ] **Step 3: Write minimal implementation**

```python
# gitexpose/agent_exposure/debug_print.py
"""AST detector for credential-bearing debug prints in agent/skill/tool Python.

Walks Python files, finds print()/logging.<level>() calls whose arguments
reference a variable whose NAME looks like a credential (api_key, token,
secret, bearer, password, client_secret, access_key, ...). String literals that
merely mention those words do NOT fire — only NAME/ATTRIBUTE references and the
embedded expressions of f-strings count. One bad file never aborts the scan.

Backed by arXiv:2604.03070 (73.5% of agent-skill credential leaks are stdout
broadcasts). Finding type: agent_skill_credential_print (HIGH, OWASP LLM06 /
ATLAS AML.T0019).
"""
from __future__ import annotations

import ast
import logging
import re
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)

_SKIP_DIRS = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv"})
_MAX_BYTES = 1 * 1024 * 1024

_CRED_NAME_RE = re.compile(
    r"(api[_-]?key|apikey|access[_-]?key|secret|client[_-]?secret|"
    r"token|bearer|password|passwd|credential|private[_-]?key)",
    re.IGNORECASE,
)

_LOGGING_LEVELS = frozenset({"debug", "info", "warning", "warn", "error",
                             "critical", "exception", "log"})


def _is_print_or_logging(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Name) and func.id == "print":
        return True
    if isinstance(func, ast.Attribute) and func.attr in _LOGGING_LEVELS:
        return True
    return False


def _names_in(node: ast.AST):
    """Yield identifier strings for Name/Attribute references inside an arg,
    including the embedded expressions of an f-string (JoinedStr)."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            yield sub.id
        elif isinstance(sub, ast.Attribute):
            yield sub.attr


def _credential_ref_in_call(call: ast.Call) -> bool:
    for arg in call.args:
        for ident in _names_in(arg):
            if _CRED_NAME_RE.search(ident):
                return True
    return False


def _scan_source(text: str, source: str) -> List[Dict]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    out: List[Dict] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_print_or_logging(node) \
                and _credential_ref_in_call(node):
            out.append({
                "type": "agent_skill_credential_print",
                "severity": "HIGH",
                "source": source,
                "line": getattr(node, "lineno", 1),
                "description": (
                    "Debug print/log broadcasts a credential-named variable to "
                    "stdout/logs — leaks the secret into the agent's context window "
                    "and log sinks on every invocation."
                ),
                "attack_class": "LLM06",
                "atlas_technique": "AML.T0019",
            })
    return out


def scan(root) -> List[Dict]:
    root = Path(root)
    out: List[Dict] = []
    for path in root.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        try:
            out.extend(_scan_source(text, str(path.relative_to(root))))
        except Exception as exc:  # noqa: BLE001 — one bad file never aborts
            logger.debug("debug_print: failed on %s: %s", path, exc)
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_agent_debug_print.py -v`
Expected: PASS (7 passed)

- [ ] **Step 5: Wire into agent_exposure.scan**

In `gitexpose/agent_exposure/scan.py`, add the import after the existing `from .system_prompt import ...` line (~line 15):

```python
from . import debug_print
```

In the `scan(path)` function (line ~55), add the detector call between the two existing `findings.extend(...)` lines:

```python
def scan(path) -> List[Dict]:
    root = Path(path)
    findings: List[Dict] = []
    findings.extend(analyze_configs(root))
    findings.extend(debug_print.scan(root))
    findings.extend(_scan_system_prompts(root, _load_default_fingerprints()))
    findings.sort(key=_sort_key, reverse=True)
    return findings
```

- [ ] **Step 6: Write the integration test**

```python
# append to tests/test_agent_debug_print.py
from gitexpose.agent_exposure import scan as agent_scan


def test_agent_scan_includes_debug_print(tmp_path):
    (tmp_path / "skill.py").write_text("api_key = k()\nprint(api_key)\n")
    findings = agent_scan(tmp_path)
    assert any(f["type"] == "agent_skill_credential_print" for f in findings)
```

- [ ] **Step 7: Run tests**

Run: `python -m pytest tests/test_agent_debug_print.py tests/test_agent_analyzer.py -v`
Expected: PASS (all)

- [ ] **Step 8: Commit**

```bash
git add gitexpose/agent_exposure/debug_print.py gitexpose/agent_exposure/scan.py tests/test_agent_debug_print.py
git commit -m "feat(v0.8): agent debug-print AST detector (agent_skill_credential_print)"
```

---

## Task 4: MCP security score (decoupled score/severity)

**Files:**
- Create: `gitexpose/agent_exposure/mcp_score.py`
- Modify: `gitexpose/agent_exposure/analyzer.py` (parse MCP servers structurally and emit posture findings)
- Test: `tests/test_mcp_score.py`

Per-issue findings (honest severities) + one INFO `mcp_server_posture` summary carrying the 0-100 score and its breakdown. Score informs; severity gates.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_mcp_score.py
"""MCP security score: per-issue findings + INFO posture summary; score != severity."""
from gitexpose.agent_exposure.mcp_score import score_server


def test_clean_known_https_oauth_server_scores_high():
    server = {
        "name": "stripe",
        "url": "https://mcp.stripe.com",
        "version": "1.2.3",
        "auth": "oauth",
        "env": {},
    }
    findings = score_server(server, "mcp.json")
    summary = next(f for f in findings if f["type"] == "mcp_server_posture")
    assert summary["severity"] == "INFO"
    assert summary["score"] >= 90
    # No HIGH per-issue findings for a clean server.
    assert all(f["severity"] != "HIGH" for f in findings if f["type"] != "mcp_server_posture")


def test_static_credential_is_high_and_deducts_30():
    server = {
        "name": "custom",
        "url": "https://mcp.example.com",
        "version": "1.0.0",
        "env": {"API_KEY": "sk_live_abc"},
    }
    findings = score_server(server, "mcp.json")
    issue = next(f for f in findings if f["type"] == "mcp_static_credential")
    assert issue["severity"] == "HIGH"
    summary = next(f for f in findings if f["type"] == "mcp_server_posture")
    assert summary["score"] <= 70


def test_plaintext_http_is_high():
    server = {"name": "x", "url": "http://mcp.example.com", "version": "1.0.0"}
    findings = score_server(server, "mcp.json")
    assert any(f["type"] == "mcp_plaintext_http" and f["severity"] == "HIGH"
               for f in findings)


def test_unknown_origin_is_low():
    server = {"name": "x", "url": "https://totally-unknown.example", "version": "1.0.0"}
    findings = score_server(server, "mcp.json")
    issue = next(f for f in findings if f["type"] == "mcp_unknown_origin")
    assert issue["severity"] == "LOW"


def test_unpinned_version_is_low():
    server = {"name": "stripe", "url": "https://mcp.stripe.com"}  # no version
    findings = score_server(server, "mcp.json")
    assert any(f["type"] == "mcp_unpinned_version" and f["severity"] == "LOW"
               for f in findings)


def test_posture_summary_lists_deductions_in_description():
    server = {"name": "x", "url": "https://unknown.example"}  # unknown + no pin
    findings = score_server(server, "mcp.json")
    summary = next(f for f in findings if f["type"] == "mcp_server_posture")
    assert "unknown origin" in summary["description"].lower()
    assert str(summary["score"]) in summary["description"]
    assert 0 <= summary["score"] <= 100
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_mcp_score.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'gitexpose.agent_exposure.mcp_score'`

- [ ] **Step 3: Write minimal implementation**

```python
# gitexpose/agent_exposure/mcp_score.py
"""MCP server security posture scoring (0-100).

Decoupled design: per-issue findings carry honest, gating severities; a separate
INFO `mcp_server_posture` summary carries the 0-100 score and its deduction
breakdown. The score informs humans; the per-issue severities gate CI. No other
scanner produces a quantified MCP posture score.
"""
from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urlparse

_OWASP = "OWASP LLM08 Excessive Agency"
_ATLAS = "AML.T0053"

# Minimal seed registry of known-legitimate MCP server origins. Grows over time.
KNOWN_MCP_SERVERS = frozenset({
    "mcp.anthropic.com",
    "mcp.stripe.com",
    "api.github.com",
    "mcp.github.com",
    "huggingface.co",
    "hf.co",
})

_SECRET_VALUE_RE = re.compile(
    r"(sk_live_|sk-|ghp_|glpat-|hf_|AKIA|xox[baprs]-)|"
    r"(_KEY|_TOKEN|_SECRET|PASSWORD|APIKEY)",
    re.IGNORECASE,
)


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _issue(ftype: str, severity: str, source: str, server_name: str,
           description: str) -> Dict:
    return {
        "type": ftype,
        "severity": severity,
        "source": source,
        "mcp_server": server_name,
        "description": description,
        "attack_class": _OWASP,
        "atlas_technique": _ATLAS,
    }


def score_server(server: Dict, source: str) -> List[Dict]:
    """Score one parsed MCP server. Returns per-issue findings + INFO summary."""
    name = server.get("name") or "(unnamed)"
    url = server.get("url") or ""
    host = _host(url)
    env = server.get("env") or {}
    auth = (server.get("auth") or "").lower()
    version = server.get("version")

    score = 100
    reasons: List[str] = []
    out: List[Dict] = []

    # Static credential in env (—30, HIGH)
    has_static_cred = any(
        _SECRET_VALUE_RE.search(str(k)) or _SECRET_VALUE_RE.search(str(v))
        for k, v in env.items()
    ) and auth != "oauth"
    if has_static_cred:
        score -= 30
        reasons.append("-30 static credential")
        out.append(_issue(
            "mcp_static_credential", "HIGH", source, name,
            f"MCP server '{name}' embeds a static credential in its env block.",
        ))

    # Plaintext HTTP (—20, HIGH)
    if url.startswith("http://"):
        score -= 20
        reasons.append("-20 plaintext http")
        out.append(_issue(
            "mcp_plaintext_http", "HIGH", source, name,
            f"MCP server '{name}' uses plaintext http:// — credentials and traffic "
            "are exposed in transit.",
        ))

    # Unknown origin (—15, LOW)
    if host and host not in KNOWN_MCP_SERVERS:
        score -= 15
        reasons.append("-15 unknown origin")
        out.append(_issue(
            "mcp_unknown_origin", "LOW", source, name,
            f"MCP server '{name}' origin ({host}) is not in the known-good registry.",
        ))

    # No version pin (—5, LOW)
    if not version:
        score -= 5
        reasons.append("-5 no version pin")
        out.append(_issue(
            "mcp_unpinned_version", "LOW", source, name,
            f"MCP server '{name}' has no pinned version — supply-chain drift risk.",
        ))

    # Bonuses (affect score only, never gating)
    if host in KNOWN_MCP_SERVERS:
        score = min(100, score + 20)
        reasons.append("+20 known vendor")
    if auth == "oauth":
        score = min(100, score + 15)
        reasons.append("+15 oauth")

    score = max(0, min(100, score))
    breakdown = "; ".join(reasons) if reasons else "no deductions"
    out.append({
        "type": "mcp_server_posture",
        "severity": "INFO",
        "source": source,
        "mcp_server": name,
        "score": score,
        "description": f"MCP server '{name}' posture score {score}/100 ({breakdown}).",
        "attack_class": _OWASP,
        "atlas_technique": _ATLAS,
    })
    return out


def parse_servers(data: Dict, source: str) -> List[Dict]:
    """Normalise an mcpServers object into a list of server dicts for scoring."""
    servers = (data or {}).get("mcpServers") or {}
    if not isinstance(servers, dict):
        return []
    out: List[Dict] = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        out.append({
            "name": name,
            "url": cfg.get("url") or cfg.get("serverUrl") or "",
            "version": cfg.get("version"),
            "auth": cfg.get("auth") or cfg.get("type") or "",
            "env": cfg.get("env") if isinstance(cfg.get("env"), dict) else {},
        })
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_mcp_score.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Wire into analyze_configs**

In `gitexpose/agent_exposure/analyzer.py`, add the import after `from .models import CapabilityClass, Grant` (~line 17):

```python
from . import mcp_score
```

The MCP score needs the parsed JSON. The cleanest seam: in `analyze_configs`, after a file's `grants` are computed but within the same `try`, if the file is MCP-shaped JSON, parse and score it. Add this helper near the top of `analyzer.py` (after the `_REC` constant):

```python
import json as _json
_MCP_BASENAMES = ("mcp.json", ".mcp.json", "claude_desktop_config.json")


def _maybe_score_mcp(content: str, rel: str, tail: str) -> List[Dict]:
    if tail not in _MCP_BASENAMES:
        return []
    try:
        data = _json.loads(content)
    except (ValueError, TypeError):
        return []
    out: List[Dict] = []
    for server in mcp_score.parse_servers(data, rel):
        out.extend(mcp_score.score_server(server, rel))
    return out
```

Then add the scoring call inside the per-file loop. In `analyze_configs`, `content` is assigned at line ~86 inside the `try:` block, and the `for grant in grants:` loop (line ~97) runs after it in that same scope. Add the scoring call right after the `for grant in grants:` loop body closes — `content`, `rel`, and `tail` are all in scope there:

```python
        for grant in grants:
            classes = classify(grant)
            if not classes:
                continue
            findings.append(_finding(grant, classes))
            classes_by_source.setdefault(rel, set()).update(classes)

        # v0.8 — MCP posture scoring (per-server findings + INFO summary)
        findings.extend(_maybe_score_mcp(content, rel, tail))
```

- [ ] **Step 6: Write the integration test**

```python
# append to tests/test_mcp_score.py
import json
from gitexpose.agent_exposure.analyzer import analyze_configs


def test_analyze_configs_emits_mcp_posture(tmp_path):
    (tmp_path / "mcp.json").write_text(json.dumps({
        "mcpServers": {
            "weird": {"url": "http://unknown.example", "env": {"API_KEY": "sk_live_x"}}
        }
    }))
    findings = analyze_configs(tmp_path)
    types = {f["type"] for f in findings}
    assert "mcp_server_posture" in types
    assert "mcp_static_credential" in types
    assert "mcp_plaintext_http" in types
```

- [ ] **Step 7: Run tests**

Run: `python -m pytest tests/test_mcp_score.py tests/test_agent_analyzer.py tests/test_agent_adapter_mcp.py -v`
Expected: PASS (all)

- [ ] **Step 8: Commit**

```bash
git add gitexpose/agent_exposure/mcp_score.py gitexpose/agent_exposure/analyzer.py tests/test_mcp_score.py
git commit -m "feat(v0.8): MCP security score (0-100) with decoupled per-issue findings + INFO posture summary"
```

---

## Task 5: Orphan cross-source signal + SARIF fingerprints

**Files:**
- Create: `gitexpose/advanced/secret_registry.py`
- Modify: `gitexpose/advanced/credential_cluster.py` (enrichment pass), `gitexpose/advanced/local_fs_scanner.py` (thread `track`/`registry_path`), `gitexpose/cli_advanced.py` (`--track`/`--registry` flags)
- Modify: `gitexpose/agent_exposure/sarif.py` (emit `partialFingerprints`)
- Test: `tests/test_secret_registry.py`

Enrichment mutates each secret finding with `source_frequency` + `secret_value_hash`. Registry stores **hashes only**, opt-in via `--track`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_secret_registry.py
"""Cross-source orphan signal: hash-only registry, frequency bands, no raw values."""
import json
from pathlib import Path

from gitexpose.advanced.secret_registry import (
    SecretRegistry, frequency_band, KNOWN_EXAMPLE_KEYS, enrich,
)


def test_frequency_bands():
    assert frequency_band(1) == "orphan_candidate"
    assert frequency_band(3) == "low"
    assert frequency_band(10) == "moderate"
    assert frequency_band(40) == "high"
    assert frequency_band(99) == "replicated"


def test_registry_stores_only_hashes(tmp_path):
    reg_path = tmp_path / "registry.json"
    reg = SecretRegistry(reg_path)
    reg.observe("AKIAREALSECRETVALUE123", "repo-a")
    reg.save()
    raw = reg_path.read_text()
    assert "AKIAREALSECRETVALUE123" not in raw  # raw value never persisted
    data = json.loads(raw)
    assert all(len(k) == 64 for k in data)      # sha256 hex keys only


def test_observe_counts_distinct_sources(tmp_path):
    reg = SecretRegistry(tmp_path / "r.json")
    assert reg.observe("secretX", "repo-a") == 1
    assert reg.observe("secretX", "repo-a") == 1   # same source not double counted
    assert reg.observe("secretX", "repo-b") == 2


def test_known_example_key_is_downgraded():
    findings = [{"type": "aws_access_key", "value_full": "AKIAIOSFODNN7EXAMPLE",
                 "severity": "HIGH", "source": "demo.py"}]
    enrich(findings, registry=None)
    assert findings[0]["severity"] == "INFO"
    assert findings[0]["source_frequency"] == "known_example"


def test_enrich_without_registry_still_tags_hash():
    findings = [{"type": "github_token", "value_full": "ghp_realtokenvalue000",
                 "severity": "HIGH", "source": "a.py"}]
    enrich(findings, registry=None)
    assert len(findings[0]["secret_value_hash"]) == 64
    # No registry → no frequency band assertion, but hash is always present.


def test_enrich_with_registry_tags_orphan(tmp_path):
    reg = SecretRegistry(tmp_path / "r.json")
    findings = [{"type": "github_token", "value_full": "ghp_uniqueonce999",
                 "severity": "HIGH", "source": "a.py"}]
    enrich(findings, registry=reg)
    assert findings[0]["source_frequency"] == "orphan_candidate"


def test_non_secret_findings_are_untouched():
    findings = [{"type": "unpinned_ai_middleware", "severity": "LOW", "source": "req.txt"}]
    enrich(findings, registry=None)
    assert "secret_value_hash" not in findings[0]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_secret_registry.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'gitexpose.advanced.secret_registry'`

- [ ] **Step 3: Write minimal implementation**

```python
# gitexpose/advanced/secret_registry.py
"""Cross-source secret frequency registry + orphan-signal enrichment.

A secret seen in exactly one source is statistically more likely a private
accidental leak; a secret seen across many sources is likely a scraped public
example. We tag each secret finding with a `source_frequency` band and a
`secret_value_hash` (SHA256 of the normalised value). The registry persists
HASHES ONLY — never raw secret values. Frequency is a triage hint, not a verdict.

The hash also feeds SARIF `partialFingerprints["secretValueHash/v1"]`, enabling
cross-tool deduplication (e.g. running alongside TruffleHog).
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import unquote

logger = logging.getLogger(__name__)

# Well-known placeholder/example credentials → downgrade to INFO.
KNOWN_EXAMPLE_KEYS = frozenset({
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "AIzaSyDUMMYKEYDUMMYKEYDUMMYKEYDUMMYKEY1",
})


def normalize(value: str) -> str:
    """Normalise a secret for hashing: strip + URL-decode, preserve case."""
    return unquote((value or "").strip())


def secret_hash(value: str) -> str:
    return hashlib.sha256(normalize(value).encode("utf-8")).hexdigest()


def frequency_band(count: int) -> str:
    if count <= 1:
        return "orphan_candidate"
    if count <= 5:
        return "low"
    if count <= 15:
        return "moderate"
    if count <= 50:
        return "high"
    return "replicated"


# Token substrings that mark a finding-dict as a credential (mirrors cluster logic).
_SECRET_TYPE_TOKENS = (
    "_api_key", "_token", "_pat", "_webhook", "_key", "_sid", "_password",
    "_url", "private_key", "jwt_token",
)


def _is_secret_finding(f: Dict) -> bool:
    if f.get("value_full") or f.get("secret"):
        return True
    t = f.get("type", "") or ""
    return any(tok in t for tok in _SECRET_TYPE_TOKENS)


def _raw_value(f: Dict) -> Optional[str]:
    return f.get("value_full") or f.get("secret")


class SecretRegistry:
    """Persistent SHA256 -> sorted list of distinct source labels. Hashes only."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._data: Dict[str, List[str]] = {}
        if self.path.is_file():
            try:
                self._data = json.loads(self.path.read_text())
            except (OSError, ValueError):
                self._data = {}

    def observe(self, value: str, source: str) -> int:
        """Record (hash, source); return the distinct-source count for this secret."""
        h = secret_hash(value)
        sources = self._data.setdefault(h, [])
        if source not in sources:
            sources.append(source)
            sources.sort()
        return len(sources)

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._data, indent=0))
        except OSError as exc:
            logger.warning("secret_registry: could not save %s: %s", self.path, exc)


def enrich(findings: List[Dict], registry: Optional[SecretRegistry]) -> None:
    """Mutate secret findings in-place: add secret_value_hash + source_frequency.

    With a registry, source_frequency reflects cross-source observation count.
    Without one, only the hash is added (still feeds SARIF fingerprints).
    Known example keys are downgraded to INFO regardless of registry.
    """
    for f in findings:
        if not _is_secret_finding(f):
            continue
        raw = _raw_value(f)
        if raw is None:
            continue
        f["secret_value_hash"] = secret_hash(raw)
        if normalize(raw) in KNOWN_EXAMPLE_KEYS:
            f["severity"] = "INFO"
            f["source_frequency"] = "known_example"
            continue
        if registry is not None:
            count = registry.observe(raw, f.get("source") or "unknown")
            f["source_frequency"] = frequency_band(count)
    if registry is not None:
        registry.save()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_secret_registry.py -v`
Expected: PASS (8 passed)

- [ ] **Step 5: Thread enrichment through credential_cluster + local_fs_scanner**

In `gitexpose/advanced/credential_cluster.py`, change the `process` signature and add the enrichment call at the start. Replace the `def process(findings: List[Dict]) -> List[Dict]:` line and the first line of its body:

```python
def process(findings: List[Dict], registry=None) -> List[Dict]:
    """Return original findings plus any cluster/multi-provider findings.

    Before clustering, enrich secret findings with secret_value_hash and (when a
    registry is supplied) source_frequency. Enrichment mutates findings in place.
    """
    from .secret_registry import enrich
    enrich(findings, registry)
    by_source: Dict[str, List[Dict]] = defaultdict(list)
```

In `gitexpose/advanced/local_fs_scanner.py`, change `scan` to accept and pass registry options. Update the method signature (line ~49) and the final return:

```python
    def scan(self, root: Path, track: bool = False, registry_path=None) -> List[Dict]:
        root = Path(root)
        findings: List[Dict] = []
        for path in self._iter_files(root):
            try:
                if path.stat().st_size > self.max_bytes:
                    continue
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                logger.debug("Skipping unreadable file %s: %s", path, exc)
                continue
            relative = str(path.relative_to(root))
            findings.extend(skill_security.detect_polyglot(path))
            if "\x00" in content[:1024]:
                continue
            findings.extend(self._scan_content(content, relative, path.name))
        # v0.8 — structural git-metadata credential scan (once per root, never via git)
        findings.extend(scan_git_metadata(root))
        # v0.8 — opt-in cross-source registry for orphan signal
        registry = None
        if track:
            from pathlib import Path as _Path
            from .secret_registry import SecretRegistry
            default = _Path.home() / ".gitexpose" / "registry.json"
            registry = SecretRegistry(_Path(registry_path) if registry_path else default)
        # v0.2 — cluster post-processor adds blast-radius findings (+ v0.8 enrichment)
        from .credential_cluster import process as cluster_process
        return cluster_process(findings, registry=registry)
```

- [ ] **Step 6: Add `--track` / `--registry` flags to supply-chain**

In `gitexpose/cli_advanced.py`, add two options to the `supply-chain` command decorator stack (after the `--osv-max` option, before `@add_verify_args`):

```python
@click.option("--track", is_flag=True, default=False,
              help="Record secret hashes in a cross-source registry for orphan signal (opt-in).")
@click.option("--registry", "registry_path", type=click.Path(), default=None,
              help="Registry file path (default ~/.gitexpose/registry.json). Implies --track.")
```

Add `track: bool, registry_path: str` to the `supply_chain` signature (after `fail_on: str` from Task 1), and change the scanner call (line ~864) from:

```python
    scanner = LocalFilesystemScanner()
    findings = scanner.scan(Path(path))
```

to:

```python
    scanner = LocalFilesystemScanner()
    findings = scanner.scan(Path(path), track=track or bool(registry_path),
                            registry_path=registry_path)
```

- [ ] **Step 7: Emit partialFingerprints in SARIF**

In `gitexpose/agent_exposure/sarif.py`, in the `to_sarif` loop where each result dict is built (the `results.append({...})` at line ~53), add a `partialFingerprints` key when the finding carries a hash. Insert immediately before `results.append(`:

```python
        result_obj = {
            "ruleId": rid,
            "level": level,
            "message": {"text": f.get("description") or f.get("type", "finding")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("source") or "unknown"},
                    "region": {"startLine": f.get("line", 1)},
                }
            }],
            "taxa": [{"toolComponent": {"name": _TAXONOMY_NAME}, "id": tid}
                     for tid in compliance.values()],
            "properties": result_props,
        }
        if f.get("secret_value_hash"):
            result_obj["partialFingerprints"] = {
                "secretValueHash/v1": f["secret_value_hash"]
            }
        if f.get("source_frequency"):
            result_obj["properties"]["source_frequency"] = f["source_frequency"]
        results.append(result_obj)
```

(Delete the old `results.append({...})` block that followed.)

- [ ] **Step 8: Write the SARIF + integration tests**

```python
# append to tests/test_secret_registry.py
import json as _json
from gitexpose.agent_exposure.sarif import to_sarif


def test_sarif_emits_partial_fingerprint():
    findings = [{
        "type": "github_token", "severity": "HIGH", "source": "a.py",
        "description": "leak", "secret_value_hash": "a" * 64,
        "source_frequency": "orphan_candidate",
    }]
    doc = _json.loads(to_sarif(findings, "0.8.0"))
    result = doc["runs"][0]["results"][0]
    assert result["partialFingerprints"]["secretValueHash/v1"] == "a" * 64
    assert result["properties"]["source_frequency"] == "orphan_candidate"


def test_supply_chain_scan_tracks_when_enabled(tmp_path):
    from gitexpose.advanced.local_fs_scanner import LocalFilesystemScanner
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.py").write_text('github_token = "ghp_' + "a" * 36 + '"\n')
    reg = tmp_path / "reg.json"
    findings = LocalFilesystemScanner().scan(repo, track=True, registry_path=str(reg))
    assert reg.is_file()
    secret = next((f for f in findings if f.get("secret_value_hash")), None)
    assert secret is not None
    assert secret["source_frequency"] == "orphan_candidate"
```

- [ ] **Step 9: Run tests**

Run: `python -m pytest tests/test_secret_registry.py tests/test_credential_cluster.py tests/test_local_fs_scanner.py tests/test_agent_sarif.py -v`
Expected: PASS (all)

- [ ] **Step 10: Commit**

```bash
git add gitexpose/advanced/secret_registry.py gitexpose/advanced/credential_cluster.py gitexpose/advanced/local_fs_scanner.py gitexpose/cli_advanced.py gitexpose/agent_exposure/sarif.py tests/test_secret_registry.py
git commit -m "feat(v0.8): orphan cross-source signal + SARIF partialFingerprints (runs-alongside dedup)"
```

---

## Task 6: SARIF output for `supply-chain`

**Files:**
- Modify: `gitexpose/cli_advanced.py` (`supply-chain` `--output` choices + sarif branch)
- Test: `tests/test_supply_chain_sarif.py`

The orphan signal's headline (cross-tool dedup) is only reachable if `supply-chain` can emit SARIF. Reuse the existing `to_sarif` emitter.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_supply_chain_sarif.py
"""supply-chain --output sarif emits valid SARIF carrying fingerprints."""
import json
from click.testing import CliRunner

from gitexpose.cli_advanced import cli


def test_supply_chain_sarif_output(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.py").write_text('aws_access_key = "AKIA' + "A" * 16 + '"\n')
    res = CliRunner().invoke(
        cli, ["supply-chain", str(repo), "--output", "sarif", "--offline"]
    )
    # exit code may be 0/1 depending on severity gate; output must be valid SARIF.
    payload = res.stdout.strip()
    doc = json.loads(payload)
    assert doc["version"] == "2.1.0"
    assert "runs" in doc
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_supply_chain_sarif.py -v`
Expected: FAIL — Click errors that `sarif` is not a valid `--output` choice (non-zero exit, no JSON).

- [ ] **Step 3: Add sarif to the choices and an output branch**

In `gitexpose/cli_advanced.py`, change the `supply-chain` `--output` option (line ~846):

```python
@click.option("-o", "--output", type=click.Choice(["console", "json", "cyclonedx", "aibom", "sarif"]),
              default="console")
```

In the output-formatting block (the `if output in ("cyclonedx", "aibom"):` chain at line ~952), add a `sarif` branch before the `elif output == "json":`:

```python
    if output in ("cyclonedx", "aibom"):
        from .reporters.cyclonedx_reporter import build_bom
        text = build_bom(_v05_deps, findings)
    elif output == "sarif":
        from .agent_exposure.sarif import to_sarif
        text = to_sarif(findings, __version__)
    elif output == "json":
```

`__version__` is already imported in `cli_advanced.py` (line 26: `from . import __version__`) and already used by the `agent-audit` sarif branch — no import change needed.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_supply_chain_sarif.py -v`
Expected: PASS

- [ ] **Step 5: Validate against the SARIF schema fixture**

```python
# append to tests/test_supply_chain_sarif.py
def test_supply_chain_sarif_has_runs_and_tool(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text('github_token = "ghp_' + "b" * 36 + '"\n')
    res = CliRunner().invoke(
        cli, ["supply-chain", str(repo), "--output", "sarif", "--offline", "--track",
              "--registry", str(tmp_path / "r.json")]
    )
    doc = json.loads(res.stdout)
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "GitExpose"
    # the tracked secret should carry a partial fingerprint
    fps = [r.get("partialFingerprints", {}) for r in run["results"]]
    assert any("secretValueHash/v1" in fp for fp in fps)
```

- [ ] **Step 6: Run tests**

Run: `python -m pytest tests/test_supply_chain_sarif.py -v`
Expected: PASS (2 passed)

- [ ] **Step 7: Commit**

```bash
git add gitexpose/cli_advanced.py tests/test_supply_chain_sarif.py
git commit -m "feat(v0.8): supply-chain --output sarif (carries orphan-signal fingerprints)"
```

---

## Task 7: Release — version, docs, smoke, full suite

**Files:**
- Modify: `gitexpose/__init__.py` (version → 0.8.0), `pyproject.toml`, `requirements.txt` (verify), `CHANGELOG.md`, `README.md`, `docs/COVERAGE.md`
- Create: `docs/planning/v0.8-notes.md`, `tests/fixtures/agent_repo_v08/` smoke fixture, `tests/test_v08_smoke.py`

- [ ] **Step 1: Bump version (synced across files)**

In `gitexpose/__init__.py` line 32: `__version__ = "0.8.0"`.
In `pyproject.toml`: set `version = "0.8.0"` (find the `[project]` `version =` line).

Run: `grep -rn "0\.7\.0" pyproject.toml gitexpose/__init__.py`
Expected: no remaining matches (all now 0.8.0). If `setup.py` carries a version, update it too.

- [ ] **Step 2: Verify requirements.txt (the v0.7 CI lesson)**

The four features use stdlib only (`configparser`, `ast`, `hashlib`, `base64`, `json`, `urllib`). No new runtime dependency is introduced.

Run: `python -c "import configparser, ast, hashlib, base64, json, urllib.parse; print('stdlib ok')"`
Expected: `stdlib ok`

Confirm no new third-party import was added: `grep -rn "^import \|^from " gitexpose/advanced/git_config_scanner.py gitexpose/advanced/secret_registry.py gitexpose/agent_exposure/debug_print.py gitexpose/agent_exposure/mcp_score.py gitexpose/cli_gating.py | grep -viE "from __future__|from \.|from typing|^.*import (ast|re|json|base64|binascii|hashlib|logging|configparser|click)( |$)|urllib"`
Expected: no output (no unexpected third-party imports). `requirements.txt` needs no change.

- [ ] **Step 3: Create the v0.8 smoke fixture**

```bash
mkdir -p tests/fixtures/agent_repo_v08/.git tests/fixtures/agent_repo_v08/skills
```

```ini
# tests/fixtures/agent_repo_v08/.git/config
[core]
	repositoryformatversion = 0
[remote "origin"]
	url = https://ghp_AbCdEf0123456789AbCdEf0123456789AbCd@github.com/acme/agent.git
```

```python
# tests/fixtures/agent_repo_v08/skills/leaky_skill.py
def run(api_key):
    print(api_key)  # debug-print credential leak
    return True
```

```json
{
  "mcpServers": {
    "shady": {
      "url": "http://mcp.unknown.example",
      "env": {"API_KEY": "sk_live_smoke_value"}
    }
  }
}
```
(Save the JSON above as `tests/fixtures/agent_repo_v08/mcp.json`.)

Note: `.git/` fixtures are normally gitignored — add a negation so the fixture is tracked (the v0.7 gitignore lesson). Append to `.gitignore`:

```
!tests/fixtures/agent_repo_v08/.git/config
```

- [ ] **Step 4: Write the smoke test**

```python
# tests/test_v08_smoke.py
"""v0.8 end-to-end smoke: all four features fire on the fixture repo."""
from pathlib import Path

from gitexpose.advanced.local_fs_scanner import LocalFilesystemScanner
from gitexpose.agent_exposure import scan as agent_scan

FIXTURE = Path(__file__).parent / "fixtures" / "agent_repo_v08"


def test_supply_chain_finds_git_metadata_and_orphan(tmp_path):
    findings = LocalFilesystemScanner().scan(
        FIXTURE, track=True, registry_path=str(tmp_path / "r.json")
    )
    types = {f["type"] for f in findings}
    assert "git_config_credential_url" in types
    # the ghp_ token in .git/config is a real secret-bearing finding with a hash
    assert any(f.get("secret_value_hash") for f in findings)


def test_agent_audit_finds_debug_print_and_mcp_posture():
    findings = agent_scan(FIXTURE)
    types = {f["type"] for f in findings}
    assert "agent_skill_credential_print" in types
    assert "mcp_server_posture" in types
    assert "mcp_static_credential" in types
    assert "mcp_plaintext_http" in types
```

- [ ] **Step 5: Run the smoke test**

Run: `python -m pytest tests/test_v08_smoke.py -v`
Expected: PASS (2 passed)

- [ ] **Step 6: Run the FULL suite**

Run: `python -m pytest -q`
Expected: all pass (prior 395 + the ~40 new v0.8 tests). If any pre-existing test asserts the old `sys.exit(1 if findings else 0)` behaviour for `agent-audit`/`supply-chain`/`git-history`, update it to the `--fail-on` contract (search: `grep -rn "exit_code == 1" tests/ | grep -iE "agent_audit|supply|git_history"`).

- [ ] **Step 7: Update docs**

- `CHANGELOG.md`: add a `## [0.8.0]` section listing the four features + the `--fail-on` **behavior change** (default `high`; use `--fail-on info` for the old "any finding fails" behavior) + the new `supply-chain --output sarif`.
- `README.md`: bump the version badge to 0.8.0; reframe the header/tagline to the AI-infra-layer positioning ("AI-infrastructure credential & exposure scanner — runs alongside TruffleHog/Gitleaks"); add a short "v0.8" bullet list; show one `supply-chain --output sarif --track` example.
- `docs/COVERAGE.md`: add the five+ new finding types (git_config_credential_url, git_config_extraheader_credential, gitmodules_credential_url, agent_skill_credential_print, mcp_* posture) with their OWASP/ATLAS tags.
- Create `docs/planning/v0.8-notes.md`: shipped features + the v0.9 backlog (hf-scan, Jupyter output cells, SafeTensors/PNG metadata, ml_dataset_context, --semantic, hf-monitor).

- [ ] **Step 8: Manual editable-install verification**

Run:
```bash
pip install -e . -q
gitexpose agent-audit tests/fixtures/agent_repo_v08
gitexpose supply-chain tests/fixtures/agent_repo_v08 --output sarif --offline --track --registry /tmp/gx-reg.json | python -m json.tool | head -30
```
Expected: agent-audit prints debug-print + MCP posture findings; supply-chain emits valid SARIF with a `secretValueHash/v1` fingerprint.

- [ ] **Step 9: Commit the release**

```bash
git add -A
git commit -m "release(v0.8): version bump, docs reframe, v0.8 smoke fixture + tests"
```

---

## Self-Review Notes (completed by plan author)

- **Spec coverage:** Feature 0 `--fail-on` → Task 1. ① git-metadata (3 types + generic) → Task 2. ② debug-print → Task 3. ③ MCP score (decoupled) → Task 4. ④ orphan signal + SARIF fingerprints → Task 5. supply-chain SARIF (needed for ④'s dedup story; gap found in §4 review) → Task 6. Version/docs/smoke/requirements-sync/v0.9-deferral → Task 7. CVE-2025-41390 no-subprocess test → Task 2 Step 1. No-raw-value persistence test → Task 5 Step 1.
- **Type consistency:** `scan(root) -> List[Dict]` for both new scanners; `score_server(server, source)` and `parse_servers(data, source)` used consistently; `process(findings, registry=None)`; `enrich(findings, registry)`; `exit_code_for(findings, fail_on)`; `LocalFilesystemScanner.scan(root, track=False, registry_path=None)`. Finding-dict keys (`type/severity/source/description/attack_class/atlas_technique/secret_value_hash/source_frequency`) match across tasks and the SARIF emitter.
- **No placeholders:** every code step shows complete code; every run step shows the command + expected result.
- **Deferred (v0.9, per spec §2.2):** hf-scan, Jupyter output cells, SafeTensors/PNG metadata, ml_dataset_context, --semantic, hf-monitor — intentionally out of plan.
