# GitExpose v0.7 "Agent Exposure, Deepened" Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the v0.6 agent-exposure engine with a function-calling tool-schema grant source (shape-sniffed from JSON/YAML, classified by tool name) and SARIF output for `agent-audit` (GitHub Code Scanning).

**Architecture:** Add a second "content adapter" dispatch mode (shape-based) to `agent_exposure/adapters/base.py` alongside v0.6's filename dispatch; a `function_calling` content adapter parses OpenAI/Anthropic `tools[]` and emits name-keyed `Grant`s through the unchanged capability engine. A focused `agent_exposure/sarif.py` serializes the plain finding-dicts to SARIF 2.1.0. PyYAML becomes a declared core dep (imported defensively).

**Tech Stack:** Python ≥3.9, `click`, stdlib `json`, `PyYAML` (new core dep, defensive import). Tests: `pytest`, `click.testing.CliRunner`. Run tests with `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/` (system Python, NOT `uv run`).

**Spec:** `docs/superpowers/specs/2026-05-31-agent-exposure-deepened-design.md`

---

## File Structure

**Create:**
- `gitexpose/agent_exposure/adapters/function_calling.py` — shape-sniff OpenAI/Anthropic `tools[]` → `Grant`s
- `gitexpose/agent_exposure/sarif.py` — `to_sarif(findings, tool_version)` → SARIF 2.1.0
- Tests: `tests/test_agent_adapter_function_calling.py`, `tests/test_agent_sarif.py`, `tests/test_smoke_v07.py`
- Fixture: `tests/fixtures/agent_repo_v07/agent_tools.json`

**Modify:**
- `gitexpose/agent_exposure/adapters/base.py` — add `CONTENT_ADAPTERS` + `_register_content` + `content_adapters`
- `gitexpose/agent_exposure/adapters/__init__.py` — import `function_calling`
- `gitexpose/agent_exposure/capabilities.py` — extend name-sets + add `_SECRET_NAMES`
- `gitexpose/agent_exposure/analyzer.py` — run content adapters on `.json/.yaml/.yml`
- `gitexpose/cli_advanced.py` — `agent-audit --output` gains `sarif`
- `tests/test_agent_audit_cli.py` — append SARIF CLI tests
- `pyproject.toml`, `setup.py` — add `PyYAML>=6.0` to core deps; version → `0.7.0`
- `gitexpose/__init__.py` — `__version__ = "0.7.0"`
- `README.md`, `docs/COVERAGE.md`, `CHANGELOG.md`, `docs/v0.7-planning-notes.md` — docs

---

## Task 1: Content-adapter dispatch mode (base.py)

**Files:**
- Modify: `gitexpose/agent_exposure/adapters/base.py`
- Test: `tests/test_agent_adapter_function_calling.py` (create)

- [ ] **Step 1: Write failing test in `tests/test_agent_adapter_function_calling.py`**

```python
"""Tests for the function-calling content adapter + content-adapter registry."""

from gitexpose.agent_exposure.adapters.base import (
    CONTENT_ADAPTERS, _register_content, content_adapters,
)
from gitexpose.agent_exposure.models import Grant


def test_content_adapter_registry_register_and_list():
    marker = lambda c, s: [Grant("t", "r", s)]  # noqa: E731
    _register_content(marker)
    assert marker in content_adapters()
    CONTENT_ADAPTERS.remove(marker)
```

- [ ] **Step 2: Run to verify failure**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_agent_adapter_function_calling.py -v`
Expected: FAIL (`CONTENT_ADAPTERS`/`_register_content`/`content_adapters` not found).

- [ ] **Step 3: Add the content-adapter registry to `gitexpose/agent_exposure/adapters/base.py`**

Append at the end of the file:

```python


# --- Content adapters (shape dispatch) -------------------------------------
# Unlike ADAPTERS (filename dispatch), a content adapter is offered the parsed
# text of every .json/.yaml/.yml file and decides for itself whether the content
# matches its shape (returns [] on non-match). Adding a v0.8 framework adapter =
# one new module that calls _register_content().

CONTENT_ADAPTERS: List[Adapter] = []


def _register_content(adapter: Adapter) -> None:
    CONTENT_ADAPTERS.append(adapter)


def content_adapters() -> List[Adapter]:
    return list(CONTENT_ADAPTERS)
```

> `List` and `Adapter` are already imported/defined at the top of `base.py` (from the v0.6 filename-dispatch code).

- [ ] **Step 4: Run test to verify pass**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_agent_adapter_function_calling.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add gitexpose/agent_exposure/adapters/base.py tests/test_agent_adapter_function_calling.py
git commit -m "feat(v0.7): content-adapter (shape dispatch) registry in adapters/base"
```

---

## Task 2: Capability name-set extension + `_SECRET_NAMES`

**Files:**
- Modify: `gitexpose/agent_exposure/capabilities.py`
- Test: `tests/test_agent_capabilities.py` (append)

- [ ] **Step 1: Append failing tests to `tests/test_agent_capabilities.py`**

```python
def test_classify_function_tool_names():
    # function-calling tool names map to the taxonomy by NAME
    assert CapabilityClass.SHELL_EXEC in classify(_g("run_shell", 'tools[].name="run_shell"'))
    assert CapabilityClass.CODE_EVAL not in classify(_g("run_shell", 'tools[].name="run_shell"'))
    assert CapabilityClass.NETWORK_FETCH in classify(_g("http_get", 'tools[].name="http_get"'))
    assert CapabilityClass.DATABASE in classify(_g("query_db", 'tools[].name="query_db"'))
    assert CapabilityClass.SECRET_ACCESS in classify(_g("read_secret", 'tools[].name="read_secret"'))


def test_classify_exec_code_tool_is_shell_exec():
    assert CapabilityClass.SHELL_EXEC in classify(_g("exec_code", 'tools[].name="exec_code"'))


def test_classify_benign_function_tool_empty():
    assert classify(_g("get_weather", 'tools[].name="get_weather"')) == set()
    assert classify(_g("calculator", 'tools[].name="calculator"')) == set()
```

> `_g` and `classify`/`CapabilityClass` are already imported in this test file (v0.6).

- [ ] **Step 2: Run to verify failure**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_agent_capabilities.py -k function -v`
Expected: FAIL (e.g. `run_shell`/`http_get`/`read_secret` not yet classified).

- [ ] **Step 3: Extend the name-sets in `gitexpose/agent_exposure/capabilities.py`**

Replace the name-set block:

```python
_SHELL = {"bash", "sh", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh",
          "shell", "terminal", "run_command", "execute_command", "run_shell_command"}
_NETWORK = {"webfetch", "fetch", "curl", "wget", "http", "https",
            "fetch_url", "browser_fetch", "web_request"}
_FS_WRITE = {"write", "edit", "multiedit", "write_file", "create_file",
             "delete_file", "fs_write", "filesystem"}
_DB = {"postgres", "postgresql", "mysql", "sqlite", "mongodb", "redis", "database", "sql"}
_BROWSER = {"playwright", "puppeteer", "browser", "selenium", "chromium"}
```

with (additive — existing entries kept, function-tool names added):

```python
_SHELL = {"bash", "sh", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh",
          "shell", "terminal", "run_command", "execute_command", "run_shell_command",
          "run_shell", "execute", "exec_code", "run_code", "code_interpreter", "python_exec"}
_NETWORK = {"webfetch", "fetch", "curl", "wget", "http", "https",
            "fetch_url", "browser_fetch", "web_request",
            "http_get", "http_post", "web_search", "browse", "search_web", "url_fetch"}
_FS_WRITE = {"write", "edit", "multiedit", "write_file", "create_file",
             "delete_file", "fs_write", "filesystem", "save_file", "put_file"}
_DB = {"postgres", "postgresql", "mysql", "sqlite", "mongodb", "redis", "database", "sql",
       "query_db", "run_query", "execute_sql"}
_BROWSER = {"playwright", "puppeteer", "browser", "selenium", "chromium"}
_SECRET_NAMES = {"read_secret", "get_secret", "read_env", "get_env",
                 "fetch_secret", "secrets_manager", "vault_read"}
```

- [ ] **Step 4: Add the `_SECRET_NAMES` check in `classify()`**

Change the secret line:

```python
    if _SECRET_RE.search(raw) or (_ENV_FILE_RE.search(raw) and "read" in tool):
        classes.add(CapabilityClass.SECRET_ACCESS)
```

to:

```python
    if base in _SECRET_NAMES or _SECRET_RE.search(raw) or (_ENV_FILE_RE.search(raw) and "read" in tool):
        classes.add(CapabilityClass.SECRET_ACCESS)
```

- [ ] **Step 5: Run tests to verify pass**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_agent_capabilities.py -v`
Expected: all PASS (new + v0.6).

- [ ] **Step 6: Commit**

```bash
git add gitexpose/agent_exposure/capabilities.py tests/test_agent_capabilities.py
git commit -m "feat(v0.7): extend capability name-sets for function-calling tools + _SECRET_NAMES"
```

---

## Task 3: Function-calling adapter

**Files:**
- Create: `gitexpose/agent_exposure/adapters/function_calling.py`
- Modify: `gitexpose/agent_exposure/adapters/__init__.py`
- Test: `tests/test_agent_adapter_function_calling.py` (append)

- [ ] **Step 1: Append failing tests to `tests/test_agent_adapter_function_calling.py`**

```python
from gitexpose.agent_exposure.adapters.function_calling import parse_function_calling
from gitexpose.agent_exposure.capabilities import classify
from gitexpose.agent_exposure.models import CapabilityClass


def test_openai_nested_shape():
    content = (
        '{"tools": [{"type": "function", "function": {"name": "run_shell",'
        ' "description": "run a shell command"}}]}'
    )
    grants = parse_function_calling(content, "agent.json")
    assert [g.tool for g in grants] == ["run_shell"]
    assert CapabilityClass.SHELL_EXEC in classify(grants[0])


def test_openai_flattened_shape():
    content = '[{"type": "function", "name": "http_get"}]'
    grants = parse_function_calling(content, "tools.json")
    assert [g.tool for g in grants] == ["http_get"]


def test_anthropic_shape():
    content = (
        '{"tools": [{"name": "query_db", "input_schema": {"type": "object"}}]}'
    )
    grants = parse_function_calling(content, "claude_tools.json")
    assert [g.tool for g in grants] == ["query_db"]


def test_benign_tools_no_dangerous_name():
    content = '{"tools": [{"type": "function", "function": {"name": "get_weather"}}]}'
    grants = parse_function_calling(content, "agent.json")
    assert [g.tool for g in grants] == ["get_weather"]      # emitted...
    assert classify(grants[0]) == set()                      # ...but benign -> no finding


def test_non_tool_json_no_match():
    # package.json-style JSON has no tool-schema shape
    content = '{"name": "my-pkg", "version": "1.0.0", "scripts": {"test": "jest"}}'
    assert parse_function_calling(content, "package.json") == []


def test_description_with_secret_does_not_trigger_secret_access():
    # FP guard: the free-form description is NOT placed in raw, so _SECRET_RE can't fire
    content = (
        '{"tools": [{"type": "function", "function": {"name": "get_weather",'
        ' "description": "needs OPENAI_API_KEY to call the weather API"}}]}'
    )
    grants = parse_function_calling(content, "agent.json")
    assert "API_KEY" not in grants[0].raw
    assert CapabilityClass.SECRET_ACCESS not in classify(grants[0])


def test_yaml_tools_shape():
    content = (
        "tools:\n"
        "  - type: function\n"
        "    function:\n"
        "      name: run_shell\n"
    )
    grants = parse_function_calling(content, "agent.yaml")
    assert [g.tool for g in grants] == ["run_shell"]


def test_malformed_returns_empty():
    assert parse_function_calling("{not json", "x.json") == []
    assert parse_function_calling(": : : not yaml : :", "x.yaml") == []
```

- [ ] **Step 2: Run to verify failure**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_agent_adapter_function_calling.py -v`
Expected: FAIL (`function_calling` module not found).

- [ ] **Step 3: Create `gitexpose/agent_exposure/adapters/function_calling.py`**

```python
"""Function-calling tool-schema content adapter.

Shape-sniffs OpenAI/Anthropic `tools[]` arrays in JSON/YAML and emits one Grant per
tool, keyed on the tool NAME (never the free-form description — so classify()'s
secret/eval regexes cannot fire on prose). A content adapter: offered every
.json/.yaml/.yml file by the analyzer; returns [] when the file is not a tool
schema (the precise-shape gate keeps false positives low).
"""

from __future__ import annotations

import json
from typing import List, Optional

from ..models import Grant
from .base import _register_content

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a declared dep; degrade if absent
    yaml = None


def _load(content: str):
    """Parse as JSON (stdlib) then YAML (if available). Return obj or None."""
    try:
        return json.loads(content)
    except ValueError:
        pass
    if yaml is not None:
        try:
            return yaml.safe_load(content)
        except Exception:  # noqa: BLE001 — any YAML parse error -> not a tool schema
            return None
    return None


def _candidate_arrays(obj):
    """Yield lists that might be tool arrays: a top-level list, or lists under the
    'tools'/'functions' keys (one level deep)."""
    if isinstance(obj, list):
        yield obj
    if isinstance(obj, dict):
        for key in ("tools", "functions"):
            val = obj.get(key)
            if isinstance(val, list):
                yield val


def _tool_name(item) -> Optional[str]:
    """Return the tool name iff the item matches an exact OpenAI/Anthropic shape."""
    if not isinstance(item, dict):
        return None
    # OpenAI nested: {"type":"function","function":{"name":N}}
    if item.get("type") == "function" and isinstance(item.get("function"), dict):
        name = item["function"].get("name")
        if isinstance(name, str) and name:
            return name
    # OpenAI flattened: {"type":"function","name":N}
    if item.get("type") == "function" and isinstance(item.get("name"), str) and item["name"]:
        return item["name"]
    # Anthropic: {"name":N,"input_schema":{...}}
    if isinstance(item.get("name"), str) and item["name"] and isinstance(item.get("input_schema"), dict):
        return item["name"]
    return None


def parse_function_calling(content: str, source_file: str) -> List[Grant]:
    obj = _load(content)
    if obj is None:
        return []
    out: List[Grant] = []
    for arr in _candidate_arrays(obj):
        names = [n for n in (_tool_name(it) for it in arr) if n]
        if not names:
            continue  # not a tool schema -> skip (FP guard)
        for name in names:
            out.append(Grant(
                tool=name,
                raw=f'tools[].name="{name}"',  # structured evidence ONLY (no description)
                source_file=source_file,
            ))
    return out


_register_content(parse_function_calling)
```

- [ ] **Step 4: Register the adapter in `gitexpose/agent_exposure/adapters/__init__.py`**

Add the `function_calling` import:

```python
"""Agent-config adapters. Importing the package registers every adapter."""

from . import base  # noqa: F401
from . import mcp  # noqa: F401  (registers mcp.json family)
from . import permissions  # noqa: F401  (registers .claude/settings.json family)
from . import function_calling  # noqa: F401  (registers the shape-sniff content adapter)

from .base import ADAPTERS, adapter_for

__all__ = ["ADAPTERS", "adapter_for"]
```

- [ ] **Step 5: Run tests to verify pass**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_agent_adapter_function_calling.py -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add gitexpose/agent_exposure/adapters/function_calling.py gitexpose/agent_exposure/adapters/__init__.py tests/test_agent_adapter_function_calling.py
git commit -m "feat(v0.7): function-calling tool-schema content adapter (shape-sniff, name-keyed)"
```

---

## Task 4: Analyzer content-dispatch integration

**Files:**
- Modify: `gitexpose/agent_exposure/analyzer.py`
- Test: `tests/test_agent_analyzer.py` (append)

- [ ] **Step 1: Append failing tests to `tests/test_agent_analyzer.py`**

```python
def test_function_calling_schema_produces_finding(tmp_path):
    _write(tmp_path, "agent_tools.json",
           '{"tools": [{"type": "function", "function": {"name": "run_shell"}}]}')
    findings = analyze_configs(tmp_path)
    f = [x for x in findings if x["type"] == "excessive_agent_capability"]
    assert f and f[0]["capability_class"] == "shell_exec"
    assert f[0]["source"] == "agent_tools.json"


def test_function_calling_exfil_chain(tmp_path):
    # a tools schema with both an exec tool and a fetch tool -> exfil-chain CRITICAL
    _write(tmp_path, "tools.yaml",
           "tools:\n"
           "  - type: function\n"
           "    function: {name: run_shell}\n"
           "  - type: function\n"
           "    function: {name: http_get}\n")
    findings = analyze_configs(tmp_path)
    chained = [x for x in findings if x.get("exfil_chain")]
    assert chained and chained[0]["severity"] == "CRITICAL"
    assert set(chained[0]["exfil_chain"]) >= {"shell_exec", "network_fetch"}


def test_benign_tools_schema_no_finding(tmp_path):
    _write(tmp_path, "agent.json",
           '{"tools": [{"type": "function", "function": {"name": "get_weather"}}]}')
    assert analyze_configs(tmp_path) == []
```

> `_write` and `analyze_configs` are already in this test file (v0.6). The v0.6 test
> `test_unrelated_settings_json_not_parsed` must still pass — its fixture has no `tools[]`
> shape, so the content adapter returns `[]`.

- [ ] **Step 2: Run to verify failure**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_agent_analyzer.py -v`
Expected: the three new tests FAIL (content adapters not yet run by the analyzer).

- [ ] **Step 3: Rewrite the walk in `gitexpose/agent_exposure/analyzer.py`**

Update the imports at the top of the file:

```python
from .adapters.base import adapter_for
```

to:

```python
from .adapters.base import adapter_for, content_adapters
```

Add a content-extensions constant near `_SKIP_DIRS`/`_MAX_BYTES`:

```python
_CONTENT_EXTS = frozenset({".json", ".yaml", ".yml"})
```

Replace `_iter_config_files` and the `analyze_configs` loop. Delete the existing
`_iter_config_files` function entirely and replace `analyze_configs` with:

```python
def analyze_configs(root: Path) -> List[Dict]:
    root = Path(root)
    findings: List[Dict] = []
    # source_file -> set of capability classes seen (for exfil-chain escalation)
    classes_by_source: Dict[str, set] = {}

    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        rel = str(path.relative_to(root))
        tail = path.name

        fn_adapter = adapter_for(rel)
        # permission lists only count under a .claude/ directory (filename dispatch only)
        suppress_fn = (
            fn_adapter is not None
            and tail in ("settings.json", "settings.local.json")
            and ".claude" not in path.parts
        )
        is_content = path.suffix.lower() in _CONTENT_EXTS

        if (fn_adapter is None or suppress_fn) and not is_content:
            continue  # nothing dispatches to this file

        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            content = path.read_text(encoding="utf-8", errors="ignore")
            grants: List[Grant] = []
            if fn_adapter is not None and not suppress_fn:
                grants.extend(fn_adapter(content, rel))
            if is_content:
                for ca in content_adapters():
                    grants.extend(ca(content, rel))
        except Exception as exc:  # noqa: BLE001 — one bad file never aborts the scan
            logger.warning("agent-audit: failed to parse %s (%s)", rel, type(exc).__name__)
            continue

        for grant in grants:
            classes = classify(grant)
            if not classes:
                continue
            findings.append(_finding(grant, classes))
            classes_by_source.setdefault(rel, set()).update(classes)

    findings.extend(_exfil_chain_findings(classes_by_source))
    return findings
```

> `Grant` is already imported in `analyzer.py` (from `.models`). The package import
> `from . import adapters` at the top already triggers registration of the
> `function_calling` content adapter (Task 3 added it to the adapters `__init__`).

- [ ] **Step 4: Run tests to verify pass**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_agent_analyzer.py -v`
Expected: all PASS (3 new + all v0.6 analyzer tests, including `test_unrelated_settings_json_not_parsed`).

- [ ] **Step 5: Commit**

```bash
git add gitexpose/agent_exposure/analyzer.py tests/test_agent_analyzer.py
git commit -m "feat(v0.7): analyzer runs content adapters on json/yaml (function-calling grants)"
```

---

## Task 5: SARIF emitter

**Files:**
- Create: `gitexpose/agent_exposure/sarif.py`
- Test: `tests/test_agent_sarif.py` (create)

- [ ] **Step 1: Write failing tests in `tests/test_agent_sarif.py`**

```python
"""Tests for the agent-exposure SARIF 2.1.0 emitter."""

import json

from gitexpose.agent_exposure.sarif import to_sarif


_FINDINGS = [
    {
        "type": "excessive_agent_capability", "capability_class": "shell_exec",
        "severity": "CRITICAL", "source": ".cursor/mcp.json",
        "description": "Agent grant 'bash' grants arbitrary shell/command execution.",
        "attack_class": "OWASP LLM08 Excessive Agency",
        "atlas_technique": "AML.T0053", "mitre_attack": "T1059",
    },
    {
        "type": "exposed_system_prompt", "severity": "HIGH", "source": "p.txt",
        "description": "Matches a known-leaked system prompt.",
        "attack_class": "OWASP LLM07 System Prompt Leakage",
        "atlas_technique": "AML.T0056", "mitre_attack": "T1552.001",
    },
]


def test_to_sarif_is_valid_sarif_210():
    doc = json.loads(to_sarif(_FINDINGS, "0.7.0"))
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert doc["runs"][0]["tool"]["driver"]["name"] == "GitExpose"
    assert doc["runs"][0]["tool"]["driver"]["version"] == "0.7.0"


def test_severity_maps_to_level():
    doc = json.loads(to_sarif(_FINDINGS, "0.7.0"))
    levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    assert levels["excessive_agent_capability/shell_exec"] == "error"   # CRITICAL -> error
    assert levels["exposed_system_prompt"] == "error"                    # HIGH -> error


def test_rules_carry_compliance_ids():
    doc = json.loads(to_sarif(_FINDINGS, "0.7.0"))
    rules = {r["id"]: r for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    props = rules["excessive_agent_capability/shell_exec"]["properties"]
    assert props["mitre_attack"] == "T1059"
    assert props["atlas_technique"] == "AML.T0053"


def test_results_have_file_locations():
    doc = json.loads(to_sarif(_FINDINGS, "0.7.0"))
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in doc["runs"][0]["results"]}
    assert ".cursor/mcp.json" in uris


def test_clean_scan_emits_valid_empty_sarif():
    doc = json.loads(to_sarif([], "0.7.0"))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []


def test_missing_optional_keys_do_not_crash():
    doc = json.loads(to_sarif([{"type": "x", "severity": "LOW"}], "0.7.0"))
    assert doc["runs"][0]["results"][0]["level"] == "note"
```

- [ ] **Step 2: Run to verify failure**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_agent_sarif.py -v`
Expected: FAIL (`sarif` module not found).

- [ ] **Step 3: Create `gitexpose/agent_exposure/sarif.py`**

```python
"""SARIF 2.1.0 emitter for agent-exposure finding-dicts (GitHub Code Scanning).

Focused serializer for the plain finding dicts that `agent_exposure.scan()` returns.
The web reporters' SARIFReporter is coupled to the ScanReport model and is not reused;
this mirrors its structure (rules + results + compliance taxonomy refs) for dicts.
"""

from __future__ import annotations

import json
from typing import Dict, List

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/fevra-dev/GitExpose"
_TAXONOMY_NAME = "GitExpose-compliance"

_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
          "LOW": "note", "INFO": "note"}


def _rule_id(f: Dict) -> str:
    t = f.get("type", "finding")
    cls = f.get("capability_class")
    return f"{t}/{cls}" if cls else t


def to_sarif(findings: List[Dict], tool_version: str) -> str:
    rules: Dict[str, Dict] = {}
    results: List[Dict] = []
    taxa: Dict[str, Dict] = {}   # id -> taxon

    for f in findings:
        rid = _rule_id(f)
        compliance = {k: f[k] for k in ("attack_class", "atlas_technique", "mitre_attack")
                      if f.get(k)}
        for tid in compliance.values():
            taxa.setdefault(tid, {"id": tid})

        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rid.replace("/", "_"),
                "shortDescription": {"text": f.get("type", "finding")},
                "fullDescription": {"text": f.get("description", rid)},
                "helpUri": _INFO_URI,
                "properties": dict(compliance),
            }

        level = _LEVEL.get((f.get("severity") or "INFO").upper(), "note")
        result_props = {k: f[k] for k in ("severity", "capability_class", "attack_class",
                                          "atlas_technique", "mitre_attack", "exfil_chain")
                        if f.get(k) is not None}
        results.append({
            "ruleId": rid,
            "level": level,
            "message": {"text": f.get("description") or f.get("type", "finding")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("source") or "unknown"},
                    "region": {"startLine": 1},
                }
            }],
            "taxa": [{"toolComponent": {"name": _TAXONOMY_NAME}, "id": tid}
                     for tid in compliance.values()],
            "properties": result_props,
        })

    doc = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "GitExpose",
                "version": tool_version,
                "informationUri": _INFO_URI,
                "rules": list(rules.values()),
            }},
            "taxonomies": [{
                "name": _TAXONOMY_NAME,
                "shortDescription": {
                    "text": "OWASP LLM Top 10 / MITRE ATLAS / MITRE ATT&CK references"
                },
                "taxa": list(taxa.values()),
            }],
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)
```

- [ ] **Step 4: Run tests to verify pass**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_agent_sarif.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add gitexpose/agent_exposure/sarif.py tests/test_agent_sarif.py
git commit -m "feat(v0.7): SARIF 2.1.0 emitter for agent-exposure findings"
```

---

## Task 6: `agent-audit -o sarif` CLI wiring

**Files:**
- Modify: `gitexpose/cli_advanced.py`
- Test: `tests/test_agent_audit_cli.py` (append)

- [ ] **Step 1: Append failing tests to `tests/test_agent_audit_cli.py`**

```python
def test_agent_audit_sarif_output(tmp_path):
    _repo(tmp_path)
    result = CliRunner().invoke(cli, ["agent-audit", str(tmp_path), "-o", "sarif"])
    doc = json.loads(result.output)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "GitExpose"
    assert any(r["ruleId"].startswith("excessive_agent_capability")
               for r in doc["runs"][0]["results"])
    assert result.exit_code == 1   # findings => exit 1


def test_agent_audit_sarif_clean_dir(tmp_path):
    (tmp_path / "README.md").write_text("# hello")
    result = CliRunner().invoke(cli, ["agent-audit", str(tmp_path), "-o", "sarif"])
    doc = json.loads(result.output)
    assert doc["runs"][0]["results"] == []
    assert result.exit_code == 0
```

> `_repo`, `cli`, and `json` are already imported in this test file (v0.6).

- [ ] **Step 2: Run to verify failure**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_agent_audit_cli.py -k sarif -v`
Expected: FAIL (`sarif` not a valid `--output` choice → exit code 2).

- [ ] **Step 3: Extend the `agent-audit` command in `gitexpose/cli_advanced.py`**

Change the output option:

```python
@click.option("-o", "--output", type=click.Choice(["console", "json"]), default="console")
```

to:

```python
@click.option("-o", "--output", type=click.Choice(["console", "json", "sarif"]), default="console")
```

And add a `sarif` branch. Change:

```python
    if output == "json":
        import json as _json
        text = _json.dumps(findings, indent=2, default=str)
    else:
```

to:

```python
    if output == "json":
        import json as _json
        text = _json.dumps(findings, indent=2, default=str)
    elif output == "sarif":
        from .agent_exposure.sarif import to_sarif
        text = to_sarif(findings, __version__)
    else:
```

> `__version__` is already imported at the top of `cli_advanced.py` (added in v0.6.1).

- [ ] **Step 4: Run tests to verify pass**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_agent_audit_cli.py -v`
Expected: all PASS (new SARIF + v0.6 console/json).

- [ ] **Step 5: Commit**

```bash
git add gitexpose/cli_advanced.py tests/test_agent_audit_cli.py
git commit -m "feat(v0.7): agent-audit -o sarif (GitHub Code Scanning output)"
```

---

## Task 7: PyYAML core dep + version bump + docs

**Files:**
- Modify: `pyproject.toml`, `setup.py`, `gitexpose/__init__.py`, `README.md`, `docs/COVERAGE.md`, `CHANGELOG.md`
- Create: `docs/v0.7-planning-notes.md`

- [ ] **Step 1: Add PyYAML to core deps + bump version**

In `pyproject.toml`, add to the `dependencies` list:

```toml
    "PyYAML>=6.0",
```

and bump `version = "0.6.1"` → `version = "0.7.0"`.

In `setup.py`, add `"PyYAML>=6.0",` to the `install_requires` list (find the list that mirrors pyproject core deps; if `setup.py` has no `install_requires`, skip — `pyproject.toml` is authoritative).

In `gitexpose/__init__.py`: `__version__ = "0.6.1"` → `__version__ = "0.7.0"`.

- [ ] **Step 2: Add a `CHANGELOG.md` v0.7.0 section** (immediately under `# Changelog`)

```markdown
## v0.7.0 — 2026-05-31 — Agent Exposure, Deepened

### Added
- **Function-calling tool-schema detection** — `agent-audit` now flags over-permissioned function-calling tools (OpenAI/Anthropic `tools[]` arrays in JSON/YAML), shape-sniffed wherever they live and classified by tool **name** against the v0.6 capability taxonomy (`excessive_agent_capability`, OWASP LLM08). Low-FP: only the exact tool-schema shape matches, and free-form tool descriptions are never inspected.
- **SARIF 2.1.0 output for `agent-audit`** (`-o sarif`) — agent findings now upload to GitHub Code Scanning, carrying the OWASP/ATLAS/ATT&CK compliance triple as rule/result properties + taxonomy references.
- New content-adapter (shape dispatch) mode in the agent-exposure engine — v0.8 framework adapters (CrewAI/AutoGen/LangChain) drop in here.

### Changed
- `PyYAML>=6.0` is now a core dependency (enables YAML tool-schema sniffing; also fixes a previously-undeclared `import yaml` in `gitexpose/advanced/api_discovery.py`). The agent-exposure package imports it defensively, so `agent-audit` still runs (JSON-only) if PyYAML is somehow absent.
```

- [ ] **Step 3: Update `README.md`**

- Version badge → `0.7.0`.
- In the AI-agent-exposure feature row, note it now also covers **function-calling tool schemas** and **SARIF output**.
- Add an example near the other `agent-audit` examples:

```bash
# Emit SARIF for GitHub Code Scanning
gitexpose agent-audit ./repo -o sarif --out-file agent.sarif
```

- [ ] **Step 4: Update `docs/COVERAGE.md`** — in the "AI agent exposure (v0.6)" section, add function-calling tool schemas (OpenAI/Anthropic `tools[]`) as a covered grant source and SARIF as an `agent-audit` output format. Update the "Last updated" line to v0.7.

- [ ] **Step 5: Create `docs/v0.7-planning-notes.md`**

```markdown
# GitExpose v0.7 — Planning Notes

Shipped v0.7.0 "Agent Exposure, Deepened": function-calling tool-schema adapter (shape-sniffed
OpenAI/Anthropic `tools[]`, name-classified, low-FP) + SARIF output for `agent-audit`. New
content-adapter dispatch mode; PyYAML now a core dep.

## v0.8 backlog
- CrewAI / AutoGen / LangChain framework-grant content adapters.
- Heuristic (non-fingerprint) system-prompt detection; free-form tool-description danger inference.
- SARIF for supply-chain / git-history findings (unify Code Scanning across all commands).
- Retrofit `mitre_attack` onto existing v0.2–v0.5 findings (secret-scan → T1552, supply-chain → T1195).
- Lazy `advanced/__init__` import so a bare `pip install gitexpose` runs supply-chain/agent-audit.
- Grow the CL4R1T4S seed fingerprint set.
- Carried from v0.5: classic typosquatting, lock-file poisoning checks, Shai-Hulud behavioral analysis, Go/Cargo SCA, policy engine, --verify on web-scan path, AI canary tokens.
```

- [ ] **Step 6: Run the full suite, then commit**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/ -q`
Expected: all green.

```bash
git add pyproject.toml setup.py gitexpose/__init__.py README.md docs/COVERAGE.md CHANGELOG.md docs/v0.7-planning-notes.md
git commit -m "docs(v0.7): PyYAML core dep + bump to 0.7.0; README + COVERAGE + CHANGELOG + v0.8 notes"
```

---

## Task 8: v0.7 smoke test + full suite

**Files:**
- Create: `tests/fixtures/agent_repo_v07/agent_tools.json`, `tests/test_smoke_v07.py`

- [ ] **Step 1: Create the fixture `tests/fixtures/agent_repo_v07/agent_tools.json`**

```json
{"tools": [{"type": "function", "function": {"name": "run_shell", "description": "run a command"}}, {"type": "function", "function": {"name": "http_get", "description": "fetch a url"}}, {"type": "function", "function": {"name": "get_weather", "description": "weather lookup"}}]}
```

- [ ] **Step 2: Write smoke test `tests/test_smoke_v07.py`**

```python
"""v0.7 smoke: agent-audit detects an over-permissioned function-calling tool schema."""

import json
from pathlib import Path

from click.testing import CliRunner

from gitexpose.cli_advanced import cli

FIX = Path(__file__).parent / "fixtures" / "agent_repo_v07"


def test_smoke_v07_function_calling_json():
    result = CliRunner().invoke(cli, ["agent-audit", str(FIX), "-o", "json"])
    findings = json.loads(result.output)
    # run_shell -> shell_exec CRITICAL
    assert any(f.get("capability_class") == "shell_exec" and f["severity"] == "CRITICAL"
               for f in findings)
    # run_shell + http_get in one schema -> exfil-chain escalation
    assert any(f.get("exfil_chain") for f in findings)
    assert result.exit_code == 1


def test_smoke_v07_sarif_valid():
    result = CliRunner().invoke(cli, ["agent-audit", str(FIX), "-o", "sarif"])
    doc = json.loads(result.output)
    assert doc["version"] == "2.1.0"
    assert any(r["ruleId"].startswith("excessive_agent_capability")
               for r in doc["runs"][0]["results"])
```

- [ ] **Step 3: Run the smoke test**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_smoke_v07.py -v`
Expected: PASS.

- [ ] **Step 4: Check the fixture isn't gitignored**

Run: `git check-ignore tests/fixtures/agent_repo_v07/agent_tools.json && echo IGNORED || echo ok`
If `IGNORED`: add a negation to `.gitignore` (after the existing `agent_repo_v06` negation):
```
!tests/fixtures/agent_repo_v07/
!tests/fixtures/agent_repo_v07/**
```
and `git add -f tests/fixtures/agent_repo_v07/`.

- [ ] **Step 5: Run the FULL suite (no regressions)**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/ -q`
Expected: all green (370 prior + the new v0.7 tests).

- [ ] **Step 6: Commit**

```bash
git add tests/test_smoke_v07.py tests/fixtures/agent_repo_v07/ .gitignore
git commit -m "test(v0.7): function-calling + SARIF smoke + fixture"
```

---

## Task 9: Manual verification (pre-release gate)

> Manual maintainer step before tagging — same gated pattern as v0.5.1/v0.6.0/v0.6.1. Editable install so the real `gitexpose` binary is exercised.

- [ ] **Step 1: Editable install into a scratch venv**

```bash
/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m venv /tmp/ge-07-venv
/tmp/ge-07-venv/bin/pip install -q -e '.[advanced]'
```

- [ ] **Step 2: Verify function-calling detection + SARIF over a tools schema**

```bash
mkdir -p /tmp/ge-07
printf '%s' '{"tools":[{"type":"function","function":{"name":"run_shell"}},{"type":"function","function":{"name":"http_get"}}]}' > /tmp/ge-07/agent_tools.json
/tmp/ge-07-venv/bin/gitexpose --version                                   # expect 0.7.0
/tmp/ge-07-venv/bin/gitexpose agent-audit /tmp/ge-07 -o console           # expect CRITICAL shell_exec + exfil chain, exit 1
/tmp/ge-07-venv/bin/gitexpose agent-audit /tmp/ge-07 -o sarif | python3 -c "import sys,json; d=json.load(sys.stdin); print('SARIF', d['version'], len(d['runs'][0]['results']), 'results')"
```
Expected: `--version` → 0.7.0; console shows a CRITICAL `shell_exec` finding + an exfil-chain finding; SARIF parses as `2.1.0` with ≥1 result.

- [ ] **Step 3: Confirm a benign tools file is silent + clean dir**

```bash
printf '%s' '{"tools":[{"type":"function","function":{"name":"get_weather"}}]}' > /tmp/ge-07/benign.json
rm /tmp/ge-07/agent_tools.json
/tmp/ge-07-venv/bin/gitexpose agent-audit /tmp/ge-07            # expect no findings, exit 0
rm -rf /tmp/ge-07 /tmp/ge-07-venv
```

- [ ] **Step 4: If green, ship** — merge `v0.7` → `main`, tag `v0.7.0`, push `main` + `v0.7` + the tag via `git push origin refs/tags/v0.7.0`, let the Release workflow build wheel+sdist, then `gh release edit v0.7.0 --notes-file …`. Confirm CI + the self-scan workflow stay green.

---

## Self-Review (completed during planning)

**1. Spec coverage** — every spec section maps to a task:
- §2/§3 content-adapter dispatch mode → Task 1; function-calling adapter → Task 3; name-set extension + `_SECRET_NAMES` → Task 2; analyzer integration → Task 4; SARIF → Tasks 5 (emitter) + 6 (CLI); PyYAML core dep → Task 7.
- §4 adapter shape detection (OpenAI nested/flattened, Anthropic) + name-keyed grants + no-prose-in-raw → Task 3 (tests cover all shapes + the description-secret FP guard).
- §5 SARIF structure (rules, results, level mapping, taxonomies/taxa, compliance properties, empty-on-clean) → Task 5.
- §6 PyYAML declared core + defensive import → Task 7 (declare) + Task 3 (`try/except ImportError`).
- §7 data flow (filename + content dispatch, `.claude` guard only suppresses the filename adapter) → Task 4.
- §8 error handling (unparseable → [], shape non-match → [], per-file isolation, size cap, yaml-absent degrade) → Tasks 3, 4.
- §9 testing → every task's tests + Task 8 smoke.
- §10 docs/release → Tasks 7, 9.
- §11 v0.8 backlog → Task 7 (`docs/v0.7-planning-notes.md`).

**2. Placeholder scan** — no TBD/TODO; every code step shows complete code or an exact old→new edit. The `setup.py` step has a conditional ("if no `install_requires`, skip — pyproject is authoritative") because pyproject is the build source of truth; this is a concrete instruction, not a placeholder.

**3. Type/name consistency** — `parse_function_calling(content, source_file) -> List[Grant]` matches Task 3 def, the adapters `__init__` import, and the analyzer's `content_adapters()` call (Task 4). `Grant(tool, raw, source_file)` used identically. `_register_content`/`content_adapters`/`CONTENT_ADAPTERS` consistent across Tasks 1, 3, 4. `_SECRET_NAMES` defined and used in Task 2's `classify()`. `to_sarif(findings, tool_version)` matches Task 5 def, the SARIF tests, and the CLI call in Task 6. `_CONTENT_EXTS` defined and used in Task 4. The renamed `analyze_configs` keeps the same signature (`(root) -> List[Dict]`) so `scan.py` (unchanged) still calls it correctly.

**Behavior-preservation note:** Task 4 deletes `_iter_config_files` and inlines its `.claude/`-guard logic into `analyze_configs`. The v0.6 `test_unrelated_settings_json_not_parsed` still passes because a `settings.json` outside `.claude/` has `suppress_fn=True` (no filename grants) and its `{"permissions":...}` content has no `tools[]` shape (content adapter returns `[]`).
