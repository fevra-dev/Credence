# GitExpose v0.7 — "Agent Exposure, Deepened" Design

> Brainstormed 2026-05-31. Extends the v0.6 agent-exposure engine to a new grant source —
> function-calling **tool schemas** (OpenAI/Anthropic `tools[]`), discovered by SHAPE rather than
> filename and classified by tool NAME (low-FP) — and adds **SARIF output** for `agent-audit` so
> agent findings flow into GitHub Code Scanning. Reuses the v0.6 capability taxonomy and finding-dict
> convention unchanged.

## 1. Motivation

v0.6 shipped the agent-exposure engine over two config families (MCP server configs, Claude-Code
permission lists) and built a deliberately **pluggable adapter architecture** so new grant sources
are additive. v0.7 exercises that architecture: agents increasingly declare their capabilities as
**function-calling tool schemas** (the OpenAI/Anthropic `tools` array) committed to repos — the same
"what tools an agent has permission to use" surface that motivated v0.6, but expressed as a tool
schema rather than an MCP/permission config. v0.6 deferred this for FP reasons ("inferring danger
from free-form descriptions"); v0.7 takes it on with a **name-based, shape-gated** approach that
keeps false positives low.

Second, `agent-audit` currently emits only console/json. Adding **SARIF 2.1.0** output lets agent
findings upload to GitHub Code Scanning — closing the gap surfaced in v0.6.1 (the local-scan commands
had no SARIF path).

This is the agent-side continuation of the capability-jump cadence (v0.3 Verification → v0.4 Depth →
v0.5 Supply-Chain → v0.6 Agent Exposure → **v0.7 Agent Exposure, Deepened**).

## 2. Scope

### In scope (v0.7)
- **Function-calling tool-schema adapter** — a new *content adapter* (shape dispatch) that shape-sniffs
  `.json/.yaml/.yml` files for OpenAI/Anthropic `tools[]` arrays and emits `Grant`s classified by tool
  **name** against the existing taxonomy. New `excessive_agent_capability` findings (same shape as v0.6).
- **Content-adapter dispatch mode** in `adapters/base.py` (`CONTENT_ADAPTERS`) alongside v0.6's
  filename dispatch (`ADAPTERS`), so v0.8 framework adapters are additive here too.
- **Extended capability name-sets** in `capabilities.py` for common function-tool naming
  (`run_shell`/`exec_code`/`fetch`/`read_file`/`query_db`/`read_secret`/…).
- **SARIF 2.1.0 output for `agent-audit`** — new `agent_exposure/sarif.py`; `agent-audit -o sarif`.
- **PyYAML declared as a core dependency** (enables YAML shape-sniffing; also fixes a latent
  undeclared `import yaml` in `advanced/api_discovery.py`).

### Out of scope (deferred to v0.8 — additive via the content-adapter interface)
- CrewAI / AutoGen / LangChain framework-grant adapters (per-framework, brittle).
- Heuristic ("looks-like-a-system-prompt") detection and free-form tool-**description** danger inference (higher FP).
- SARIF for `supply-chain`/`git-history` findings (those use a different finding pipeline).
- Retrofitting `mitre_attack` onto v0.2–v0.5 findings.
- Lazy `advanced/__init__` dependency cleanup.

### Deliberate properties
- **Low-FP by construction.** Tool schemas are matched only when the precise OpenAI/Anthropic shape is
  present; classification is by tool **name** against a curated set; the free-form `description` is
  **never** placed where `classify()`'s secret/eval regexes can see it.
- **v0.6 engine unchanged.** The capability taxonomy, MCP/permissions adapters, and system-prompt
  pillar are untouched; v0.7 only adds a grant source and an output format.

## 3. Architecture

Two additions to the existing `gitexpose/agent_exposure/` package:

```
agent_exposure/
  adapters/
    base.py             # + CONTENT_ADAPTERS registry + _register_content() + content_adapters()
    function_calling.py # NEW: shape-sniff OpenAI/Anthropic tools[] -> Grants (by name)
  capabilities.py       # extend _SHELL/_NETWORK/_FS_WRITE/_DB + secret name-set for function tools
  analyzer.py           # walk also offers .json/.yaml/.yml content to CONTENT_ADAPTERS
  sarif.py              # NEW: findings[] -> SARIF 2.1.0 (OWASP/ATLAS/ATT&CK taxonomies)
  scan.py               # unchanged (function-calling findings flow through analyze_configs)
```

CLI: `agent-audit` `--output` choice extended `console|json` → `console|json|sarif`.

### Two dispatch modes (base.py)

v0.6 dispatches by filename (`ADAPTERS: Dict[str, Adapter]`, `adapter_for(filename)`). v0.7 adds a
parallel **content-adapter** list:

```python
# parser signature unchanged: (content: str, source_file: str) -> List[Grant]
CONTENT_ADAPTERS: List[Adapter] = []

def _register_content(adapter: Adapter) -> None:
    CONTENT_ADAPTERS.append(adapter)

def content_adapters() -> List[Adapter]:
    return list(CONTENT_ADAPTERS)
```

A content adapter is offered the raw text of every `.json/.yaml/.yml` file and decides for itself
whether the parsed structure matches (returns `[]` on non-match — no filename gate).

## 4. Function-calling adapter (`adapters/function_calling.py`)

```python
import json
try:
    import yaml          # PyYAML (declared core dep); degrade gracefully if absent
except ImportError:
    yaml = None

def _load(content: str):
    # try JSON first (stdlib), then YAML if available; return parsed obj or None
    try:
        return json.loads(content)
    except ValueError:
        pass
    if yaml is not None:
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError:
            return None
    return None

def _iter_tool_arrays(obj):
    # yield candidate lists: top-level list, or lists under keys "tools"/"functions"
    ...

def _tool_name(item) -> Optional[str]:
    # OpenAI:  {"type":"function","function":{"name": N}}  or flattened {"type":"function","name":N}
    # Anthropic: {"name": N, "input_schema": {...}}
    # return N only when the item matches one of those exact shapes, else None

def parse_function_calling(content: str, source_file: str) -> List[Grant]:
    obj = _load(content)
    if obj is None:
        return []
    out = []
    for arr in _iter_tool_arrays(obj):
        names = [n for n in (_tool_name(it) for it in arr if isinstance(it, dict)) if n]
        if not names:
            continue                      # this array isn't a tool schema -> skip (FP guard)
        for name in names:
            out.append(Grant(
                tool=name,
                raw=f'tools[].name="{name}"',   # structured evidence ONLY — never the description
                source_file=source_file,
            ))
    return out

_register_content(parse_function_calling)
```

**Shape gate (FP control):** a candidate array produces grants only if ≥1 item matches the exact
OpenAI or Anthropic tool-object shape. `package.json`/`tsconfig.json`/CI YAML don't match. The
free-form `description` is intentionally excluded from `raw`, so `classify()`'s `_SECRET_RE`/`_EVAL_RE`
cannot fire on prose.

### Capability name-set extension (`capabilities.py`)

Add common function-tool names to the existing sets (additive; existing entries unchanged):
- `_SHELL` += `execute`, `exec_code`, `run_code`, `code_interpreter`, `python_exec`
- `_NETWORK` += `http_get`, `http_post`, `web_search`, `browse`, `search_web`, `url_fetch`
- `_FS_WRITE` += `save_file`, `put_file`
- `_DB` += `query_db`, `run_query`, `execute_sql`
- **New `_SECRET_NAMES` set** = `{read_secret, get_secret, read_env, get_env, fetch_secret, secrets_manager, vault_read}`, checked as `base in _SECRET_NAMES` in `classify()` → `SECRET_ACCESS`. (Name-based, not via `_SECRET_RE` — the function-tool `raw` is `tools[].name="…"`, which the existing `_SECRET_RE` would never match, and we deliberately keep prose out of `raw`.)

Benign names (`get_weather`, `calculator`, `lookup_order`) match nothing → no finding.

## 5. SARIF output (`agent_exposure/sarif.py`)

`to_sarif(findings: List[Dict], tool_version: str) -> str` → SARIF 2.1.0 JSON string.

- `runs[0].tool.driver`: `name="GitExpose"`, `version=tool_version`, `informationUri`, and a **rules**
  array — one rule per distinct `(type, capability_class)` seen (e.g. `excessive_agent_capability/shell_exec`,
  `excessive_agent_capability/exfil_capable_agent`, `exposed_system_prompt`), each with `fullDescription`
  and `properties` carrying the OWASP/ATLAS/ATT&CK ids.
- `results[]`: one per finding — `ruleId`, `level` from severity (CRITICAL/HIGH→`error`, MEDIUM→`warning`,
  LOW/INFO→`note`), `message.text` = `description`, `locations[0].physicalLocation` =
  `{artifactLocation.uri: source, region.startLine: 1}` (findings are file-level).
- `taxonomies`: OWASP LLM Top 10 + MITRE ATLAS + MITRE ATT&CK definitions; each result carries `taxa`
  references, mirroring the web `SARIFReporter`'s taxonomy approach so compliance metadata renders in
  Code Scanning.
- Robust to missing optional keys (`.get()`); a clean scan emits valid SARIF with empty `results`.

The existing `gitexpose/reporters/sarif_reporter.py` is **not reused** (it is coupled to the web
`ScanReport`/`ScanResult` model); `agent_exposure/sarif.py` is a focused emitter for the dict findings,
mirroring its structure.

CLI wiring (`cli_advanced.py agent-audit`):
```python
@click.option("-o", "--output", type=click.Choice(["console", "json", "sarif"]), default="console")
...
elif output == "sarif":
    from .agent_exposure.sarif import to_sarif
    text = to_sarif(findings, __version__)
```

## 6. Dependency change

- **Declare `PyYAML>=6.0` in core `dependencies`** (`pyproject.toml` + `setup.py`). Rationale: YAML
  shape-sniffing requires it; `advanced/api_discovery.py` already imports `yaml` undeclared (latent
  bug this fixes); PyYAML is small, pure-Python, ubiquitous.
- **Defensive import in `agent_exposure`**: `try: import yaml / except ImportError: yaml = None`. JSON
  shape-sniffing always works; YAML is sniffed only when importable (degrade with a debug log, never
  crash). So `agent-audit` still runs on a minimal/broken environment (JSON-only).

This is the only runtime-footprint change vs v0.6's "no new deps" — deliberate and justified.

## 7. Data flow (`analyze_configs`)

```
for each file under root (skip .git/node_modules/__pycache__/.venv/venv; size-cap 1 MB):
  1. filename dispatch (v0.6): adapter_for(rel) -> mcp / permissions -> Grant[]
  2. content dispatch (v0.7): if ext in {.json,.yaml,.yml}:
        for ca in content_adapters(): grants += ca(content, rel)   # function_calling
  classify every Grant -> excessive_agent_capability finding (UNRESTRICTED/exfil handled as v0.6)
exfil-chain escalation per source_file (now also covers tools-array sources)
scan() merges capability + system-prompt findings, severity-sorts (unchanged)
```

A file may yield grants from both paths; in practice the shape-sniff returns `[]` for MCP/permission
configs and vice-versa, so there is no spurious double-counting.

## 8. Error handling

- Unparseable JSON/YAML → `[]` (skip). Non-matching shape → `[]`.
- Per-file adapter exceptions isolated (one bad file never aborts the scan) — existing analyzer guard
  covers content adapters too.
- `yaml` absent → JSON-only, debug log, no crash.
- SARIF emitter tolerates findings missing optional keys; always emits valid SARIF.
- Size cap (1 MB) + skip-dirs reused for the content-dispatch path.

## 9. Testing

- **Adapter units** (`test_agent_adapter_function_calling.py`): OpenAI shape (nested + flattened) →
  grants by name; Anthropic shape → grants; benign `get_weather` array → no grant; `package.json`-style
  JSON (no tool shape) → `[]`; YAML tools file → grants; malformed JSON/YAML → `[]`; **a tool whose
  `description` contains "API_KEY" → NO `SECRET_ACCESS`** (proves the no-prose-in-`raw` FP guard);
  `read_secret`/`run_shell` names → SECRET/SHELL via the extended name-sets.
- **Analyzer integration**: a tools-schema file in a repo → `excessive_agent_capability`; a schema with
  both an exec tool and a fetch tool → exfil-chain CRITICAL finding.
- **SARIF** (`test_agent_sarif.py`): valid SARIF 2.1.0 (parses as JSON; `version`/`$schema`/`runs`);
  severity→level mapping; rules + taxa present; OWASP/ATLAS/ATT&CK ids carried; clean scan → empty
  `results`; missing-optional-key finding doesn't crash.
- **CLI** (`test_agent_audit_cli.py` append): `agent-audit -o sarif` emits parseable SARIF; exit 1 with
  findings; `--out-file` writes it.
- **Smoke** (`test_smoke_v07.py`): synthetic repo with an over-permissioned `tools` schema (exec+fetch)
  + the v0.6 MCP/permission fixtures → both engines fire; deterministic, offline.

Run with system Python 3.12 (`/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest
tests/`), not `uv run`.

## 10. Documentation & release

- README: feature row update (agent-audit now covers function-calling tool schemas + SARIF output) +
  an `agent-audit -o sarif` example; note the optional agent-audit step for the Code Scanning sample.
- `docs/COVERAGE.md`: function-calling tool schemas as a covered grant source; SARIF as an agent-audit
  output.
- `CHANGELOG.md` v0.7.0; `docs/v0.7-planning-notes.md` (v0.8 backlog: framework adapters, heuristic
  prompt detection, supply-chain SARIF, project-wide `mitre_attack`, `advanced/__init__` lazy-import).
- Version bump to `0.7.0` (pyproject, `gitexpose/__init__.py`); add `PyYAML>=6.0` to core deps.
- Gated on manual verification (`agent-audit` over a tools-schema fixture, `-o sarif` validity) before
  tag/push, same pattern as v0.5.1/v0.6.0/v0.6.1.

## 11. v0.8+ backlog (rolled forward)
- CrewAI / AutoGen / LangChain framework-grant content adapters.
- Heuristic (non-fingerprint) system-prompt detection; free-form tool-description danger inference.
- SARIF for `supply-chain`/`git-history` findings (unifies Code Scanning across all commands).
- Retrofit `mitre_attack` onto existing v0.2–v0.5 findings (secret-scan → T1552, supply-chain → T1195).
- Lazy `advanced/__init__` import so a bare `pip install gitexpose` runs supply-chain/agent-audit.
- Grow the CL4R1T4S seed fingerprint set.
- Carried from v0.5: classic typosquatting, lock-file poisoning checks, Shai-Hulud install-time
  behavioral analysis, Go/Cargo SCA, policy engine, `--verify` on web-scan path, AI canary tokens.
