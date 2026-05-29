# GitExpose v0.6 — "AI Agent Exposure" Design

> Brainstormed 2026-05-28. Headline: GitExpose learns to judge *what an AI agent is allowed to do* —
> parse MCP server configs + agent permission lists, classify tool/capability grants against a
> dangerous-capability taxonomy, and flag over-permissioned agents (OWASP LLM08 Excessive Agency).
> Second pillar: detect committed/leaked system prompts via vendored CL4R1T4S known-leak fingerprints.

## 1. Motivation

GitExpose detects AI-config *presence/exposure* (`mcp.json`, `.continue/`, CrewAI/AutoGen via path
signatures) and *malicious content* inside those files (`skill_prompt_injection`,
`agent_config_malicious_content`). It does **not** parse the actual tool/capability grants inside
agent configs and judge whether an agent is over-permissioned. That gap is the v0.6 target.

The 2025-26 explosion of MCP servers and agentic IDE tooling created a new exposure class: an agent
wired to a `bash` MCP server, or granted `Bash(*)` + `WebFetch`, is an *exfil-capable* foothold —
legitimate-looking config, dangerous capability. This is **OWASP LLM08 Excessive Agency**, and it is
distinct from the existing "malicious content" detector (which looks for command/exfil *payloads*,
not over-broad *grants*).

Input that motivated this: the Pliny "system-prompts-and-models-of-ai-tools" finding — leaked JSON
tool schemas reveal "what tools an agent has been given permission to use" — plus the CL4R1T4S
corpus of real leaked system prompts. (The rest of the Pliny ecosystem — L1B3RT4S jailbreak
taxonomy, OBLITERATUS abliteration, G0DM0D3 — is offensive research outside GitExpose's defensive
exposure-scanner lane and is deliberately excluded.)

This is a detection-depth release, the agent-side analog of the long-deferred "capability/scope
enumeration for verified credentials." Same capability-jump shape as prior releases (v0.3 Active
Verification, v0.4 Detection Depth, v0.5 Supply-Chain Intelligence, v0.6 AI Agent Exposure).

## 2. Scope

### In scope (v0.6)

- **Excessive-agency analyzer** over two config-format families:
  - **MCP server configs:** `mcp.json`, `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`.
  - **Claude-Code permission lists:** `.claude/settings.json`, `.claude/settings.local.json` (`permissions.allow` / `permissions.deny`).
- **New finding type `excessive_agent_capability`** (OWASP LLM08).
- **Exposed system-prompt detection** via vendored CL4R1T4S known-leak fingerprints → **new finding type `exposed_system_prompt`** (OWASP LLM07).
- **New `gitexpose agent-audit <path>` command** (console/json).
- **Format-agnostic capability engine + pluggable config-source adapters** so v0.7 formats are additive.

### Out of scope (deferred to v0.7 — additive via the adapter interface)

- Function-calling tool schemas (OpenAI/Anthropic `tools` arrays) — inferring danger from free-form descriptions (higher FP).
- CrewAI / AutoGen / LangChain framework tool grants (per-framework class knowledge; brittle).
- Generic "looks-like-a-system-prompt" heuristic detection (v0.6 uses fingerprints only, for precision).
- SARIF output for agent findings (console/json in v0.6; SARIF later).

### Two deliberate properties

- **No active-verification dimension.** A tool grant cannot be "verified" by a network call — v0.6 is
  pure static analysis. Unlike v0.3/v0.5, there is no `--verify`-style liveness here.
- **No new runtime dependencies.** Core formats are JSON (stdlib `json`); fingerprinting uses stdlib
  `hashlib`. (Contrast v0.5, which added `cyclonedx-python-lib` etc.)

## 3. Architecture

A new cohesive `gitexpose/agent_exposure/` package, parallel to `supply_chain/`, `verification/`,
`git_history/`:

```
gitexpose/agent_exposure/
  __init__.py
  models.py            # Grant, CapabilityClass, AgentFinding helpers
  capabilities.py      # dangerous-capability taxonomy + classify() + escalation rules
  adapters/
    __init__.py        # imports register adapters (side-effect, like lockfiles/)
    base.py            # ConfigAdapter protocol + registry + scan_path() dispatcher
    mcp.py             # MCP server config adapter
    permissions.py     # Claude-Code permission-list adapter
  analyzer.py          # walk → adapters → Grant[] → classify → excessive_agent_capability findings
  system_prompt.py     # CL4R1T4S fingerprint matcher → exposed_system_prompt findings
  scan.py              # top-level scan(path) → merged finding-dict list
  data/cl4r1t4s_fingerprints.json   # vendored known-leak fingerprints (hashes only)
```

The capability engine (taxonomy + `classify`) is **format-agnostic**: each adapter normalizes its
format into `Grant` objects, and the engine classifies grants identically regardless of source.
Adding a v0.7 format = one new adapter, no engine change. The package is **self-contained** — it does
its own focused directory walk (like `supply_chain.lockfiles.parse_all`) and does not touch the
existing `skill_security` / `LocalFilesystemScanner` / `supply-chain` path.

### Data model (`models.py`)

```python
class CapabilityClass(str, Enum):
    SHELL_EXEC = "shell_exec"
    CODE_EVAL = "code_eval"
    SECRET_ACCESS = "secret_access"
    NETWORK_FETCH = "network_fetch"
    FILESYSTEM_WRITE = "filesystem_write"
    DATABASE = "database"
    BROWSER_CONTROL = "browser_control"
    UNRESTRICTED = "unrestricted"

@dataclass(frozen=True)
class Grant:
    tool: str            # e.g. "shell", "WebFetch", "filesystem"
    raw: str             # the literal config evidence, e.g. 'command="bash"'
    source_file: str     # relative path
```

## 4. Capability taxonomy

| Class | Trigger examples | Base severity |
|---|---|---|
| `SHELL_EXEC` | MCP `command` ∈ {bash, sh, zsh, fish, cmd, powershell, `python -c`, `node -e`}; `Bash`/`Shell`/`Terminal` allow | CRITICAL |
| `CODE_EVAL` | code-interpreter / eval tools; `python`/`node` REPL servers | HIGH |
| `SECRET_ACCESS` | MCP `env` passthrough of `*_KEY`/`*_TOKEN`/`*_SECRET`; `Read` of `.env*`; secret-manager servers | HIGH |
| `NETWORK_FETCH` | `WebFetch`/`fetch`/`curl`/`http` tools; fetch/web MCP servers | HIGH |
| `FILESYSTEM_WRITE` | `Write`/`Edit`/`MultiEdit`; filesystem-write MCP servers | MEDIUM |
| `DATABASE` | postgres/mysql/sqlite MCP servers | MEDIUM |
| `BROWSER_CONTROL` | playwright/puppeteer/browser MCP servers | MEDIUM |
| `UNRESTRICTED` | `*`, `Bash(*)`, allow-list present with empty/absent deny-list | CRITICAL |

**Classification:** `classify(grant) -> set[CapabilityClass]` via a known-tool map + command/pattern
matching. A benign grant (read-only docs server, no shell, no wildcard) returns the empty set → no
finding.

**Escalation rules:**
- **Wildcard escalation** — a grant matching `*` / `(*)`, or an allow-list with no corresponding
  deny-list, is classed `UNRESTRICTED` (CRITICAL) regardless of the underlying tool. The
  over-permission itself is the finding.
- **Combination escalation** — when `SHELL_EXEC` or `CODE_EVAL` co-occurs with `NETWORK_FETCH` or
  `SECRET_ACCESS` on the same agent/source, emit one escalated CRITICAL finding carrying
  `exfil_chain` (the chain of classes), described as an exfil-capable agent.

**Deny-list awareness:** for permission lists, an allow-entry that is fully covered by a matching
deny-entry produces no finding (the deny neutralizes it).

## 5. Finding shapes

### `excessive_agent_capability`

```jsonc
{
  "type": "excessive_agent_capability",
  "tool": "shell", "capability_class": "shell_exec",
  "severity": "CRITICAL",
  "source": ".cursor/mcp.json",
  "evidence": "mcpServers.shell.command = \"bash\"",
  "description": "MCP server 'shell' is wired to an arbitrary shell command — an agent using it can run any command on the host.",
  "recommendation": "Remove the server or restrict it to a fixed allow-listed binary; add an explicit deny.",
  "attack_class": "OWASP LLM08 Excessive Agency",
  "atlas_technique": "AML.T0053",        // LLM Plugin Compromise — verify against current ATLAS during impl
  "exfil_chain": ["shell_exec", "network_fetch"]   // only on combination-escalated findings
}
```

### `exposed_system_prompt`

```jsonc
{
  "type": "exposed_system_prompt",
  "product": "<AI tool/product name>",
  "severity": "HIGH",
  "source": "src/prompts/agent.txt",
  "match_strength": "12/40 shingles",
  "description": "Matches the known-leaked system prompt of <product> (CL4R1T4S corpus) — exposing its guardrails and granted tool permissions.",
  "recommendation": "If this is your product's prompt, treat it as leaked (rotate embedded secrets/tools, assume guardrails are known). If a copied third-party prompt, remove it.",
  "attack_class": "OWASP LLM07 System Prompt Leakage",
  "atlas_technique": "AML.T0054"         // LLM Meta Prompt Extraction — verify during impl
}
```

Both keep GitExpose's finding-dict convention (`severity`/`source`/`attack_class`/`atlas_technique`)
so they render through the same console/json paths.

## 6. System-prompt pillar — CL4R1T4S fingerprints

**Fingerprint scheme (privacy- & license-clean):** never vendor prompt text — only one-way hashes.
For each known leak: normalize text (lowercase, collapse whitespace), slide a k-word window (k = 8),
`blake2b`-hash each shingle (truncated to 16 hex chars), store the hash set + metadata
(`product`, `source_url`, `min_match`). Redistributes no third-party content (sidesteps CL4R1T4S
licensing), keeps the repo tiny, and tolerates light edits via shingle overlap.

**`cl4r1t4s_fingerprints.json` shape:**
```jsonc
{
  "version": 1,
  "fingerprints": [
    { "product": "Example IDE Agent", "source_url": "https://github.com/elder-plinius/CL4R1T4S/...",
      "shingle_k": 8, "min_match": 5, "shingles": ["a1b2c3d4e5f6a7b8", "..."] }
  ]
}
```

**Detection (`system_prompt.py`):** for each text file (size-capped, binary-skipped), compute its
k=8 shingle hashes and intersect with each fingerprint's set. Overlap ≥ `min_match` → emit
`exposed_system_prompt` with `match_strength = "<overlap>/<len(fingerprint.shingles)>"`.

**v0.6 seed corpus:** a curated seed set (a handful of high-profile, well-documented leaks) ships in
`data/cl4r1t4s_fingerprints.json`. An offline generator `scripts/build_cl4r1t4s_fingerprints.py`
(NOT shipped in the wheel) regenerates the file from a local CL4R1T4S checkout, so the set is
expandable without hand-editing JSON. Growing the set is a maintenance task, not a code change.

**Why fingerprints, not heuristics:** matching known leaks is high-precision and defensible
("this IS the leaked <product> prompt"); a generic "looks like a system prompt" classifier would
fire on every repo with prompt strings. Heuristic detection is explicitly deferred to v0.7.

## 7. CLI & data flow

```
gitexpose agent-audit <path> [options]
  -o, --output console|json     # mirrors supply-chain renderers
  --out-file PATH
  --max-bytes N                 # per-file size cap (default 1 MB), both pillars
```

Data flow (`agent_exposure.scan(path)`):
```
1. walk path  (skip .git/node_modules/__pycache__/.venv/venv; size-cap; binary-skip)
2. recognized config files → adapters → Grant[] → classify → excessive_agent_capability
     (+ wildcard escalation, + combination/exfil-chain escalation)
3. text files → system_prompt fingerprint match → exposed_system_prompt
4. merge → severity-sort (UNRESTRICTED / exfil-chain first) → render (console/json)
   → exit 1 if findings else 0
```

Console: severity-tagged lines with the OWASP/ATLAS tag + an evidence line. JSON: raw finding dicts.
The command is **separate from `supply-chain`** (category clarity: deps vs. agent exposure); existing
`skill_security` findings remain in the `supply-chain` path unchanged.

## 8. Error handling

- Malformed JSON in a config → skip that file with a warning; continue (one bad file never aborts).
- Per-file adapter exceptions isolated (a bad config can't crash the scan).
- Unreadable / oversized files skipped with a warning.
- No configs + no matches → clean "✅ no agent-exposure findings in <path>" (exit 0).

## 9. Testing

- **Adapter units** — MCP: `command:"bash"` → `SHELL_EXEC`; read-only `npx @x/docs-server` → no
  finding; `env` passthrough of `*_KEY` → `SECRET_ACCESS`. Permissions: `Bash(*)` →
  `UNRESTRICTED`+`SHELL_EXEC`; `WebFetch` → `NETWORK_FETCH`; allow-entry covered by a matching deny →
  no finding.
- **Taxonomy/classify** — each `CapabilityClass`; wildcard escalation; combination escalation
  (`SHELL_EXEC`+`NETWORK_FETCH` → CRITICAL with `exfil_chain`).
- **System-prompt matcher** — planted known-leak text → match at expected strength; benign prompt
  text → no match (FP guard); light-reformat robustness (shingle overlap holds).
- **CLI** — `agent-audit` console/json, severity ordering, exit codes, malformed-config resilience.
- **Smoke (`test_smoke_v06`)** — synthetic repo with an over-permissioned MCP config + a planted
  seed-fingerprint prompt → both finding types; deterministic, offline.

Run with system Python 3.12 (`/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m
pytest tests/`), not `uv run`.

## 10. Documentation & release

- README feature row + `agent-audit` examples; `docs/COVERAGE.md` (new finding types + OWASP
  LLM07/LLM08 mapping + the config formats covered); `CHANGELOG.md`; `docs/v0.6-planning-notes.md`
  (v0.7 backlog).
- Version bump to `0.6.0` (pyproject, `gitexpose/__init__.py`).
- Gated on manual verification before push, same pattern as v0.2–v0.5.

## 11. v0.7+ backlog (rolled forward)

- Function-calling tool schemas (OpenAI/Anthropic `tools`) adapter.
- CrewAI / AutoGen / LangChain framework-grant adapters.
- Heuristic (non-fingerprint) system-prompt detection.
- SARIF output for agent-exposure findings.
- Carried from v0.5: classic typosquatting, lock-file poisoning checks, Shai-Hulud install-time
  behavioral analysis, Go/Cargo SCA, policy engine, `--verify` on web-scan path, AI canary tokens.
