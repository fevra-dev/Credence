# GitExpose v0.8 — "AI-Infra Layer, Deepened" — Design Spec

**Date:** 2026-06-01
**Status:** Approved (brainstorm) → ready for implementation plan
**Predecessor:** v0.7.0 "Agent Exposure, Deepened" (function-calling adapter + SARIF)

---

## 1. Positioning & Strategy

### 1.1 The frame

GitExpose is the secrets/exposure scanner for the **AI-infrastructure layer** —
MCP configs, agent skill files, model cards, dataset pipelines, LiteLLM proxies,
and `.claude/settings.json` — the artifacts general scanners (TruffleHog, Gitleaks)
treat as plain text. It is designed to run **alongside** those tools, not replace them.

This is a deliberate retreat from "beat TruffleHog on breadth" (they have 800+ detectors,
a $25M Series B, and an HF vendor relationship — breadth is unwinnable). The defensible,
accurate frame is complementarity: GitExpose owns the AI-infra finding types incumbents
don't have, and proves the "runs alongside" claim mechanically via SARIF
`partialFingerprints` cross-tool deduplication.

### 1.2 Three credibility commitments

1. **"Runs alongside" is mechanical, not rhetorical.** The orphan cross-source signal
   emits `partialFingerprints["secretValueHash/v1"]` — the exact SARIF field GitHub Code
   Scanning and DefectDojo use to dedup findings across tools.
2. **Honest scoping as a feature.** Where the tool cannot scan (LFS binaries, `include.path`
   git configs, etc.), it says so in output rather than skipping silently.
3. **Precision over recall, on purpose.** Every new finding type is structural/high-confidence
   and ships with a fixture corpus measuring precision. We do not chase Betterleaks' 98.6%
   recall at 57% precision; we win on AI-infra finding types they lack.

### 1.3 North-star reconciliation

Build to **balanced** discipline (precision, SARIF dedup, honest scoping, fixtures for every
finding type); **frame** with a portfolio lean (AI-infra positioning, MITRE ATLAS/OWASP-LLM
tagging, narrative README). Same codebase, intentional framing — the two goals are not in
tension for this project.

### 1.4 Naming (PARKED — decoupled, not in v0.8 scope)

The project will eventually be renamed away from "GitExpose" (the "Git" prefix undersells the
AI-infra scope) toward an *Exposure Intelligence* brand. This is **decoupled from v0.8**:
features ship under `gitexpose` first; the rename is its own later pass.

- **Top 3 candidates** (for the rebrand pass, in preference order): **Veracity** (truth/verdict
  lane; real word; bare PyPI name free), **Credence / Credentia** (trust+credential lane;
  `credence` PyPI taken → dist `credence-cli`, or coined `credentia` for the zero-asterisk
  variant), **Unmask** (reveal-action lane; best raw CLI line; free).
- **Decoupling rule:** rename brand + CLI + PyPI dist only; **keep the internal `gitexpose/`
  package directory** to avoid import churn across every module and test.
- Working artifacts: `docs/new_research/naming-candidates.md` + `.html`.
- A PyPI/GitHub availability + security-vendor-collision check must run before any final lock.

---

## 2. Scope

### 2.1 In scope (four features + one foundation)

| # | Feature | New/changed module | Pipeline |
|---|---------|--------------------|----------|
| 0 | `--fail-on` severity exit gating (foundation) | `cli_advanced.py` (shared helper) | both local subcommands + git-history |
| ① | Git-metadata credential spine (3 finding types) | `advanced/git_config_scanner.py` (new) | `supply-chain` |
| ② | Agent debug-print AST detector | `agent_exposure/debug_print.py` (new) | `agent-audit` |
| ③ | MCP security score (0-100) + per-issue findings | `agent_exposure/mcp_score.py` (new); extend `adapters/mcp.py`, `analyzer.py` | `agent-audit` |
| ④ | Orphan cross-source signal | `advanced/secret_registry.py` (new); pass in `credential_cluster.py` | `supply-chain` |

### 2.2 Explicitly deferred to v0.9 (named, not dropped)

`hf-scan` subcommand, Jupyter output-cell scanning, SafeTensors/PNG metadata scanning,
`ml_dataset_context` risk amplifier, `--semantic` (Anthropic API) classification, `hf-monitor`
webhook daemon. These cohere as their own release: a new **remote scan mode** (network egress,
rate limits, ID-addressed targets) distinct from v0.8's all-local high-precision static analysis.

### 2.3 Non-goals

- No new runtime dependencies (all stdlib: `configparser`, `ast`, `hashlib`, `base64`).
- No network calls in any v0.8 feature.
- No rename wiring (see §1.4).
- No change to the web-scanner (`scan`) or `full-audit` pipelines.

---

## 3. Architecture & Data Flow

Both target pipelines converge on the **finding-dict** shape
(`{type, severity, source, description, attack_class, atlas_technique, ...}`) and the shared
console/json/sarif reporters. The HTTP `ScanResult` dataclass (web scanner) is untouched.

```
gitexpose supply-chain <path>
  └─ LocalFilesystemScanner.scan(root)
       ├─ _iter_files()                          [① add .git/config + .gitmodules access]
       ├─ per-file: SecretExtractor + supply-chain modules (existing)
       ├─ NEW ① git_config_scanner.scan(root)    → 3 git-metadata finding-dicts
       └─ credential_cluster.process(findings)
              └─ NEW ④ secret_registry pass        → enriches each secret finding with
                                                     source_frequency + secret_value_hash
                                                     (opt-in via --track)

gitexpose agent-audit <path>
  └─ agent_exposure.scan(root)
       ├─ analyze_configs(root)
       │     ├─ mcp adapter (existing grants)
       │     └─ NEW ③ mcp_score → per-issue findings + INFO posture summary per server
       ├─ NEW ② debug_print.scan(root)            → agent_skill_credential_print finding-dicts
       └─ _scan_system_prompts() (existing)
```

### 3.1 Feature ① — Git-metadata credential spine

- **Module:** `advanced/git_config_scanner.py`, exposing `scan(root: Path) -> List[Dict]`.
- **Invocation:** once per scan (not per-file) from `LocalFilesystemScanner.scan()`; parses
  three specific files structurally.
- **Files & finding types:**
  - `.git/config` `[remote "*"] url =` → `git_config_credential_url`
  - `.git/config` `[http "*"] extraHeader = AUTHORIZATION: Basic <b64>` →
    `git_config_extraheader_credential` (base64-decode, then provider-pattern match)
  - `.gitmodules` `[submodule "*"] url =` → `gitmodules_credential_url`
    (working-tree + history file → carries `committed_to_history: true`)
- **Token classes:** prefix patterns `ghp_`, `github_pat_`, `ghs_`, `glpat-`, `hf_`;
  generic `user:password@host` URL structure → lower-confidence `git_config_generic_token_url`
  at INFO/LOW with a manual-verify note.
- **HARD SAFETY CONSTRAINT (CVE-2025-41390):** parse with `configparser.ConfigParser(strict=False)`
  ONLY. **Never invoke git** (no subprocess, no GitPython `Remote`) on the target — a malicious
  `core.fsmonitor` in `.git/config` yields RCE. `.git/` stays in `_SKIP_DIRS`; the scanner reads
  `.git/config` by explicit path. This is a documented design property.
- **`.git/` access note:** `.git/config` is read by direct path even though `.git/` is in the
  walk skip-set; this is intentional and the only `.git/` file the scanner opens.

### 3.2 Feature ② — Agent debug-print AST detector

- **Module:** `agent_exposure/debug_print.py`, exposing `scan(root: Path) -> List[Dict]`.
- **Shape:** mirrors `_scan_system_prompts` — walk root (respecting `_SKIP_DIRS`, `_MAX_BYTES`),
  filter to Python agent/skill/tool files, `ast.parse`, walk `ast.Call` nodes.
- **Detection:** `print(...)` / `logging.*(...)` calls whose arguments reference a credential-named
  variable (`api_key`, `apikey`, `token`, `bearer`, `secret`, `client_secret`, `password`,
  `access_key`, etc., matched on `ast.Name`/`ast.Attribute` identifiers — NOT string literals).
- **Finding type:** `agent_skill_credential_print`, severity HIGH, OWASP LLM06 / ATLAS AML.T0019.
- **FP discipline:** only variable references count; `print("api_key is set")` (string literal)
  does not fire. Malformed Python → caught per-file, never aborts the scan (existing convention).
- **Dependency:** stdlib `ast` only.

### 3.3 Feature ③ — MCP security score (0-100) + per-issue findings

**Decoupled design: score informs; severity gates.** (This corrects an earlier bundled-finding
proposal that would have made the score decorative, broken SARIF identity, and been un-triageable.)

- **Module:** `agent_exposure/mcp_score.py`, exposing `score_servers(parsed_mcp, source) -> List[Dict]`.
- **Per-issue findings** (one fact per finding; independently severity-tagged, suppressible,
  fingerprinted on `(issue_type + server + source)`):
  - `mcp_static_credential` — static token/secret in config → HIGH (−30)
  - `mcp_plaintext_http` — `http://` (not https) server URL → HIGH (−20)
  - `mcp_unknown_origin` — server not in `KNOWN_MCP_SERVERS` registry → LOW (−15)
  - `mcp_unpinned_version` — no version pin on the server/package → LOW (−5)
- **Bonuses (affect score only, not gating):** known-vendor server (+20), OAuth-not-static (+15).
- **Per-server summary finding:** `mcp_server_posture` at **INFO**, carrying the 0-100 score AND
  its deduction breakdown (e.g. `"78/100 — −15 unknown origin, −5 no pin"`). Fingerprinted on
  `(server + source)` so its evolution tracks as one finding. INFO never gates CI.
- **Registry seed:** small `KNOWN_MCP_SERVERS` constant (Anthropic, Stripe, GitHub, known HF
  endpoints) — enough to make `unknown_origin` meaningful rather than penalizing every server.
- **Integration:** `analyze_configs` calls `score_servers` on each parsed MCP server; emitted
  alongside (not replacing) existing `excessive_agent_capability` MCP grant findings.

### 3.4 Feature ④ — Orphan cross-source signal

- **Module:** `advanced/secret_registry.py` — a `SecretRegistry` class.
- **Mechanism:** post-processing **enrichment** pass inside `credential_cluster.process()` — it
  **mutates** each secret finding-dict to add `source_frequency` + `secret_value_hash`, rather
  than emitting new finding types.
- **Hashing:** `SHA256(normalize(value))` where normalize = strip whitespace + URL-decode +
  case-preserve. **Raw secret values are NEVER persisted** — the registry stores hashes only.
- **Frequency bands:** `orphan_candidate` (1) / `low` (2–5) / `moderate` (6–15) / `high` (16–50)
  / `replicated` (51+). Band is a **triage hint, not a verdict** — finding text states
  "appears in N scanned sources; statistical association with private accidental leaks, not
  confirmation."
- **`KNOWN_EXAMPLE_KEYS`:** static downgrade list (e.g. AWS `AKIAIOSFODNN7EXAMPLE`) → INFO.
- **State & opt-in:** registry persists to `~/.gitexpose/registry.json` (override via `--registry`).
  **Opt-in via `--track`**; without it, default runs are stateless and write nothing to disk.
- **SARIF:** the emitter reads `secret_value_hash` → `partialFingerprints["secretValueHash/v1"]`.

### 3.5 State & side-effects summary

Only feature ④ touches disk state, and only under `--track`. All other features are pure
functions over file content. No network in any feature.

---

## 4. CLI Surface, Flags & SARIF

### 4.1 Exit-code gating foundation (Feature 0)

- **New flag `--fail-on {info,low,medium,high,critical}`**, shared across `agent-audit`,
  `supply-chain`, and `git-history` (one coherent gating contract).
- **Default: `high`** — only HIGH/CRITICAL findings fail CI. Cosmetic posture (LOW) and existing
  MEDIUM capability grants become **visible-but-non-blocking**.
- Replaces the current `sys.exit(1 if findings else 0)` contract with a severity-thresholded exit.
  **All findings still print**; the gate only controls the exit code.
- **Behavior change — CHANGELOG'd.** Acceptable pre-1.0; aligns with Trivy/Semgrep/Checkov norms.
  Power users tighten with `--fail-on info` (= old behavior) or loosen with `--fail-on critical`.

### 4.2 `supply-chain` additions

- `--track` (flag, default off) — enable the cross-source `SecretRegistry`. Off = stateless.
- `--registry PATH` (optional) — override registry location (default `~/.gitexpose/registry.json`).
  Useful for CI cache dirs and test isolation.
- Git-metadata findings (①) are **always on** (structural, high-precision — no flag).
- `--fail-on` (from §4.1).

### 4.3 `agent-audit` additions

- Features ② (debug-print) and ③ (MCP score) are **always on** — high-precision, no flag.
- `--fail-on` (from §4.1).
- No other new flags; existing `--output {console,json,sarif}` carries the new finding types.

### 4.4 Defaults preserved

Bare `gitexpose <host>` still routes to the web scanner. `supply-chain` and `agent-audit` keep
their current positional signatures. Only additions are flags.

### 4.5 SARIF wiring

- `partialFingerprints["secretValueHash/v1"] = <sha256>` on every secret-bearing result carrying
  `secret_value_hash` (the cross-tool dedup mechanism — the "runs alongside TruffleHog" proof).
- `result.properties.source_frequency`, `properties.ml_dataset_context` (carried through if
  present), existing MITRE/OWASP tags stay in `properties`.
- New rule IDs registered in the SARIF taxonomy: `git_config_credential_url`,
  `git_config_extraheader_credential`, `gitmodules_credential_url`, `git_config_generic_token_url`,
  `agent_skill_credential_print`, `mcp_static_credential`, `mcp_plaintext_http`,
  `mcp_unknown_origin`, `mcp_unpinned_version`, `mcp_server_posture`.

### 4.6 Console output

New finding types render through the existing generic finding-dict loop. MCP per-issue findings
render as discrete lines; the `mcp_server_posture` summary adds a `score: NN/100 (reasons...)` line.

---

## 5. Testing, Rollout & Sequencing

### 5.1 Testing — precision-first discipline

Every new finding type ships with a **fixture corpus** under `tests/fixtures/v0.8/`: positive
cases (real-shaped) + negative cases (placeholders, comments, example keys) to measure FP rate.

- **① git-metadata:** fixtures for `.git/config` with `ghp_`/`glpat-`/`hf_`/generic URLs, Azure
  `extraHeader` (valid base64 + garbage), `.gitmodules`; **explicit CVE-2025-41390 test** — a
  malicious `core.fsmonitor` config proving the scanner never shells out to git (assert no
  subprocess invocation).
- **② debug-print:** AST fixtures — `print(api_key)` (hit), `print("api_key is set")` (no hit),
  `logging.info(token)` (hit), malformed Python (no crash, no finding).
- **③ MCP score:** server configs spanning the deduction/bonus matrix; assert score arithmetic,
  per-issue severities, INFO summary content, and that LOW issues do NOT gate at default
  `--fail-on high`.
- **④ orphan registry:** frequency-band transitions, `KNOWN_EXAMPLE_KEYS` downgrade,
  **no-raw-value persistence assertion** (registry file contains only hashes), `--track` off ⇒
  no disk writes, SARIF `partialFingerprints` emission.
- **Feature 0 gate:** `--fail-on` threshold + exit-code matrix across all five severities on
  both subcommands.
- **CI:** keep the suite green across py3.9–3.12 (preserve the first-green-CI streak).
- **`requirements.txt` sync:** the v0.7 lesson — CI installs from `requirements.txt`, not
  `pyproject.toml`. No new runtime deps planned (all stdlib), so nothing to add — verify at
  ship time regardless.

### 5.2 Build sequence (low-risk → headline)

1. `--fail-on` gating foundation (Feature 0 — everything else assumes it).
2. ① git-metadata spine (self-contained, highest precision).
3. ② debug-print AST (self-contained, peer-reviewed basis).
4. ③ MCP score (extends existing adapter).
5. ④ orphan registry + SARIF fingerprints (the integration headline).
6. README reframe (AI-infra-layer + runs-alongside-TruffleHog) + docs/COVERAGE/CHANGELOG +
   version bump + smoke fixture + manual editable-install verification.

### 5.3 Rollout

TDD per feature; one feature per logical commit group; suite green throughout. Smoke-test fixture
+ manual editable-install verification before tag (matching the v0.2→v0.7 cadence). Version →
`0.8.0` synced across `pyproject.toml` / `__init__.py` / `requirements*`. Tag `v0.8.0`,
build wheel+sdist, publish release notes. Branch `v0.8` → fast-forward `main` per project pattern.

---

## 6. Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| CVE-2025-41390 RCE via malicious `.git/config` | `configparser` only, never git subprocess; explicit no-subprocess test (§5.1). |
| MCP posture LOW findings spam CI | Decoupled score/severity + `--fail-on high` default (§3.3, §4.1). |
| Orphan signal false-downgrade (one owner, many repos) | Band is a documented triage hint, not a verdict; `--verify` remains the arbiter (§3.4). |
| `--fail-on` default change surprises existing users | CHANGELOG as behavior change; `--fail-on info` restores old behavior (§4.1). |
| Raw secret values leaking into registry | Hash-only persistence + explicit no-raw-value test (§3.4, §5.1). |
| configparser edge cases (multi-value keys, `include.path`) | Check each `url=` line independently; document `include.path` as a known limitation (honest scoping). |
| New runtime dep sneaks in | All features stdlib by design; verify `requirements.txt` at ship (§5.1). |

---

## 7. Success Criteria

- The new finding types across the four features (3 git-metadata + 1 generic-URL fallback +
  1 debug-print + 4 MCP per-issue + 1 MCP posture summary = 10 rule IDs per §4.5) live in
  `supply-chain` / `agent-audit`, each with passing positive + negative fixtures demonstrating
  low FP.
- `--fail-on` works across the three local subcommands with a tested exit-code matrix; default
  `high`.
- SARIF emits `partialFingerprints["secretValueHash/v1"]` and validates against SARIF 2.1.0.
- CVE-2025-41390 no-subprocess test passes; orphan registry no-raw-value test passes.
- CI green across py3.9–3.12; wheel+sdist published; README reframed to the AI-infra positioning.
- `hf-scan` and the ML-dataset surface explicitly recorded as the v0.9 scope.
