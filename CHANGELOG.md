# Changelog

## v0.7.0 — 2026-05-31 — Agent Exposure, Deepened

### Added
- **Function-calling tool-schema detection** — `agent-audit` now flags over-permissioned function-calling tools (OpenAI/Anthropic `tools[]` arrays in JSON/YAML), shape-sniffed wherever they live and classified by tool **name** against the v0.6 capability taxonomy (`excessive_agent_capability`, OWASP LLM08). Low-FP: only the exact tool-schema shape matches, and free-form tool descriptions are never inspected.
- **SARIF 2.1.0 output for `agent-audit`** (`-o sarif`) — agent findings now upload to GitHub Code Scanning, carrying the OWASP/ATLAS/ATT&CK compliance triple as rule/result properties + taxonomy references.
- New content-adapter (shape dispatch) mode in the agent-exposure engine — v0.8 framework adapters (CrewAI/AutoGen/LangChain) drop in here.

### Changed
- `PyYAML>=6.0` is now a core dependency (enables YAML tool-schema sniffing; also fixes a previously-undeclared `import yaml` in `gitexpose/advanced/api_discovery.py`). The agent-exposure package imports it defensively, so `agent-audit` still runs (JSON-only) if PyYAML is somehow absent.

## v0.6.1 — 2026-05-31 — CLI entry-point unification

### Fixed
- The installed `gitexpose` binary now exposes the advanced subcommands — `scan`, `supply-chain`, `git-history`, `agent-audit`, `react2shell`, `ml-scan`, `llm-scan`, `unicode-scan`, `mcp`, `list-tools`, `full-audit`. Previously the console script only ran the web scanner, so the documented `gitexpose supply-chain`/`git-history`/`agent-audit` commands didn't work from an install — they required `python -m gitexpose.cli_advanced`.
- The group's `--version` reported a stale `0.4.0`; it now reflects the package version.
- **Sample GitHub Action** (`gitexpose-scan.yml`): it never ran — it installed core-only (`supply-chain` needs the `advanced` extra), used `--output sarif` (supply-chain emits console/json/cyclonedx/aibom, not SARIF) and a non-existent `--output-file` flag. Now installs `.[advanced]`, runs `supply-chain . --offline -o json --out-file …`, and uploads the JSON as a build artifact.
- **Pre-commit hook** (`.pre-commit-hooks.yaml`): removed the broken `gitexpose-staged` hook (it passed individual files to `supply-chain`, whose `PATH` is directory-only) and kept a single working `gitexpose-supply-chain` hook that scans the repo root, with the `advanced` extra wired via `additional_dependencies`.

### Changed
- Bare-target `gitexpose <host>` and `gitexpose -f targets.txt` still run the web scanner (now the default `scan` command) — **non-breaking**.
- The advanced multi-module aggregator (`--full-audit` sweep) moved from `scan` to **`gitexpose full-audit`**; the mature web scanner is the canonical `gitexpose scan`. (Its sub-modules `react2shell`/`ml-scan`/`llm-scan`/`unicode-scan` remain standalone subcommands.)

## v0.6.0 — 2026-05-30 — AI Agent Exposure

### Added
- **`gitexpose agent-audit <path>`** — audits AI-agent configs for excessive tool permissions and leaked system prompts (console/json).
- **Excessive-agency analysis** (`excessive_agent_capability`, OWASP LLM08) over MCP server configs (`mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`) and Claude-Code permission lists (`.claude/settings.json`). 8-class dangerous-capability taxonomy (shell/exec, code-eval, secret-access, network, fs-write, database, browser, unrestricted-wildcard) with exfil-chain escalation (exec + network/secret → CRITICAL). Deny-list-aware (a deny neutralizes a matching allow).
- **System-prompt exposure detection** (`exposed_system_prompt`, OWASP LLM07) via CL4R1T4S known-leak shingle fingerprints (blake2b hashes only; no prompt text vendored; tolerant of light edits).
- **Verified MITRE triple** on every agent finding: OWASP LLM Top 10 + ATLAS (`AML.T0053` AI Agent Tool Invocation / `AML.T0056` LLM Meta Prompt Extraction, verified against the live matrix) + ATT&CK (`T1059`/`T1552`/`T1071.001`/… per capability class, `T1041` on exfil chains). New `mitre_attack` finding field.

### Notes
- No new runtime dependencies (stdlib `json`/`hashlib`). Format-agnostic capability engine + pluggable adapters — v0.7 can add function-calling schemas / CrewAI / AutoGen / LangChain as drop-in adapters.
- The fingerprint seed (`gitexpose/agent_exposure/data/cl4r1t4s_fingerprints.json`) ships empty-but-valid; regenerate/expand it offline with `scripts/build_cl4r1t4s_fingerprints.py` against a local CL4R1T4S checkout.

## v0.5.1 — 2026-05-28 — Supply-Chain Intelligence (hardening)

### Fixed
- **Verification request amplification** — identical secrets gathered concurrently each fired an outbound auth request to the provider (the in-run dedup populated its cache only after the `await`). Now collapses to a single request per distinct secret via an await-once pattern. Also resolves cross-Python-version flakiness in the dedup test.
- **OSV robustness** — a malformed-but-200 OSV response (non-JSON body or unexpected shape) crashed the `supply-chain` scan instead of degrading to the curated list; per-batch and per-vuln parsing is now guarded (spec §9).
- **CI / Click ≥8.2 compatibility** — the v0.5 CLI/smoke tests used `CliRunner(mix_stderr=)`, which Click 8.2 removed (CI installs it on Python 3.10+); switched to `--no-verify-banner` so parsed stdout stays clean on every Click version.
- **Version-fragile test** — `test_status_is_string_enum` asserted the Python-3.12 `(str, Enum).__str__` output; now asserts the version-stable JSON-serialization contract.

### Security (hardening — focused /attack pass on the v0.5 egress surface)
- URL-encode OSV-provided vuln IDs before interpolating them into the hydration URL path.
- Cap total OSV vuln-hydration fan-out to `--osv-max` (a dependency with many advisories — or a hostile OSV — can no longer amplify into unbounded outbound requests).
- Skip lock files larger than 1 MB in `parse_all` (mirrors `LocalFilesystemScanner`).
- Clamp `--osv-max` (≥0) and `--osv-timeout` (≥0.1).

## v0.5.0 — 2026-05-28 — Supply-Chain Intelligence

### Added
- **Live dependency SCA** — lock-file parsing for Python (`requirements.txt`, `poetry.lock`, `Pipfile.lock`) and JavaScript (`package-lock.json`, `yarn.lock` v1 + Berry), enriched via OSV.dev live CVE/GHSA/malicious-package advisories. New `vulnerable_dependency` finding type (OWASP A06:2021 / CICD-SEC-3; AI middleware also keeps its ATLAS tag).
- **OSV.dev integration** (`gitexpose/supply_chain/osv.py`) — default on; sends only package **names + versions** (no secrets) to Google's OSV API via the batch endpoint (≤1000/request → bounded fan-out). `--offline` opt-out falls back to the curated known-bad list; any network failure degrades gracefully to that list rather than failing the scan. New flags: `--offline`, `--osv-timeout`, `--osv-max`.
- **CycloneDX 1.6 AI-BOM** (`-o cyclonedx`, alias `aibom`) — built with `cyclonedx-python-lib`; emits components (with PURLs + lock-file integrity hashes), dependency-vulnerability VEX, and NTIA minimum elements.
- **Exploitability-first ranking** — `vulnerable_dependency` findings are ordered by exploitability *context* (direct/transitive, fix-available, pinned, credential-co-presence) with CVSS only as a tiebreaker, per the "rank by proven-exploitable, not CVSS" discipline.
- **Honest VEX** — the BOM marks a vulnerability `exploitable` only when proven: a credential in the same source file was `--verify`-confirmed live, or OSV flags it known-exploited. Otherwise `in_triage`. We never assert `not_affected` (no reachability analysis). Self-contained CVSS v3.1 base-score computation (no external CVSS dependency).

### Changed
- New core dependencies: `cyclonedx-python-lib>=8.0.0` and `packageurl-python>=0.15.0` (both pure-Python); `tomli>=2.0.0` only on Python 3.9/3.10 (`tomllib` is stdlib on 3.11+).
- Test count grew from 287 (v0.4.0) to 325 (v0.5.0).
- Existing supply-chain regression tests now pass `--offline` so the suite makes no live network calls.

### Deferred to v0.6
- Classic typosquatting; lock-file poisoning checks (SRI/ghost-deps/off-registry URLs — data already captured); Shai-Hulud install-time behavioral analysis; Go/Cargo ecosystems.

## v0.4.0 — 2026-05-28 — Detection Depth

### Added
- **`gitexpose git-history <path>`** — scans all reachable git history (`git log -p --all --reverse`) for credentials committed and later removed, reusing the full credential matrix. Each secret is reported once at its earliest-introducing commit, with commit SHA / author / date. Composes with `--verify`: a historical secret can be reported `verified`/`dead`/`error` — "deleted N commits ago, confirmed live." Flags: `-o/--output`, `--out-file`, `--since`, `--max-commits`, and the `--verify*` family.
- **AI-supply-chain signature pack** (working-tree, via `supply-chain`):
    - `polyglot_file` (HIGH) — text-extension file whose leading bytes are a binary/executable/archive signature (ELF, PE, ZIP, PDF, Mach-O, gzip). Built-in magic-byte detection — no external dependency.
    - `skill_prompt_injection` (HIGH, LLM01) — hidden directives in instruction files (CLAUDE.md/AGENTS.md/.continue/…): "ignore previous instructions", exfil directives, system-prompt-reveal attempts.
    - `agent_config_malicious_content` (CRITICAL) — command/exfil payloads inside CrewAI/AutoGen/litellm configs.
    - `langgrinch_lc_key` (CRITICAL) — heuristic pattern for LangChain `lc-`-prefixed credentials (LangGrinch / CVE-2025-68664 context; upstream key format not authoritatively confirmed).
- **AWS access+secret pairing** — same-source `aws_access_key` + `aws_secret_key` findings are paired into `ACCESS:SECRET` so AWS keys now verify live (previously always ERROR). Applies to both `supply-chain --verify` and `git-history --verify`.
- Shared `add_verify_args` Click decorator (reused by `supply-chain` and `git-history`).

### Changed
- New OPTIONAL dependency: `python-magic>=0.4.27` (advanced extra; reserved for future richer format detection — the polyglot detector itself uses built-in magic bytes and needs no system lib).
- Test count grew from 251 (v0.3.0) to 287 (v0.4.0).
- Internal `_verify_input` (the paired AWS secret) is scrubbed from all command output.

### Fixed
- The v0.3 smoke-test fixture (`tests/fixtures/synthetic_repo_v03/.env`) was never tracked — the generic `.env` gitignore rule silently dropped it at commit time, so `test_smoke_v03` was red on clean checkouts. It is now tracked via a gitignore negation.

### Deferred to v0.5
- AI-BOM (`--format aibom`) structured security inventory
- Policy engine + tamper-evident audit log
- Unreachable/dangling-blob history walk (force-pushed-away secrets)
- Additional provider verifiers (Discord/Telegram/Twilio/SendGrid/Stripe)
- `--verify` on the web-scan path; capability/scope enumeration

## v0.3.0 — 2026-05-28 — Active Verification

### Added

- **Active Verification engine** (opt-in via `--verify`). 16 providers
  supported: OpenAI (3 variants), Anthropic, Groq, OpenRouter, Perplexity,
  xAI, Cerebras, Hugging Face, ElevenLabs, Pinecone, LangSmith (v2 + legacy),
  GitHub, GitLab, Docker Hub, Slack token, AWS (SigV4 `GetCallerIdentity`).
  Verification adds binary `verified` / `dead` / `error` status to each
  applicable finding.
- **`--verify` CLI flags** on the `supply-chain` command: `--verify`,
  `--verify-concurrency`, `--verify-timeout`, `--verify-only-severity`,
  `--no-verify-banner`.
- **Consent banner** printed to stderr when `--verify` is active. Names every
  destination host.
- **Verification surfaces in all reporters:** JSON (`verification_status`,
  `verification_detail`), SARIF (`properties.verification_status` + `tags`),
  HTML (color badge), CSV (two new columns), console (colored tag).
- **In-run dedup:** identical secrets in multiple files trigger only one
  verification call per scan.
- **Log-redaction safety net:** every verifier and engine path tested with a
  sentinel canary to guarantee no raw secret leaks to logs, stdout, stderr, or
  `verification_detail`.
- **Tier 3 provider patterns:** Helicone, Portkey, Voyage, Cohere, Modal
  (paired token), Runpod. Detection-only in v0.3; verification deferred to
  v0.4.
- **GitHub Actions sample workflow** at `.github/workflows/gitexpose-scan.yml`.
- **pre-commit hook config** at `.pre-commit-hooks.yaml`.
- **`docs/INTEGRATIONS_CICD.md`** — pipeline setup walkthrough.
- **`docs/INTEGRATIONS_CODE_SCANNING.md`** — GitHub Code Scanning setup +
  SARIF tag filtering.
- **`docs/MITRE_ATLAS_COVERAGE.md`** — per-detection ATLAS technique mapping.
- **README "Why this matters" section** linking to the CISA `Private-CISA`
  incident.

### Changed

- New runtime dependency: `httpx>=0.27.0`.
- New dev dependency: `respx>=0.21.0` for HTTP mocking in tests.
- Test count grew from 122 (v0.2.0) to 253 (v0.3.0).
- Project research notes now tracked under `docs/notes/`.
- `.gitignore` extended for workspace artifacts (`.serena/`, `RESEARCH/`,
  `files/`, root PNGs, `uv.lock`, `.venv/`).

### Fixed

- **`gitexpose/advanced/mcp_server.py`** — removed unsupported `validate=`
  kwarg from `SecretExtractor.extract()` call; fixed `.get("valid")` →
  `.get("validated")` typo; fixed broken `from .secret_extractor` import path.
  Regression test added.
- **`gitexpose/advanced/local_fs_scanner.py`** — `.env` dotfiles were silently
  skipped (`Path('.env').suffix` is empty); added `.env` to the bare-filename
  allowlist so supply-chain scans actually read `.env` files.
- **`github_token` verifier registration** — the scanner emits finding type
  `github_token` (not `github_pat`); registered the alias so GitHub tokens are
  actually liveness-checked.

### Deferred to v0.4

- Capability/scope enumeration (AWS IAM perms, GitHub PAT scopes, OpenAI
  org/project membership)
- AI-BOM (SPDX 3.0) output format
- Verifiers for Discord bot/webhook, Telegram, Twilio, SendGrid, Stripe (each
  needs case-by-case side-effect analysis)
- Tier 3 provider verification (need documented endpoint surfaces)
- Persistent cross-run verification cache
- Deep git-history traversal
- `--verify` on the web-scan command (cli.py:main produces URL findings, not
  extractable credentials)

## v0.2.0 — 2026-05-16 — Real-World Hardening

### Added

- **23-provider credential matrix.** Net-new patterns: Groq (`gsk_`), OpenRouter (`sk-or-`), xAI (`xai-`), Cerebras (`csk-`), Hugging Face (`hf_`), Replicate (`r8_`), Perplexity (`pplx-`), Pinecone (`pcsk_`), LangSmith (`lsv2_pt_`/`ls__`), ElevenLabs (context-bound), OpenAI extended (`sk-proj-`/`sk-svcacct-`), Anthropic (`sk-ant-`), Stripe `sk_test_`, GitLab (`glpat-`), Docker Hub (`dckr_pat_`), Discord bot, Discord webhook, Telegram bot, Twilio account SID. Existing v0.1 patterns retained.
- **OWASP LLM + MITRE ATLAS metadata** on every finding. Surfaced in JSON, SARIF, HTML, CSV, console.
- **SARIF 2.1.0 reporter** with MITRE ATLAS / OWASP LLM Top 10 taxonomy references.
- **`gitexpose supply-chain <path>` CLI subcommand** for local-filesystem supply-chain scanning.
- **TeamPCP supply-chain pack:**
    - `unpinned_ai_middleware` — HIGH severity for unpinned LLM SDKs
    - `known_malicious_package_version` — CRITICAL for `litellm==1.82.7/.8`, `telnyx==4.87.1/.2`, `xinference==2.6.{0,1,2}`, `gptplus`, `claudeai-eng`, `hermes-px`
    - `slopsquatting` — known LLM-hallucinated package names
    - `pth_persistence` — `.pth` file with `exec`/`eval`/`base64`
    - `ai_c2_beacon` — MITRE ATLAS AML.TA0015 (Command and Control via AI agent)
    - `kubernetes_exfiltration` — k8s secret enumeration patterns
- **Paired-secret cluster detection** (`credential_cluster`) — ≥2 distinct secret types in the same file.
- **Multi-provider-key file flagging** (`multi_provider_credential_file`) — clusters in known aggregator paths.
- **Empirical AI-tool config paths** for `.continue/`, `claude/.credentials.json`, MCP configs, .NET build output, `drizzle.config.ts`, CrewAI YAMLs, AutoGen `OAI_CONFIG_LIST`, LiteLLM configs, `.env.*.example` and `.env.*.bak` variants, Firebase configs.
- **`docs/COVERAGE.md`** — provider parity matrix.
- **End-to-end smoke test** (`tests/test_smoke_v02.py`) against `tests/fixtures/synthetic_repo/`.

### Changed

- Test count grew from 9 (v0.1.0) to 122 (v0.2.0).
- README and `docs/README_ADVANCED.md` honesty pass: removed claims for unimplemented features (ML engine, runtime monitoring, plugin architecture, web dashboard, package verification CLI, "65+ attacks", "triple-layer defense"). Aspirational features moved to clearly-labeled Roadmap sections. Tagline updated to "Exposure intelligence for AI and dev infrastructure".
- `gitexpose/data/credential_patterns_v02.json` is now packaged with the wheel (registered in `pyproject.toml` and `setup.py`).

### Fixed

- Pre-existing latent bugs surfaced and fixed as scope additions during v0.2 work:
    - `gitexpose/paths_extended.py:19` and `:899` — broken `from ..models` / `from ..paths` (both required `.` not `..`)
    - `gitexpose/advanced/__init__.py` — `CloudScanner` → `CloudAssetScanner` (wrong class name in import + `__all__`)
- `.gitignore` — added negations for `gitexpose/data/*.json` and `tests/fixtures/**/*.json` so corpus and fixtures are tracked

### Deferred to future releases

- ML detection engine, runtime monitoring proxy, plugin architecture, web dashboard, REST API, IDE plugins
- Live external threat-intelligence enrichment
- Full MITRE ATLAS coverage map document
- Audio steganography detection (Telnyx-class)
- Browser-agent misuse, multi-agent injection patterns
- Tier 3 providers: Helicone, Portkey, Voyage, Cohere, Modal, Runpod
- Pre-existing bug in `gitexpose/advanced/mcp_server.py:432` (extract `validate=` kwarg + `.get("valid")` typo) — out of v0.2 scope, address in v0.3
