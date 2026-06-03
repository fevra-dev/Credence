# Credence Detection Coverage

Last updated: v0.7

Credence detects credential exposure across **23 providers** in 5 categories, plus supply-chain risk indicators specific to AI infrastructure, AI-agent exposure (excessive tool permissions + leaked system prompts), and — as of v0.8 — git-metadata credentials, agent debug-print leaks, MCP security posture scoring, and a cross-source orphan signal (see [AI-infra layer, deepened (v0.8)](#ai-infra-layer-deepened-v08)). Each finding carries OWASP LLM Top 10 (`attack_class`) and MITRE ATLAS technique (`atlas_technique`) metadata; agent-exposure findings additionally carry a MITRE ATT&CK technique (`mitre_attack`).

## Credential providers

### LLM and AI providers

| Provider | Pattern | Severity | Source |
|---|---|---|---|
| OpenAI | `sk-…`, `sk-proj-…`, `sk-svcacct-…` | CRITICAL | v0.1 + v0.2 |
| Anthropic | `sk-ant-…` | CRITICAL | v0.2 |
| Google AI / Firebase | `AIzaSy…` | CRITICAL | v0.1 |
| Groq | `gsk_…` | CRITICAL | v0.2 |
| OpenRouter | `sk-or-…` | CRITICAL | v0.2 |
| xAI (Grok) | `xai-…` | CRITICAL | v0.2 |
| Cerebras | `csk-…` | CRITICAL | v0.2 |
| Hugging Face | `hf_…` | CRITICAL | v0.2 |
| Replicate | `r8_…` | CRITICAL | v0.2 |
| Perplexity | `pplx-…` | CRITICAL | v0.2 |
| ElevenLabs | 32-hex (context-bound) | CRITICAL | v0.2 |
| Voyage AI | `pa-…` | CRITICAL | v0.3 |
| Cohere | `co-…` | CRITICAL | v0.3 |

### RAG / Vector DB

| Provider | Pattern | Severity | Source |
|---|---|---|---|
| Pinecone | `pcsk_…` | CRITICAL | v0.2 |

### LLM observability

| Provider | Pattern | Severity | Source |
|---|---|---|---|
| LangSmith | `lsv2_pt_…` and `ls__…` | CRITICAL | v0.2 |
| Helicone | `sk-helicone-…` | HIGH | v0.3 |
| Portkey | `PORTKEY_API_KEY=…` (context-bound) | HIGH | v0.3 |

### LLM infrastructure

| Provider | Pattern | Severity | Source |
|---|---|---|---|
| Modal | `ak-…` (token ID) + `as-…` (token secret) | CRITICAL | v0.3 |
| Runpod | `RUNPOD_API_KEY=…` (context-bound) | HIGH | v0.3 |

### Code, cloud, payment

| Provider | Pattern | Severity | Source |
|---|---|---|---|
| AWS | `AKIA…` + secret-key context | CRITICAL | v0.1 |
| GitHub PAT | `ghp_…`, `ghs_…` | CRITICAL | v0.1 |
| GitLab PAT | `glpat-…` | CRITICAL | v0.2 |
| Docker Hub | `dckr_pat_…` | CRITICAL | v0.2 |
| Stripe | `sk_live_…`, `rk_live_…`, `sk_test_…` | CRITICAL/HIGH | v0.1 + v0.2 |

### Communication

| Provider | Pattern | Severity | Source |
|---|---|---|---|
| Discord (bot) | `M…\..\..` | CRITICAL | v0.2 |
| Discord (webhook) | `discord.com/api/webhooks/…` | HIGH | v0.2 |
| Slack (token) | `xox[baprs]-…` | CRITICAL | v0.1 |
| Slack (webhook) | `hooks.slack.com/services/…` | HIGH | v0.1 |
| Telegram (bot) | `\d{8,10}:[\w-]{35}` | HIGH | v0.2 |

### Notifications

| Provider | Pattern | Severity | Source |
|---|---|---|---|
| Twilio | `AC[a-f0-9]{32}` | HIGH | v0.2 |
| SendGrid | `SG.…` | HIGH | v0.1 |

### Database connection strings

| Type | Pattern | Severity | Source |
|---|---|---|---|
| PostgreSQL | `postgres(?:ql)?://user:pass@…` | HIGH | v0.1 |
| MySQL | `mysql://user:pass@…` | HIGH | v0.1 |
| MongoDB Atlas | `mongodb(\+srv)?://user:pass@…` | HIGH | v0.1 |

### Generic

| Type | Pattern | Severity | Source |
|---|---|---|---|
| Private key (PEM) | `-----BEGIN…PRIVATE KEY-----` | CRITICAL | v0.1 |
| JWT token | `eyJ…\.eyJ…\..*` | HIGH | v0.1 |
| Generic API key | `(api[_-]?key|apikey)["']?\s*[:=]\s*["']…["']` | MEDIUM | v0.1 |

## Supply-chain detection (v0.2)

| Detection | Severity | Description |
|---|---|---|
| `unpinned_ai_middleware` | HIGH | AI middleware (litellm, langchain, openai, anthropic, etc.) without `==` pin |
| `known_malicious_package_version` | CRITICAL | Pinned to a known-compromised version (e.g., `litellm==1.82.7`) |
| `slopsquatting` | CRITICAL | Package name from the LLM-hallucination corpus (e.g., `huggingface-cli`) |
| `pth_persistence` | CRITICAL | `.pth` file with `exec`/`eval`/`base64` (TeamPCP technique) |
| `ai_c2_beacon` | CRITICAL | Skill instructs AI agent to operate as C2 implant (ATLAS AML.TA0015) |
| `kubernetes_exfiltration` | CRITICAL | Kubernetes secret enumeration / service-account token access |
| `credential_cluster` | CRITICAL | ≥2 distinct secret types co-occur in same file |
| `multi_provider_credential_file` | CRITICAL | Cluster appears in known aggregator path (`OAI_CONFIG_LIST`, `litellm_config.yaml`, `.continue/agents/*.yaml`) |

## AI-supply-chain signature pack (v0.4)

Four new working-tree detections added to `supply-chain` scanning:

| Detection | Severity | Description |
|---|---|---|
| `polyglot_file` | HIGH | A text-extension file (`.md`, `.yaml`, `.json`, etc.) whose leading bytes match a binary/executable/archive magic signature (ELF, PE/MZ, ZIP, PDF, Mach-O, gzip). Detection uses **built-in magic-byte matching** — no external dependency (python-magic / libmagic not required). |
| `skill_prompt_injection` | HIGH | Hidden directives found in AI-agent instruction files (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, files under `.continue/` or `.cursor/`): "ignore previous instructions", exfiltration directives, or system-prompt-reveal attempts. OWASP LLM01. |
| `agent_config_malicious_content` | CRITICAL | Embedded command or exfiltration payloads (`curl\|bash`, `exec`/`eval`) inside CrewAI, AutoGen, or litellm config files. |
| `langgrinch_lc_key` | CRITICAL | Heuristic detection of LangChain `lc-`-prefixed API keys. **Best-effort pattern** — the exact upstream key format is not authoritatively confirmed; pattern is motivated by CVE-2025-68664 (LangGrinch credential-theft chain) and should be treated as a high-signal lead requiring manual confirmation. |

## AWS access+secret pairing (v0.4)

When `supply-chain --verify` (or `git-history --verify`) detects both an `aws_access_key` and an `aws_secret_key` from the same source, Credence now pairs them and performs a live `sts:GetCallerIdentity` (SigV4) liveness check. Previously, AWS findings always surfaced as `error` at verification time because the secret component was unavailable. Pairing is applied automatically — no additional flags are required.

## Live dependency SCA (v0.5)

`supply-chain` parses lock files and queries OSV.dev for live vulnerability intelligence (default on; `--offline` falls back to the curated list).

| Lock-file format | Ecosystem |
|---|---|
| `requirements.txt` (== pins), `poetry.lock`, `Pipfile.lock` | PyPI |
| `package-lock.json` (v2/v3), `yarn.lock` (v1 + Berry) | npm |

| Finding type | Severity | Description |
|---|---|---|
| `vulnerable_dependency` | CVSS-mapped (CRITICAL/HIGH/MEDIUM/LOW) | A resolved dependency matched a live OSV CVE/GHSA/MAL advisory. Carries `vuln_id`, `fixed_version`, `direct`, `pinned`, `cred_co_present`, `known_exploited`. Mapped to **OWASP A06:2021 (Vulnerable & Outdated Components) / CICD-SEC-3**; AI middleware additionally keeps `AML.T0019`. |

Findings are ranked by **exploitability context** (credential-co-presence → known-exploited → direct → unpinned → fix-available → severity → CVSS), not raw CVSS. The CycloneDX 1.6 AI-BOM (`-o cyclonedx`) carries these as VEX entries; `analysis.state` is `exploitable` only when a co-present credential is `--verify`-confirmed live or OSV flags it known-exploited, else `in_triage`.

## AI agent exposure (v0.6–v0.7)

`credence agent-audit <path>` judges *what an AI agent is allowed to do* and detects committed/leaked system prompts. Pure static analysis — no network calls.

**Grant sources parsed** (via pluggable adapters — filename dispatch + v0.7 shape dispatch):

| Format family | Files | What's extracted |
|---|---|---|
| MCP server configs | `mcp.json`, `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json` | per-server launch `command` + `args` (folded into evidence), `env` passthrough keys |
| Claude-Code permission lists | `.claude/settings.json`, `.claude/settings.local.json` | `permissions.allow` entries (a matching `deny` neutralizes one) |
| Function-calling tool schemas (v0.7) | any `.json`/`.yaml`/`.yml` matching the OpenAI/Anthropic `tools[]` shape | each tool's **name** (classified by name; free-form descriptions never inspected — low-FP) |

**Output formats:** `console`, `json`, and **`sarif`** (v0.7 — SARIF 2.1.0 for GitHub Code Scanning, carrying the OWASP/ATLAS/ATT&CK triple).

**Dangerous-capability taxonomy** — each grant is classified into zero or more classes; a benign grant (read-only docs server, no wildcard) produces no finding:

| `capability_class` | Base severity | MITRE ATT&CK |
|---|---|---|
| `shell_exec` | CRITICAL | `T1059` Command & Scripting Interpreter |
| `code_eval` | HIGH | `T1059.006` (Python) |
| `secret_access` | HIGH | `T1552` Unsecured Credentials |
| `network_fetch` | HIGH | `T1071.001` Web Protocols |
| `filesystem_write` | MEDIUM | `T1105` Ingress Tool Transfer |
| `database` | MEDIUM | `T1213` Data from Information Repositories |
| `browser_control` | MEDIUM | `T1185` Browser Session Hijacking |
| `unrestricted` (explicit `*` / `Bash(*)`) | CRITICAL | `T1059` (posture) |

**Escalation** — when execution (`shell_exec`/`code_eval`) co-occurs with egress (`network_fetch`/`secret_access`) in the same config, an extra CRITICAL `exfil_capable_agent` finding is emitted with an `exfil_chain` and `exfil_attack: T1041` (Exfiltration Over C2 Channel).

| Finding type | Severity | Description |
|---|---|---|
| `excessive_agent_capability` | per taxonomy (CRITICAL/HIGH/MEDIUM) | An agent is granted a dangerous tool/capability. OWASP **LLM08** Excessive Agency; ATLAS **AML.T0053** AI Agent Tool Invocation; per-class `mitre_attack`. |
| `exposed_system_prompt` | HIGH | Committed text matches a CL4R1T4S known-leaked system prompt (shingle-fingerprint overlap; hashes only, no prompt text vendored). OWASP **LLM07** System Prompt Leakage; ATLAS **AML.T0056** LLM Meta Prompt Extraction; `mitre_attack: T1552.001`. |

The fingerprint seed (`credence/agent_exposure/data/cl4r1t4s_fingerprints.json`) ships empty-but-valid; expand it offline with `scripts/build_cl4r1t4s_fingerprints.py` against a local CL4R1T4S checkout.

## AI-infra layer, deepened (v0.8)

**Git-metadata credentials** (in `supply-chain`) — structural `.git/config` / `.gitmodules` parsing via `configparser` only; **never invokes git** (CVE-2025-41390-safe — a malicious `core.fsmonitor` is never executed).

| Finding type | Severity | Description |
|---|---|---|
| `git_config_credential_url` | CRITICAL | Provider-prefix token (`ghp_`/`github_pat_`/`ghs_`/`glpat-`/`hf_`) embedded in a `[remote] url =`. Persists in git metadata across clone/package ops. OWASP **LLM06** / ATLAS **AML.T0012**. |
| `git_config_extraheader_credential` | HIGH | Azure DevOps Basic-auth PAT in `[http] extraHeader = AUTHORIZATION: Basic <base64>` (base64-decoded then matched). OWASP **LLM06** / ATLAS **AML.T0012**. |
| `gitmodules_credential_url` | CRITICAL / LOW | Credential-bearing submodule URL in committed `.gitmodules` (`committed_to_history`). CRITICAL for provider-prefix tokens (`ghp_`/`glpat-`/`hf_`…), LOW for a generic `user:pass@host` URL. OWASP **LLM06** / ATLAS **AML.T0012**. |
| `git_config_generic_token_url` | LOW | Generic `user:password@host` remote URL with no recognized prefix — manual-verify. OWASP **LLM06** / ATLAS **AML.T0012**. |

**Agent debug-print** (in `agent-audit`) — AST-based, stdlib `ast` only.

| Finding type | Severity | Description |
|---|---|---|
| `agent_skill_credential_print` | HIGH | `print()`/`logging.<level>()` of a credential-named **variable** (not a string literal; f-strings supported) in agent/skill/tool Python — leaks the secret to stdout/logs/context. OWASP **LLM06** / ATLAS **AML.T0019**. |

**MCP security posture** (in `agent-audit`) — decoupled: per-issue findings gate CI, the INFO summary carries the score.

| Finding type | Severity | Description |
|---|---|---|
| `mcp_static_credential` | HIGH | Static credential embedded in an MCP server `env` block (env-var passthrough `${VAR}` is **not** flagged). OWASP **LLM08** / ATLAS **AML.T0053**. |
| `mcp_plaintext_http` | HIGH | MCP server URL is plaintext `http://`. OWASP **LLM08** / ATLAS **AML.T0053**. |
| `mcp_unknown_origin` | LOW | MCP server origin not in the known-good registry. OWASP **LLM08** / ATLAS **AML.T0053**. |
| `mcp_unpinned_version` | LOW | MCP server has no pinned version (supply-chain drift). OWASP **LLM08** / ATLAS **AML.T0053**. |
| `mcp_server_posture` | INFO | 0-100 posture score + deduction breakdown per server (informational; never gates). OWASP **LLM08** / ATLAS **AML.T0053**. |

**Orphan cross-source signal** (in `supply-chain`, opt-in `--track` / `--registry`) — a hash-only `SecretRegistry` (SHA256; raw values never persisted) annotates each secret finding **that carries a raw value** with `source_frequency` (`orphan_candidate` / `low` / `moderate` / `high` / `replicated`) and a `secret_value_hash`. (Git-metadata findings carry only a masked token, so they are intentionally not fingerprinted — there is no raw value to hash, and a masked string would not dedup against another tool anyway.) The hash is emitted as SARIF `partialFingerprints["secretValueHash/v1"]` for cross-tool dedup (run alongside TruffleHog); known example keys (e.g. `AKIAIOSFODNN7EXAMPLE`) are downgraded to INFO. This is enrichment metadata on existing secret findings, not a new finding type.

**Exit gating** — new `--fail-on {info,low,medium,high,critical}` (default `high`) on `supply-chain` / `agent-audit` / `git-history`. **Output** — `supply-chain` adds `-o sarif`.

## Empirical AI-tool config paths (v0.2)

Credence scans for these paths during URL/HTTP scans (where the path is exposed) and during local filesystem scans:

- `.continue/`, `.continue/agents/*.yaml`, `.continue/config.yaml`
- `claude/.credentials.json`
- `**/litellm*config*.{yaml,yml,md}`
- `mcp.json`, `.cursor/mcp.json`, `**/@config.json.md`
- `**/bin/Debug/**/appsettings*.json`, `**/bin/Release/**/appsettings*.json`
- `drizzle.config.ts`
- `agents.yaml`, `tasks.yaml`, `crew.yaml` (CrewAI)
- `OAI_CONFIG_LIST` (AutoGen)
- `**/.env.*.example`, `**/.env.bak`, `**/.env.*.bak`
- `firebase-config.{js,ts}`

## Git history scanning (v0.4)

`credence git-history <path>` scans **all reachable commits** (`git log -p --all --reverse`) for credentials that were committed and later removed — secrets that no longer appear in the working tree but remain accessible in repository history and may still be live.

Key behaviours:

- **Full credential matrix** — the same 29-provider pattern set used by `supply-chain` applies to every diff hunk.
- **Deduplicated to earliest introduce** — each distinct secret value is reported once, at the commit that first introduced it, to avoid alert noise from long-lived secrets touched by many commits.
- **Commit metadata** — every finding carries the introducing commit SHA, author, and date.
- **Composes with `--verify`** — pass `--verify` (plus the `--verify*` family flags) and historical secrets go through the same liveness-check path as working-tree findings. A typical result: "deleted 47 commits ago, confirmed live."
- **AWS pairing** — the same access+secret pairing introduced in v0.4 applies here, so AWS keys found in history can also be verified.
- **Flags**: `-o/--output {console,json}`, `--out-file`, `--since <date>`, `--max-commits <n>`, plus the full `--verify` family (`--verify-only-severity`, `--verify-timeout`, `--verify-concurrency`).

## Verification status

**Verification status (v0.4):** Tier 1–2 providers (OpenAI, Anthropic, Groq, OpenRouter, Perplexity, xAI, Cerebras, Hugging Face, ElevenLabs, Pinecone, LangSmith, GitHub, GitLab, Docker Hub, Slack token, AWS) support `--verify` for live/dead status. AWS liveness checks now work reliably via access+secret pairing (v0.4). Tier 3 (Helicone, Portkey, Voyage, Cohere, Modal, Runpod) remain detection-only.

## Compliance taxonomies

Every finding includes:

- **`attack_class`** — OWASP LLM Top 10 ID (`LLM05` Supply Chain, `LLM06` Sensitive Info Disclosure, `LLM07` System Prompt Leakage, `LLM08` Excessive Agency, etc.)
- **`atlas_technique`** — MITRE ATLAS technique ID (e.g., `AML.T0019`, `AML.TA0015`, `AML.T0053`, `AML.T0056`)
- **`mitre_attack`** (v0.6, agent-exposure findings) — MITRE ATT&CK technique ID (e.g., `T1059`, `T1552`, `T1071.001`, `T1041`)

These appear in JSON, SARIF (as taxonomy references), HTML (badges), CSV (columns), and console output.

The basis for new patterns and paths is public threat intelligence and real-world leak observations. No external service is queried at scan time.
