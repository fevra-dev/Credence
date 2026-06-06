<div align="center">

# Credence

**Exposure intelligence for the AI-infrastructure layer**

*Finds and weighs leaked credentials, MCP and agent configs, git-metadata secrets, supply-chain risk, and CI/CD workflow threats — and tells you which exposures to trust.*

[![Version](https://img.shields.io/badge/version-0.9.0-blue.svg)](https://github.com/fevra-dev/Credence/releases)
[![Python](https://img.shields.io/badge/python-3.9--3.12-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-8a2be2.svg)](docs/INTEGRATIONS_CODE_SCANNING.md)
[![Compliance](https://img.shields.io/badge/tagged-OWASP%20LLM%20%C2%B7%20MITRE%20ATLAS%20%C2%B7%20ATT%26CK-red.svg)](docs/MITRE_ATLAS_COVERAGE.md)

[Why](#why-credence) · [Install](#installation) · [Quick start](#quick-start) · [Coverage](#detection-coverage) · [CI/CD](#cicd-integration) · [Docs](#documentation)

<sub>Formerly **GitExpose** — renamed to Credence at v0.8.1. `pip install credence-scan`; the CLI is `credence` (the old `gitexpose` command still works as a deprecated alias for one release).</sub>

</div>

---

## Why Credence

General secret scanners treat the AI stack as plain text. Credence reads it: **MCP server configs, agent skill files, `.claude/settings.json`, LiteLLM proxies, model/dataset pipelines, and git-metadata credentials** — the leak surfaces that emerged with the 2025–2026 AI-tooling explosion. Then it does what a scanner usually doesn't: it **weighs** each exposure — verifying whether a credential is *live*, scoring MCP posture, and flagging which secrets are rare private leaks versus scraped public noise.

| | Most secret scanners | **Credence** |
|---|---|---|
| **Finds credentials in code/history** | ✅ | ✅ |
| **Confirms a key is *live*** (opt-in verification) | sometimes | ✅ 16 providers |
| **AI-infra surfaces** (MCP, agent skills, model cards) | text-only | ✅ structural |
| **Git-metadata creds** (`.git/config`, `.gitmodules`, `extraHeader`) | ✗ | ✅ |
| **CI/CD workflow threats** (poisoned pipelines, over working tree *and* git history) | ✗ | ✅ |
| **Excessive-agency / MCP posture scoring** | ✗ | ✅ 0–100 |
| **Orphan-signal triage** (rare leak vs public noise) | ✗ | ✅ |
| **Compliance tagging** (OWASP LLM · ATLAS · ATT&CK) | ✗ | ✅ every finding |
| **SARIF 2.1.0 + cross-tool dedup fingerprints** | partial | ✅ |

Built to run **alongside** general scanners in CI, not replace them.

---

## Why this matters

In May 2026, KrebsOnSecurity and GitGuardian reported on a public GitHub repository named `Private-CISA` — created by a contractor in November 2025, it held 844 MB of operational material: CI/CD logs, Kubernetes manifests, Terraform, internal docs, AWS GovCloud admin credentials, and plaintext passwords for internal systems.

That is the threat model. GitHub is the production perimeter, and one careless commit can publish keys, infrastructure maps, and operational secrets to attackers who never needed a zero-day. Credence is built to catch those exposures **and tell you which ones are actually live and reachable** — instead of drowning a responder in unranked "looks-like-a-key" noise.

---

## Capabilities

| Capability | What it does | Since |
|---|---|---|
| **Credential detection** | 29-pattern matrix across 23+ providers (OpenAI, Anthropic, AWS, GitHub, Stripe, Hugging Face, Slack, DB strings, …) with context-bound patterns and paired-secret cluster detection | v0.1+ |
| **Active verification** (`--verify`) | Confirms a key is **live** via a side-effect-free auth check — covers 16 providers (LLM tier + GitHub/GitLab/Docker Hub/Slack/AWS SigV4) | v0.3 |
| **Git-history scanning** | Scans all reachable commits for committed-then-removed secrets; reports each at its earliest-introducing commit (SHA/author/date); composes with `--verify` | v0.4 |
| **Live dependency SCA** | Lock-file parsing + OSV.dev CVE/GHSA lookups, ranked by **exploitability context** (direct/unpinned/fix-available/credential co-presence), not raw CVSS | v0.5 |
| **AI-BOM** | CycloneDX 1.6 security BOM with dependency VEX (honestly scoped) and NTIA minimum elements | v0.5 |
| **AI agent exposure** (`agent-audit`) | Flags over-permissioned agents — MCP shell/exec wiring, `.claude` grants like `Bash(*)`, function-calling tool schemas, exfil-capable capability chains; detects leaked system prompts | v0.6–v0.7 |
| **AI-infra layer, deepened** | Git-metadata credentials · agent debug-print leaks (AST) · MCP posture score (0–100) · orphan cross-source signal · `--fail-on` severity gate | v0.8 |
| **Workflow-threat engine** (`workflow-audit`) | 13 rules for GitHub Actions poisoned-pipeline patterns — runtime-decoded exec, secret exfil, `$GITHUB_ENV` injection, blast-radius (self-hosted/artipacked/secrets-inherit) — scanned over the working tree **and** full git history; `--include-unreachable` sweeps dangling commits; identity-as-context; SARIF 2.1.0 | v0.9 |
| **Compliance metadata** | OWASP LLM Top 10 + MITRE ATLAS + MITRE ATT&CK technique on **every** finding | v0.2+ |
| **Outputs** | console · JSON · CSV · HTML · **SARIF 2.1.0** (GitHub Code Scanning) · CycloneDX | — |

See **[docs/COVERAGE.md](docs/COVERAGE.md)** for the full provider + finding-type matrix.

---

## Installation

```bash
# From a release wheel (recommended)
pip install credence-scan            # core
pip install "credence-scan[advanced]"   # + local supply-chain / agent-audit / MCP modules

# From source
git clone https://github.com/fevra-dev/Credence.git
cd Credence
pip install -e ".[advanced]"
```

**Requirements:** Python 3.9–3.12. Core is stdlib + `aiohttp`/`click`/`httpx`/`PyYAML`; the `advanced` extra adds local-filesystem scanning, git-history, and the MCP server.

---

## Quick Start

```bash
# Web target — scan for exposed .git, .env, backups, configs
credence example.com
credence -f targets.txt -o json --out-file results.json

# Local repository — supply-chain + secrets + git-metadata, with live SCA (OSV.dev)
credence supply-chain ./my-project
credence supply-chain ./my-project --offline          # air-gapped: skip network
credence supply-chain ./my-project --verify           # confirm which creds are LIVE

# Audit AI-agent configs — excessive permissions, MCP posture, leaked prompts
credence agent-audit ./my-project

# Audit GitHub Actions workflows for poisoned-pipeline threats (working tree + history)
credence workflow-audit ./my-project

# Scan all git history for committed-then-removed secrets, verify which are still live
credence git-history . --verify
```

**v0.9 highlights**

```bash
# Detect poisoned pipelines in working tree + full git history (deletion ≠ erasure)
credence workflow-audit ./repo

# Include dangling/deleted-branch commits; export SARIF for GitHub Code Scanning
credence workflow-audit ./repo --include-unreachable --format sarif -o workflow.sarif

# CI gate: exits 1 on HIGH/CRITICAL workflow threats; trust known CDN egress
credence workflow-audit ./repo --allow-host cdn.example.com --fail-on high
```

**v0.8 highlights**

```bash
# Emit SARIF with cross-tool dedup fingerprints + orphan cross-source signal
credence supply-chain ./repo --output sarif --track --out-file credence.sarif

# CI gate: only HIGH/CRITICAL fail the build by default; --fail-on info = "any finding fails"
credence agent-audit ./repo --fail-on high

# Export a CycloneDX 1.6 AI-BOM (components + dependency VEX + NTIA elements)
credence supply-chain ./repo -o cyclonedx --out-file sbom.cdx.json
```

### Example output

```text
$ credence agent-audit ./repo

🤖 3 agent-exposure finding(s) in ./repo:
  [HIGH] mcp_static_credential  (mcp.json)
     MCP server 'analytics' embeds a static credential in its env block.
     📋 OWASP LLM08 Excessive Agency · ATLAS AML.T0053 · ATT&CK T1552
  [HIGH] agent_skill_credential_print  (skills/loader.py)
     Debug print/log broadcasts a credential-named variable to stdout/logs.
     📋 OWASP LLM06 · ATLAS AML.T0019
  [INFO] mcp_server_posture  (mcp.json)
     MCP server 'analytics' posture score 50/100 (−30 static credential; −20 plaintext http).
```

---

## Detection Coverage

- **29 credential patterns across 23+ providers** spanning LLM/AI, RAG/vector DB, observability, cloud, payment, comms, and DB connection strings — with context-bound patterns where prefix matching is insufficient.
- **Git-metadata credentials** — tokens in `.git/config` / `.gitmodules` remote URLs and `[url] insteadOf` rewrites, Azure DevOps `extraHeader` PATs (Basic/Bearer/token). Structural `configparser` parsing — **never invokes git** (CVE-2025-41390-safe).
- **AI agent exposure** — MCP servers wired to shell/exec, `.claude` permission grants, function-calling tool schemas, exfil-capable capability chains; MCP posture scoring (0–100) with decoupled per-issue findings.
- **Supply-chain** — unpinned AI middleware, known-malicious versions (TeamPCP), slopsquatting, `.pth` persistence, agent C2 beacons, polyglot files, prompt injection in instruction files, live OSV.dev SCA.
- **Orphan cross-source signal** — a hash-only registry (raw values never persisted) tags each secret `orphan_candidate`…`replicated` and emits SARIF `partialFingerprints` for cross-tool dedup.

Every finding carries **OWASP LLM Top 10 + MITRE ATLAS + MITRE ATT&CK** metadata. Full matrix: **[docs/COVERAGE.md](docs/COVERAGE.md)** · ATLAS map: **[docs/MITRE_ATLAS_COVERAGE.md](docs/MITRE_ATLAS_COVERAGE.md)**.

---

## CI/CD Integration

Credence emits **SARIF 2.1.0** for GitHub Code Scanning and provides a sample workflow + pre-commit hook.

```yaml
# .github/workflows/credence-scan.yml (sample included in repo)
- run: pip install ".[advanced]"
- run: credence supply-chain . --offline -o sarif --out-file credence.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: credence.sarif }
```

The `--fail-on {info,low,medium,high,critical}` gate controls the exit code (default `high`), so cosmetic findings don't break the build while real ones do. Guides: **[CI/CD](docs/INTEGRATIONS_CICD.md)** · **[Code Scanning](docs/INTEGRATIONS_CODE_SCANNING.md)**.

---

## Architecture

```
credence/
├── scanner.py              # async HTTP web-target scanner
├── signatures.py           # response validation (low-FP)
├── secrets/                # 29-provider credential extraction
├── verification/           # opt-in live-credential checks (16 providers)
├── git_history/            # all-reachable-commit secret scanning
├── supply_chain/           # lock-file SCA + OSV.dev + CycloneDX AI-BOM
├── agent_exposure/         # MCP/agent excessive-agency + posture + debug-print
├── workflow_audit/         # GitHub Actions poisoned-pipeline rules + git-history forensics
├── advanced/               # git-metadata, ML-model, LLM-exposure, MCP server, orphan registry
└── reporters/              # console · JSON · CSV · HTML · SARIF · CycloneDX
```

Design principles: **precision over recall** (every finding type ships with a fixture corpus), **fail-closed gating**, and **honest scoping** (the tool says what it can't scan rather than silently skipping). 561 tests, green across Python 3.9–3.12.

---

## Responsible Use

Credence is a **defensive** security tool for auditing systems you own or are authorized to test. Active verification (`--verify`) sends authentication probes to provider APIs and is **opt-in**, printing a consent banner before running. Do not scan targets without authorization.

---

## Research Basis

Detection logic is grounded in current research and disclosed incidents, including: USENIX 2025 (slopsquatting / LLM-hallucinated packages), arXiv:2604.03070 (agent-skill credential leakage), CVE-2025-55182 (React2Shell), CVE-2025-68664 (LangGrinch / LangChain memory poisoning), CVE-2025-41390 (malicious `.git/config` RCE), the TeamPCP supply-chain campaign, and the May 2026 CISA contractor leak.

---

## Documentation

| Doc | Contents |
|---|---|
| [COVERAGE.md](docs/COVERAGE.md) | Full provider + finding-type detection matrix |
| [USAGE.md](docs/USAGE.md) | Install, configure, and run |
| [README_ADVANCED.md](docs/README_ADVANCED.md) | Advanced modules + MCP server |
| [INTEGRATIONS_CICD.md](docs/INTEGRATIONS_CICD.md) | GitHub Actions + pre-commit |
| [INTEGRATIONS_CODE_SCANNING.md](docs/INTEGRATIONS_CODE_SCANNING.md) | SARIF → GitHub Code Scanning |
| [MITRE_ATLAS_COVERAGE.md](docs/MITRE_ATLAS_COVERAGE.md) | ATLAS technique mapping |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

---

## License

MIT — see [LICENSE](LICENSE).
