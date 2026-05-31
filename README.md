# GitExpose

<div align="center">

![Version](https://img.shields.io/badge/version-0.7.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.9+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

**Exposure intelligence for AI and dev infrastructure**

*Detect leaked credentials, exposed AI-tool configs, and supply-chain risk in the 2026 threat landscape*

[Features](#features) • [Installation](#installation) • [Quick Start](#quick-start) • [Coverage](docs/COVERAGE.md) • [Documentation](#documentation)

</div>

---

## Overview

GitExpose finds exposed credentials, sensitive AI-infrastructure configs, and supply-chain compromise indicators across web targets and local repositories.

| Threat Category | What's Detected |
|-----------------|-----------------|
| **Credential exposure** | 29-provider matrix: OpenAI, Anthropic, Google, Groq, xAI, Hugging Face, Replicate, Perplexity, Pinecone, LangSmith, Stripe, GitHub, GitLab, Docker Hub, Discord, Slack, Telegram, Twilio, SendGrid, AWS, ElevenLabs, Helicone, Portkey, Voyage, Cohere, Modal, Runpod, plus DB connection strings |
| **Active verification** (v0.3) | Opt-in `--verify` confirms whether a detected credential is **live** by sending a side-effect-free auth check to the provider — covers 16 providers (LLM tier + GitHub/GitLab/Docker Hub/Slack/AWS) |
| **Git history scanning** (v0.4) | `git-history` scans all reachable commits for credentials committed and later removed — still in history, often still live. Each secret reported once at its earliest-introducing commit with SHA/author/date. Composes with `--verify`. |
| **Exposed AI-tool configs** | `.continue/`, `claude/.credentials.json`, MCP configs, LiteLLM proxy configs, CrewAI/AutoGen YAMLs, .NET appsettings build output |
| **Supply-chain risk** | Unpinned AI middleware, known-malicious package versions (TeamPCP), slopsquatting, `.pth` persistence, AI agent C2 beacons, k8s exfiltration, polyglot files, prompt injection in agent instruction files, malicious agent config payloads |
| **Live dependency SCA** (v0.5) | Lock-file parsing (Python `requirements`/`poetry.lock`/`Pipfile.lock`, JS `package-lock.json`/`yarn.lock`) + OSV.dev live CVE/GHSA lookups → `vulnerable_dependency` findings, ranked by **exploitability context** (direct/unpinned/fix-available/credential-co-presence), not raw CVSS. Default on; `--offline` for air-gapped use. |
| **AI-BOM** (v0.5) | CycloneDX 1.6 security BOM (`-o cyclonedx`) with components, dependency-vulnerability VEX (honestly scoped — `exploitable` only when proven), and NTIA minimum elements. |
| **AI agent exposure** (v0.6–v0.7) | `agent-audit` flags over-permissioned AI agents — MCP servers wired to shell/exec, `.claude` permission grants like `Bash(*)`/`WebFetch`, **function-calling tool schemas** (OpenAI/Anthropic `tools[]`, v0.7), and exfil-capable capability chains (OWASP LLM08 / ATLAS AML.T0053 / ATT&CK T1059…) — and detects committed system prompts matching CL4R1T4S known-leak fingerprints (OWASP LLM07 / AML.T0056). Console/JSON/**SARIF** output (v0.7 SARIF → GitHub Code Scanning). |
| **Compliance metadata** | OWASP LLM Top 10 + MITRE ATLAS + MITRE ATT&CK technique on every finding |
| **HTTP target scanning** | `.git`, `.env`, source maps, framework misconfigs, exposed configs |

See [docs/COVERAGE.md](docs/COVERAGE.md) for the full matrix.

---

## Why this matters

In May 2026, KrebsOnSecurity and GitGuardian reported on a public GitHub
repository named `Private-CISA`. The repo, created by a CISA contractor in
November 2025, contained 844 MB of operational material: CI/CD logs,
Kubernetes manifests, Terraform code, GitHub workflows, internal docs, AWS
GovCloud admin credentials, and plaintext passwords for internal systems.

This is the threat model GitExpose is built for. GitHub is the production
perimeter, and one careless commit can publish keys, infrastructure maps, and
operational secrets to attackers who never needed a zero-day.

GitExpose v0.3 adds **active credential verification** — instead of just
flagging that a string looks like an OpenAI key or an AWS access key, it
confirms whether that credential is live by sending a low-footprint
authentication check to the provider. Live keys get flagged as `verified-live`
in SARIF output and surface as the highest-confidence alerts in GitHub Code
Scanning.

References:
- [KrebsOnSecurity: CISA contractor leak](https://krebsonsecurity.com/) (May 2026)
- [GitGuardian incident analysis](https://blog.gitguardian.com/)

---

## Features

### Core Scanning
- **Async HTTP** with configurable concurrency (50-100+ requests)
- **Signature validation** to reduce false positives
- **Multiple outputs**: console, JSON, CSV, HTML, **SARIF 2.1.0**
- **OWASP LLM + MITRE ATLAS metadata** on every finding

### Credential Detection (`gitexpose ...`)
- 23-provider regex matrix with context-bound patterns where needed
- Paired-secret cluster detection: when ≥2 distinct secret types appear in the same file, GitExpose emits a single CRITICAL `credential_cluster` finding
- Multi-provider-key file flagging: known aggregator paths (`OAI_CONFIG_LIST`, `litellm_config.yaml`, `.continue/agents/*.yaml`) get a CRITICAL multi-provider finding when ≥2 secret types are present

### Local Supply-Chain Scanning (`gitexpose supply-chain <path>`)
- Unpinned AI middleware (`litellm`, `langchain`, `openai`, etc.) flagged HIGH
- Known-malicious package versions corpus (TeamPCP/LiteLLM, Telnyx, Xinference, etc.)
- Slopsquatting detection — known LLM-hallucinated package names (USENIX 2025 research basis)
- `.pth` persistence pattern (TeamPCP-class post-compromise indicator)
- AI-agent C2 beacon detection (MITRE ATLAS AML.TA0015)
- Kubernetes secret-exfiltration patterns
- **Polyglot file detection** — text-extension files (`.md`, `.yaml`, `.json`, etc.) whose leading bytes are a binary/executable/archive signature (ELF, PE/MZ, ZIP, PDF, Mach-O, gzip). Built-in magic-byte detection — no external dependency.
- **Prompt injection in agent instruction files** — hidden directives in `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.continue/`, `.cursor/` (OWASP LLM01)
- **Malicious agent config payloads** — embedded `curl|bash`, `exec`/`eval` in CrewAI/AutoGen/litellm configs (CRITICAL)
- **LangChain `lc-` key heuristic** — best-effort detection of LangChain-format credentials, motivated by CVE-2025-68664 (LangGrinch); treat as a high-signal lead requiring confirmation

### Git History Scanning (`gitexpose git-history <path>`, v0.4)
- Scans **all reachable git history** (`git log -p --all --reverse`) for credentials committed and later removed
- Full 29-provider credential matrix applied to every diff hunk
- Each secret deduplicated and reported once at its **earliest-introducing commit** with SHA, author, and date
- **Composes with `--verify`**: historical secrets are liveness-checked — "deleted 47 commits ago, confirmed live"
- AWS access+secret pairing applies here too, enabling AWS liveness verification on historical findings
- Flags: `-o/--output {console,json}`, `--out-file`, `--since`, `--max-commits`, plus the full `--verify*` family

### Active Verification (`--verify`, v0.3+)
- Opt-in liveness check: turns a "looks like a key" finding into a **confirmed live / dead** verdict by sending a low-footprint, side-effect-free auth request to the provider
- Covers 16 providers: OpenAI, Anthropic, Groq, OpenRouter, xAI, Cerebras, Hugging Face, ElevenLabs, Pinecone, LangSmith, GitHub, GitLab, Docker Hub, Slack, and AWS (SigV4 `GetCallerIdentity`)
- **AWS pairing (v0.4)**: when both `aws_access_key` and `aws_secret_key` are found in the same source, they are paired automatically so the STS liveness check succeeds. Previously AWS always returned `error`. Applies to both `supply-chain` and `git-history`.
- Conservative by default: a consent banner names every destination host, concurrency is capped, and no raw secret is ever logged (canary-tested). Results surface as `verified` / `dead` / `error` and as `verified-live` SARIF tags for GitHub Code Scanning
- Status surfaced across JSON, SARIF, HTML, CSV, and console output

### Advanced Modules (in `gitexpose/advanced/`)
- React2Shell detector (CVE-2025-55182)
- ML model supply-chain scanner (pickle opcode analysis)
- LLM/RAG infrastructure exposure scanner
- Invisible Unicode detector (GlassWorm patterns)
- Cloud asset scanner (S3 / Azure Blob / GCS)
- API endpoint discovery
- WAF detection / stealth mode
- MCP server (Model Context Protocol)

---

## Installation

```bash
# Clone repository
git clone https://github.com/fevra-dev/GitExpose.git
cd gitexpose

# Install with pip
pip install -e .

# Or install with advanced dependencies
pip install -e ".[advanced]"
```

### Requirements
- Python 3.9+
- aiohttp, click, colorama (core)
- rich, aiofiles, GitPython (advanced, optional)

---

## Quick Start

### Basic Scan
```bash
# Single target
gitexpose example.com

# Multiple targets
gitexpose example.com api.example.com

# From file
gitexpose -f targets.txt
```

### Advanced Scans
```bash
# Full security audit (all modules)
gitexpose scan example.com --full-audit

# React2Shell vulnerability check
gitexpose react2shell https://nextjs-app.com

# ML model supply chain scan
gitexpose ml-scan https://api.example.com

# LLM/AI infrastructure exposure
gitexpose llm-scan https://ai-app.com

# Invisible Unicode detection
gitexpose unicode-scan --file suspicious.js

# Local supply-chain scan — now with live dependency SCA (OSV.dev, v0.5)
# Parses lock files, queries OSV for live CVEs/GHSAs, ranks by exploitability.
gitexpose supply-chain ./my-project

# Air-gapped / offline: skip OSV, use the curated known-bad list only
gitexpose supply-chain ./my-project --offline

# Export a CycloneDX 1.6 AI-BOM (components + dependency VEX + NTIA elements)
gitexpose supply-chain ./my-project -o cyclonedx --out-file sbom.cdx.json

# Supply-chain scan with active credential verification (opt-in)
# Sends a side-effect-free auth check to each provider; prints a consent banner.
gitexpose supply-chain ./my-project --verify

# Verify only the highest-severity findings, with a tighter timeout
gitexpose supply-chain ./my-project --verify --verify-only-severity HIGH --verify-timeout 3

# Scan all git history for committed-then-removed secrets, and verify which are still live
gitexpose git-history . --verify

# Audit AI-agent configs for excessive tool permissions + leaked system prompts (v0.6–v0.7)
# Classifies MCP/permission grants + function-calling tool schemas against a
# dangerous-capability taxonomy (OWASP LLM08).
gitexpose agent-audit ./repo
gitexpose agent-audit ./repo -o json --out-file agent-findings.json
# Emit SARIF for GitHub Code Scanning (v0.7)
gitexpose agent-audit ./repo -o sarif --out-file agent.sarif

# Web scan: a bare target is shorthand for `gitexpose scan` (both run the web scanner)
gitexpose example.com -o sarif
gitexpose scan example.com -o sarif

# Multi-module aggregate sweep (react2shell + ml + llm + unicode + source-maps + cicd + api)
gitexpose full-audit example.com --full-audit
```

### Output Formats
```bash
# JSON output
gitexpose example.com -o json --out-file results.json

# HTML report
gitexpose scan example.com --full-audit -o html --out-file report.html

# CSV for spreadsheets
gitexpose -f targets.txt -o csv --out-file results.csv

# SARIF 2.1.0 (for GitHub Advanced Security, VS Code, etc.)
gitexpose example.com -o sarif --out-file results.sarif
```

---

## Advanced Capabilities

### React2Shell Detection (CVE-2025-55182)
Detects the critical pre-auth RCE vulnerability affecting React Server Components:
```python
from gitexpose.advanced import React2ShellDetector

detector = React2ShellDetector(deep_scan=True)
finding = await detector.scan("https://nextjs-app.com")

print(f"Status: {finding.status.value}")  # vulnerable/potentially_vulnerable
print(f"Risk Score: {finding.risk_score}/10.0")
```

### ML Model Supply Chain
Scans for exposed models that could execute arbitrary code:
```python
from gitexpose.advanced import MLModelScanner

scanner = MLModelScanner(deep_analysis=True)
result = await scanner.scan("https://ml-api.com")

for model in result.exposed_models:
    print(f"[{model.risk_level}] {model.path}")
```

### MCP Server (AI Agent Integration)
```bash
# Start MCP server for Claude/GPT integration
gitexpose mcp
```

---

## Detection Coverage

See [docs/COVERAGE.md](docs/COVERAGE.md) for the full detection matrix.

| Category | Examples | Severity |
|----------|----------|----------|
| **Git Repositories** | .git/config, HEAD, index | Critical |
| **Environment Files** | .env, .env.production | Critical |
| **Configuration** | wp-config.php, settings.py | High |
| **Backups** | backup.sql, database.dump | Critical |
| **Source Maps** | *.js.map, webpack bundles | High |
| **ML Models** | .pkl, .pt, .h5 | Critical |
| **AI/LLM Configs** | Vector DBs, MCP configs, API keys | Critical |
| **Supply Chain** | Malicious packages, unpinned deps | High–Critical |

---

## Project Structure

```
gitexpose/
├── gitexpose/
│   ├── __init__.py          # Main package
│   ├── cli.py               # CLI interface
│   ├── scanner.py           # Core scanning engine
│   ├── models.py            # Data models
│   ├── paths.py             # AI-tool config path detection
│   ├── signatures.py        # Detection signatures
│   │
│   ├── advanced/            # Advanced security modules
│   │   ├── react2shell_detector.py
│   │   ├── ml_model_scanner.py
│   │   ├── llm_exposure_scanner.py
│   │   ├── invisible_unicode_detector.py
│   │   ├── supply_chain_patterns.py
│   │   ├── local_fs_scanner.py
│   │   ├── credential_cluster.py
│   │   ├── slopsquatting.py
│   │   ├── known_bad_versions.py
│   │   ├── dependency_pinning.py
│   │   └── mcp_server.py
│   │
│   ├── core/                # Core detection engine
│   ├── git/                 # Git analysis
│   ├── secrets/             # Credential extraction
│   └── reporters/           # Output formatters (console, JSON, CSV, HTML, SARIF)
│
├── docs/                    # Documentation
├── tests/                   # Test suite (251 tests)
└── requirements.txt
```

> Test suite: ~287 tests as of v0.4.

---

## Roadmap (not yet implemented)

The following are designed but not yet shipping. Track via GitHub issues.

- Policy engine: configurable severity overrides, allow-list patterns, org-wide suppression rules
- Classic typosquatting (Levenshtein/Jaro-Winkler/homoglyph/keyboard) against popular-package baselines
- Lock-file poisoning checks (SRI hash mismatch, ghost deps, off-registry resolved URLs) — v0.5 already captures the integrity hashes + URLs needed
- Shai-Hulud install-time behavioral analysis (lifecycle hooks, credential-harvest AST, metadata-service SSRF)
- Go (`go.sum`) and Cargo (`Cargo.lock`) ecosystems for SCA
- Capability/scope enumeration for verified credentials (AWS IAM perms, GitHub PAT scopes, OpenAI org)
- Active verification for Tier 3 providers (Helicone, Portkey, Voyage, Cohere, Modal, Runpod — detection-only today) and webhook/DB/JWT classes
- `--verify` on the web-scan path (currently verification runs on `supply-chain` and `git-history` findings only)
- ML-powered anomaly detection engine
- Runtime monitoring proxy (Pipelock-style)
- Plugin architecture for custom detection rules
- Web dashboard / REST API
- Live external threat-intelligence enrichment
- Audio steganography detection (Telnyx-class)
- Browser-agent misuse patterns

**Shipped in v0.5:** live dependency SCA — lock-file parsing (Python + JS) + OSV.dev CVE/GHSA lookups (`vulnerable_dependency`, default on, `--offline` opt-out), exploitability-first ranking, and a CycloneDX 1.6 AI-BOM (`-o cyclonedx`) with honestly-scoped VEX — see the [CHANGELOG](CHANGELOG.md).

**Shipped in v0.4:** `git-history` command (all-reachable-commit secret scanning with `--verify` composition), AI-supply-chain signature pack (`polyglot_file`, `skill_prompt_injection`, `agent_config_malicious_content`, `langgrinch_lc_key`), and AWS access+secret pairing for reliable liveness verification — see the [CHANGELOG](CHANGELOG.md).

**Shipped in v0.3:** active credential verification (`--verify`), Tier 3 provider detection, GitHub Actions + pre-commit + Code Scanning integration docs, and the full MITRE ATLAS coverage map — see the [CHANGELOG](CHANGELOG.md).

---

## Documentation

- [docs/COVERAGE.md](docs/COVERAGE.md) — full provider + supply-chain detection matrix
- [docs/MITRE_ATLAS_COVERAGE.md](docs/MITRE_ATLAS_COVERAGE.md) — per-detection MITRE ATLAS technique mapping
- [docs/INTEGRATIONS_CICD.md](docs/INTEGRATIONS_CICD.md) — GitHub Actions + pre-commit setup
- [docs/INTEGRATIONS_CODE_SCANNING.md](docs/INTEGRATIONS_CODE_SCANNING.md) — GitHub Code Scanning (SARIF) setup + `verified-live` tag filtering
- [docs/README_ADVANCED.md](docs/README_ADVANCED.md) — advanced module reference
- [CHANGELOG.md](CHANGELOG.md) — release history

---

## Responsible Use

This tool is intended for:
- Authorized penetration testing
- Bug bounty programs (in-scope targets)
- Security audits with permission
- Validating your own infrastructure

**Never** use against targets without explicit authorization.

---

## Research Basis

Built on current threat intelligence:

| Threat | Source | Impact |
|--------|--------|--------|
| React2Shell | CVE-2025-55182 | CVSS 10.0 RCE |
| ML Poisoning | nullifAI research | Arbitrary code execution |
| GlassWorm | VS Code supply chain | Self-propagating worm |
| RAG Poisoning | OWASP LLM Top 10 | AI manipulation |
| Slopsquatting | USENIX 2025 | LLM-hallucinated package abuse |
| TeamPCP | Supply-chain incident | .pth persistence + data exfil |

---

## Contributing

Contributions welcome! Areas of interest:
- New detection patterns
- Framework-specific scanners
- ML model format analysis
- Unicode attack patterns

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

<div align="center">

**Built for security researchers defending AI and developer infrastructure**

</div>
