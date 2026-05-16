# GitExpose

<div align="center">

![Version](https://img.shields.io/badge/version-0.2.0-blue.svg)
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
| **Credential exposure** | 23-provider matrix: OpenAI, Anthropic, Google, Groq, xAI, Hugging Face, Replicate, Perplexity, Pinecone, LangSmith, Stripe, GitHub, GitLab, Docker Hub, Discord, Slack, Telegram, Twilio, SendGrid, AWS, ElevenLabs, plus DB connection strings |
| **Exposed AI-tool configs** | `.continue/`, `claude/.credentials.json`, MCP configs, LiteLLM proxy configs, CrewAI/AutoGen YAMLs, .NET appsettings build output |
| **Supply-chain risk** | Unpinned AI middleware, known-malicious package versions (TeamPCP), slopsquatting, `.pth` persistence, AI agent C2 beacons, k8s exfiltration |
| **Compliance metadata** | OWASP LLM Top 10 + MITRE ATLAS technique on every finding |
| **HTTP target scanning** | `.git`, `.env`, source maps, framework misconfigs, exposed configs |

See [docs/COVERAGE.md](docs/COVERAGE.md) for the full matrix.

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

# Local supply-chain scan
gitexpose supply-chain ./my-project
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
├── tests/                   # Test suite (122 tests)
└── requirements.txt
```

---

## Roadmap (not yet implemented)

The following are designed but not shipping in v0.2. Track via GitHub issues.

- ML-powered anomaly detection engine
- Runtime monitoring proxy (Pipelock-style)
- Plugin architecture for custom detection rules
- Web dashboard / REST API
- Package pre-installation verification CLI
- IDE plugins (VS Code, JetBrains)
- Live external threat-intelligence enrichment
- Full MITRE ATLAS coverage map document (metadata ships in v0.2; full coverage doc is v0.3)
- Audio steganography detection (Telnyx-class)
- Browser-agent misuse patterns

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
