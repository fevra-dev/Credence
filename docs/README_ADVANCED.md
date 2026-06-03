# Credence Advanced Features

<div align="center">

**Security Scanner for AI and Dev Infrastructure**

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CVE](https://img.shields.io/badge/CVE--2025--55182-React2Shell-red.svg)](#react2shell-detection)

*Detect React2Shell, ML supply-chain poisoning, LLM infrastructure exposure, and invisible Unicode attacks*

</div>

---

## Overview

Credence v0.2.0 ships five advanced detection modules in `credence/advanced/`, alongside the core credential and supply-chain scanners. See [docs/COVERAGE.md](COVERAGE.md) for the full detection matrix (23-provider credential matrix, supply-chain indicators, compliance taxonomies).

| Module | Threat Addressed | Research Basis |
|--------|------------------|----------------|
| **React2Shell Detector** | CVE-2025-55182 (CVSS 10.0) | Framework RCE via Flight protocol |
| **ML Model Scanner** | Pickle/PyTorch deserialization RCE | nullifAI, HuggingFace poisoning |
| **LLM Exposure Scanner** | AI infrastructure compromise | RAG poisoning, prompt leakage |
| **Unicode Detector** | GlassWorm-style supply chain | Invisible code injection |
| **MCP Server** | AI agent integration | Model Context Protocol |

---

## Quick Start

```bash
# Full security audit
credence scan example.com --full-audit

# Specific scans
credence react2shell https://nextjs-app.com
credence ml-scan https://api.example.com
credence llm-scan https://ai-app.com
credence unicode-scan --file suspicious.js

# Local supply-chain scan
credence supply-chain ./my-project

# Start MCP server for AI agents
credence mcp
```

---

## Advanced Modules

### 1. React2Shell Detector (`react2shell_detector.py`)

Detects the **CVE-2025-55182** vulnerability — a critical pre-authentication RCE affecting React Server Components, Next.js, and the Flight protocol.

**What it detects:**
- Exposed RSC (React Server Components) endpoints
- Flight protocol serialization endpoints
- Vulnerable Next.js configurations (13.x–15.x)
- Server action exports
- Build manifest exposure

**Technical Details:**
```python
from credence.advanced import React2ShellDetector

detector = React2ShellDetector(deep_scan=True)
finding = await detector.scan("https://nextjs-app.com")

print(f"Status: {finding.status.value}")  # vulnerable/potentially_vulnerable/likely_safe
print(f"Framework: {finding.framework.value}")  # nextjs/remix/gatsby
print(f"Risk Score: {finding.risk_score}/10.0")
```

**CLI Usage:**
```bash
credence react2shell https://target.com --deep-scan
credence react2shell https://target.com -o json
```

---

### 2. ML Model Supply Chain Scanner (`ml_model_scanner.py`)

Scans for exposed machine learning model files that could execute arbitrary code when loaded.

**Threat Model:**
- **Pickle deserialization**: Arbitrary Python code execution via `__reduce__`
- **PyTorch `torch.load()`**: Uses pickle internally
- **TensorFlow SavedModel**: Custom ops can execute code
- **nullifAI attacks**: 7z-compressed pickles evading scanners

**Detected Formats:**
| Extension | Format | Risk Level |
|-----------|--------|------------|
| `.pkl`, `.pickle` | Python Pickle | Critical |
| `.pt`, `.pth`, `.bin` | PyTorch | Critical |
| `.joblib` | Joblib | Critical |
| `.h5`, `.hdf5`, `.keras` | Keras/TF | High |
| `.onnx` | ONNX | Medium |
| `.safetensors` | SafeTensors | Low |

**Deep Analysis Features:**
- Dangerous pickle opcode detection (`GLOBAL`, `REDUCE`, etc.)
- Nested pickle stream identification
- Base64-encoded payload detection
- 7z compression evasion technique detection

```python
from credence.advanced import MLModelScanner

scanner = MLModelScanner(deep_analysis=True)
result = await scanner.scan("https://ml-api.com")

for model in result.exposed_models:
    print(f"[{model.risk_level.value}] {model.path}")
    for indicator in model.indicators:
        print(f"  {indicator.description}")
```

---

### 3. LLM/RAG Exposure Scanner (`llm_exposure_scanner.py`)

Detects exposed AI/LLM infrastructure as organizations rapidly deploy AI without security controls.

**Detection Targets:**

| Category | What's Detected |
|----------|-----------------|
| **Vector Databases** | ChromaDB, Pinecone, Weaviate, Milvus, Qdrant |
| **System Prompts** | Exposed prompt templates, system instructions |
| **RAG Configs** | Knowledge base locations, chunking strategies |
| **LangChain/LlamaIndex** | Chain configs, agent definitions |
| **API Keys** | OpenAI, Anthropic, Cohere, HuggingFace tokens |
| **Agent Configs** | MCP servers, tool definitions |

**Why This Matters:**
- System prompts often contain business logic and internal API docs
- Vector databases store sensitive knowledge bases
- Exposed API keys enable model abuse and billing fraud
- Agent configs reveal tool permissions and attack surface

```python
from credence.advanced import LLMExposureScanner

scanner = LLMExposureScanner()
result = await scanner.scan("https://ai-app.com")

for exposure in result.exposures:
    print(f"[{exposure.severity.value}] {exposure.exposure_type.value}")
    print(f"  URL: {exposure.url}")
    print(f"  {exposure.description}")
```

---

### 4. Invisible Unicode Detector (`invisible_unicode_detector.py`)

Detects invisible Unicode characters used in supply chain attacks like **GlassWorm**.

**Attack Vectors Detected:**

| Category | Characters | Threat Level |
|----------|------------|--------------|
| **Zero-Width** | ZWSP, ZWNJ, ZWJ | Medium |
| **Variation Selectors** | VS1–VS256 | High |
| **Bidirectional** | RLO, LRO (Trojan Source) | Critical |
| **Tag Characters** | U+E0000–E007F | High |
| **Homoglyphs** | Cyrillic, Greek lookalikes | Medium |
| **PUA** | Private Use Area | Medium |

**GlassWorm Pattern Detection:**
```python
from credence.advanced import InvisibleUnicodeAnalyzer

analyzer = InvisibleUnicodeAnalyzer(strict_mode=True)
anomalies = analyzer.analyze(suspicious_code)

for anomaly in anomalies:
    print(f"[{anomaly.threat_level.value}] Line {anomaly.line_number}")
    print(f"  {anomaly.codepoint}: {anomaly.description}")

# Decode hidden messages from tag characters
hidden = analyzer.decode_hidden_message(suspicious_code)
if hidden:
    print(f"Hidden message: {hidden}")
```

**CLI Usage:**
```bash
# Scan URL for infected JavaScript
credence unicode-scan https://cdn.example.com/bundle.js

# Analyze local file
credence unicode-scan --file suspicious-extension/index.js
```

---

### 5. MCP Server (`mcp_server.py`)

Implements the **Model Context Protocol** to expose Credence as tools for AI agents.

**Available MCP Tools:**

| Tool | Description |
|------|-------------|
| `credence_scan` | Comprehensive sensitive file scan |
| `credence_git_dump` | Git repository reconstruction |
| `credence_extract_secrets` | Credential extraction |
| `credence_react2shell_detect` | React2Shell vulnerability check |
| `credence_ml_model_scan` | ML model poisoning scan |
| `credence_llm_exposure_scan` | AI infrastructure exposure |
| `credence_unicode_detect` | Invisible Unicode detection |

**Configuration for Claude/Cursor:**
```json
{
  "mcpServers": {
    "credence": {
      "command": "python",
      "args": ["-m", "credence.advanced.mcp_server"]
    }
  }
}
```

**Starting the Server:**
```bash
credence mcp
```

---

## Supply-Chain Scanning (`credence supply-chain`)

In addition to the advanced modules above, v0.2 adds a local supply-chain scanner covering AI-specific attack patterns:

| Detection | Severity | Description |
|-----------|----------|-------------|
| `unpinned_ai_middleware` | HIGH | AI middleware (litellm, langchain, openai, etc.) without `==` pin |
| `known_malicious_package_version` | CRITICAL | Pinned to a known-compromised version (e.g., `litellm==1.82.7`) |
| `slopsquatting` | CRITICAL | Package name from the LLM-hallucination corpus (USENIX 2025 basis) |
| `pth_persistence` | CRITICAL | `.pth` file with `exec`/`eval`/`base64` (TeamPCP technique) |
| `ai_c2_beacon` | CRITICAL | Skill instructs AI agent to operate as C2 implant (ATLAS AML.TA0015) |
| `kubernetes_exfiltration` | CRITICAL | Kubernetes secret enumeration / service-account token access |
| `credential_cluster` | CRITICAL | 2+ distinct secret types co-occur in the same file |
| `multi_provider_credential_file` | CRITICAL | Cluster in known aggregator path (`OAI_CONFIG_LIST`, `litellm_config.yaml`, etc.) |

See [docs/COVERAGE.md](COVERAGE.md) for the full credential matrix, AI-tool config paths, and compliance taxonomy details.

---

## Architecture

```
credence/
├── credence/
│   ├── __init__.py
│   ├── cli.py
│   ├── scanner.py
│   ├── models.py
│   ├── paths.py
│   ├── signatures.py
│   │
│   ├── advanced/
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
│   └── reporters/           # console, JSON, CSV, HTML, SARIF 2.1.0
│
├── docs/
│   ├── COVERAGE.md          # Full detection matrix
│   └── README_ADVANCED.md   # This file
└── tests/                   # 122 tests
```

---

## Output Formats

All scan modes support multiple output formats:

```bash
# Console (default)
credence scan target.com --full-audit

# JSON
credence scan target.com --full-audit -o json --out-file results.json

# HTML report
credence scan target.com --full-audit -o html --out-file report.html

# CSV
credence scan target.com --full-audit -o csv --out-file results.csv

# SARIF 2.1.0 (GitHub Advanced Security, VS Code, etc.)
credence scan target.com --full-audit -o sarif --out-file results.sarif
```

Every finding includes OWASP LLM Top 10 (`attack_class`) and MITRE ATLAS technique (`atlas_technique`) metadata, emitted in all output formats.

---

## Research Basis

| Threat | Source | Impact |
|--------|--------|--------|
| React2Shell | CVE-2025-55182 | CVSS 10.0 pre-auth RCE |
| ML Poisoning | nullifAI research | Arbitrary code execution on `torch.load()` / `pickle.load()` |
| GlassWorm | Truesec, Snyk | Invisible Unicode in VS Code extensions; Solana-hosted C2 |
| RAG Poisoning | OWASP LLM Top 10 | AI manipulation via poisoned knowledge base |
| Slopsquatting | USENIX 2025 | LLM-hallucinated package name abuse |
| TeamPCP | Supply-chain incident | `.pth` persistence + data exfil via AI middleware |

No external service is queried at scan time. All detections are local pattern matching.

---

## Use Cases

### Security Audit
```bash
# Full audit with all modules; SARIF output for CI integration
credence scan target.com --full-audit -o sarif --out-file audit.sarif
```

### Bug Bounty
```bash
# Quick reconnaissance
credence scan target.com --react2shell --source-maps --git-dump
```

### AI Security Assessment
```bash
# Audit AI/ML deployments
credence llm-scan https://ai-app.com
credence ml-scan https://ml-api.com --deep-analysis
```

### Supply Chain Defense
```bash
# Check for invisible Unicode in a package
credence unicode-scan --file node_modules/suspicious-package/index.js

# Scan local project for supply-chain risk
credence supply-chain ./my-project
```

### AI Agent Integration
```bash
# Start MCP server for autonomous scanning workflows
credence mcp
```

---

## Roadmap (not yet implemented)

The following are planned but not shipping in v0.2. Track via GitHub issues.

- ML-powered anomaly detection engine (beyond static opcode analysis)
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

## Installation

```bash
# Install with all dependencies
pip install "credence-scan[advanced]"

# Or install from source
git clone https://github.com/fevra-dev/Credence.git
cd credence
pip install -e ".[advanced]"
```

**Requirements:**
```
aiohttp>=3.9.0
aiofiles>=23.2.0
click>=8.1.0
rich>=13.0.0  # Optional but recommended
```

---

## Contributing

Contributions welcome. Areas of interest:
- Additional framework detection (Remix, Astro, SvelteKit)
- New ML model format analysis
- Additional vector database signatures
- Unicode attack pattern research

---

## License

MIT License — see [LICENSE](../LICENSE) for details.

---

<div align="center">

**Built for security researchers defending AI and developer infrastructure**

[Report Bug](https://github.com/fevra-dev/Credence/issues) · [Request Feature](https://github.com/fevra-dev/Credence/issues)

</div>
