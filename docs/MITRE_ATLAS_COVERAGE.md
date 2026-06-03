# Credence × MITRE ATLAS Coverage Map

Last updated: v0.3

This document maps every Credence detection to a MITRE ATLAS technique. ATLAS
(Adversarial Threat Landscape for Artificial-Intelligence Systems) is MITRE's
adversary behavior knowledge base for AI/ML systems, modeled after ATT&CK.

Reference: https://atlas.mitre.org/

## Per-detection mapping

### Credential detection

| Pattern family | ATLAS technique | Justification |
|---|---|---|
| LLM provider keys (OpenAI, Anthropic, Groq, OpenRouter, Perplexity, xAI, Cerebras, HuggingFace, ElevenLabs, Pinecone, LangSmith) | `AML.T0019` (Publish Poisoned Datasets) → Initial Access via Valid Accounts | An exposed LLM provider key allows an adversary to send requests as the victim. The downstream attack class is broad — model poisoning, data exfiltration via prompt injection, cost denial-of-service. The primary access vector is account takeover via valid credentials. |
| Code/cloud platform keys (GitHub PAT, GitLab PAT, AWS access keys, Docker Hub PAT) | `AML.T0019` + `AML.T0042` (Disable AI Logging) when scope includes audit log control | Same valid-accounts vector; AWS keys with IAM admin and GitHub PATs with `repo` scope are the highest-impact subset. |
| Communication tokens (Slack, Discord bot/webhook, Telegram) | `AML.T0050` (Command and Scripting Interpreter) → AI agent C2 | Exposed bot/webhook tokens enable AI-agent C2 channels and lateral movement into LLM-augmented workflows. |
| Payment keys (Stripe live/test) | `AML.T0019` (financial reconnaissance) | Out-of-band ATLAS mapping; included for completeness. |
| Database connection strings (Postgres, MySQL, MongoDB) | `AML.T0046` (Data Exfiltration) | Direct DB access for training-data exfiltration. |

### Supply chain detection

| Detection | ATLAS technique | Justification |
|---|---|---|
| `unpinned_ai_middleware` | `AML.T0010` (ML Supply Chain Compromise) | Unpinned versions allow compromised maintainer tokens to push malicious code without notice. TeamPCP-class incident. |
| `known_malicious_package_version` | `AML.T0010` | Confirmed-bad versions of `litellm`, `telnyx`, `xinference`, etc. |
| `slopsquatting` | `AML.T0010` + `AML.T0019` | LLM-hallucinated package names being preemptively registered as malware. |
| `pth_persistence` | `AML.T0011` (Persistence) | `.pth` files with `exec`/`eval`/`base64` are a Python-import-time execution vector. |
| `ai_c2_beacon` | `AML.TA0015` (Command and Control) | Skills that instruct an AI agent to operate as a C2 implant. |
| `kubernetes_exfiltration` | `AML.T0046` (Exfiltration via Cloud Storage) | k8s service-account token access patterns leading to ML model and secret exfiltration. |

### AI tool configuration detection

| Detection | ATLAS technique | Justification |
|---|---|---|
| `.continue/`, `claude/.credentials.json` | `AML.T0019` | Direct exposure of LLM provider keys via AI-IDE config files. |
| `litellm_config.yaml`, `OAI_CONFIG_LIST` | `AML.T0019` | Multi-provider key aggregators — one file compromise → many provider compromises. |
| `mcp.json`, `.cursor/mcp.json` | `AML.T0059` (Indirect Prompt Injection via MCP) | Malicious MCP entries are a tool-injection vector for AI agents. |
| `.env.*.example`, `.env.*.bak` | `AML.T0019` | Frequently contain real keys despite "example"/"bak" naming. |
| `firebase-config.js` | `AML.T0019` | Embeds Firebase API key in client code. |

### Detection-only categories (no ATLAS mapping yet)

These are Credence detections that don't yet map cleanly to ATLAS techniques.
Listed here for transparency.

- Generic API key (catch-all entropy/pattern) — too broad for a specific
  technique.
- JWT structural detection (no signature verification) — informational only.
- Private key (PEM) — could be many techniques depending on usage; left
  unmapped to avoid over-claiming.

## How Credence surfaces ATLAS data

Every applicable finding includes an `atlas_technique` field. This is rendered:

- in JSON output as `finding.atlas_technique`
- in SARIF output as `result.properties.atlas_technique` and as a taxonomy reference
- in HTML output as a red `ATLAS` badge next to the severity badge
- in CSV output as a column
- in console output as part of the finding's compliance line

## Caveats

- ATLAS is younger than ATT&CK and its technique list is evolving. Some of our
  mappings (`AML.T0019` → "Valid Accounts" reuse for LLM API keys) may be
  refined as ATLAS adds more specific techniques.
- A single Credence finding may legitimately touch multiple ATLAS techniques;
  we surface the single closest match to keep the model simple.
- We do not currently auto-update from upstream ATLAS releases; the mapping is
  refreshed manually on each Credence release.
