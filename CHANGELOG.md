# Changelog

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
