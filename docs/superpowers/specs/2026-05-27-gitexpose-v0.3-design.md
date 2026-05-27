# GitExpose v0.3 — Design Spec

> Status: brainstorm-approved, pending implementation plan
> Date: 2026-05-27
> Prior release: v0.2.0 (shipped 2026-05-17)
> Brainstorm notes: [`docs/v0.3-planning-notes.md`](../../v0.3-planning-notes.md)
> Implementation plan: TBD (to be produced by `superpowers:writing-plans`)

## 1. Goal

Ship v0.3 with **Active Verification** as the headline feature: turn pattern-matched credential findings into confirmed-live findings by sending low-footprint, side-effect-free authentication checks to provider APIs. Match the precision bar set by TruffleHog and GitGuardian's `ggshield` for the subset of providers GitExpose covers.

Secondary goal: ship the integration glue (GitHub Actions, pre-commit, GitHub Code Scanning) that drives the distribution model used by every successful secret scanner.

## 2. Scope

### 2.1 In scope

1. **Active Verification engine** — opt-in via `--verify`. Binary `VERIFIED` / `DEAD` / `ERROR` / `SKIPPED` / `UNVERIFIABLE` outcomes across the safely-verifiable subset of patterns.
2. **`mcp_server.py` carry-over fix** — `gitexpose/advanced/mcp_server.py:432`: drop unsupported `validate=` kwarg from `extract()` call; fix `.get("valid")` → `.get("validated")`; add regression test.
3. **Tier 3 providers** — Helicone, Portkey, Voyage, Cohere, Modal, Runpod patterns added to `gitexpose/data/credential_patterns_v02.json`.
4. **CI/CD integrations** — sample GitHub Actions workflow (`.github/workflows/gitexpose-scan.yml`), pre-commit hook config (`.pre-commit-hooks.yaml`), integration walkthrough at `docs/INTEGRATIONS_CICD.md`.
5. **MITRE ATLAS coverage map** — `docs/MITRE_ATLAS_COVERAGE.md` per-finding mapping.
6. **GitHub Code Scanning doc** — `docs/INTEGRATIONS_CODE_SCANNING.md` with sample SARIF-upload workflow.
7. **CISA-incident motivation callout** — one paragraph in `README.md` linking to Krebs / GitGuardian reporting on the Private-CISA leak.
8. **Repo cleanup** — `.gitignore` for `.serena/`, `RESEARCH/`, `files/`, `files (1)/`, root PNGs. Move `*.md` notes into `docs/notes/`.

### 2.2 Verifiable provider list (v0.3 verification scope)

LLM tier (11):
- OpenAI, Anthropic, Groq, OpenRouter, Perplexity, xAI, Cerebras, Hugging Face, ElevenLabs, Pinecone, LangSmith

Code/cloud/comms (5):
- GitHub PAT, GitLab PAT, Docker Hub, AWS (SigV4 `GetCallerIdentity`), Slack token

Total: 16 verifiers.

### 2.3 Explicitly out of scope (locked)

- AI-BOM (SPDX 3.0) output → v0.4 headline.
- Capability/scope enumeration (AWS IAM perms, GitHub PAT scopes, OpenAI org/project) → v0.4.
- Verification of webhooks (Slack, Discord, Stripe), DB URLs (Postgres, MySQL, MongoDB), JWTs, private keys, generic API keys → architecturally infeasible without side effects or out-of-band material.
- Verifiers for Discord bot, Telegram bot, Twilio, SendGrid → case-by-case in v0.4.
- Persistent verification cache (across-run cache file) → not until we have empirical use data.
- AI canary tokens → separate sister project, v0.5+.
- Deep git-history traversal (TruffleHog-style unlinked-blob walk) → v0.4+.
- ML detection engine, plugin architecture, web dashboard, REST API → out of scope indefinitely (per v0.2 honesty pass).

## 3. Architecture

### 3.1 Module layout

```
gitexpose/verification/
├── __init__.py           # public API: verify_findings(findings, *, concurrency=5, timeout=5.0)
├── engine.py             # async dispatcher, semaphore, error → status mapping
├── result.py             # VerificationStatus enum, VerificationResult dataclass
├── helpers.py            # bearer_token_check(url, header, scheme), redact(secret)
└── providers/
    ├── __init__.py       # VERIFIERS registry — single source of truth
    ├── llm.py            # bearer-token entries for the 11 LLM providers
    ├── code.py           # bearer-token entries for GitHub PAT, GitLab PAT
    ├── docker.py         # Docker Hub (POST /v2/users/login, parse JWT response)
    ├── slack.py          # Slack token (POST auth.test, parse {"ok": bool})
    └── aws.py            # AWS STS GetCallerIdentity (SigV4)
```

### 3.2 The registry (chosen pattern: callable dispatch + shared helper)

```python
# gitexpose/verification/providers/__init__.py
from functools import partial
from ..helpers import bearer_token_check
from . import aws, docker, slack

VERIFIERS = {
    "openai":      partial(bearer_token_check, url="https://api.openai.com/v1/models",
                                                header="Authorization", scheme="Bearer"),
    "anthropic":   partial(bearer_token_check, url="https://api.anthropic.com/v1/models",
                                                header="x-api-key", scheme=None),
    # ... 9 more LLM providers as one-liners ...
    "github_pat":  partial(bearer_token_check, url="https://api.github.com/user",
                                                header="Authorization", scheme="Bearer"),
    "gitlab_pat":  partial(bearer_token_check, url="https://gitlab.com/api/v4/user",
                                                header="Authorization", scheme="Bearer"),
    "docker_hub":  docker.verify,
    "aws":         aws.verify,
    "slack_token": slack.verify,
}
```

Each entry resolves to `Callable[[str], Awaitable[VerificationResult]]`. The 80% case is one line; one-offs get their own function in their own module.

### 3.3 Dispatcher

```python
# gitexpose/verification/engine.py
async def verify_findings(
    findings: list[Finding],
    *,
    concurrency: int = 5,
    timeout: float = 5.0,
) -> list[Finding]:
    sem = asyncio.Semaphore(concurrency)
    seen: dict[str, VerificationResult] = {}      # in-run dedup keyed by raw secret

    async def _one(f: Finding) -> None:
        verifier = VERIFIERS.get(f.pattern_name)
        if verifier is None:
            f.verification_status = VerificationStatus.UNVERIFIABLE
            return
        if f.secret in seen:
            result = seen[f.secret]
        else:
            async with sem:
                try:
                    result = await asyncio.wait_for(verifier(f.secret), timeout=timeout)
                except asyncio.TimeoutError:
                    result = VerificationResult(VerificationStatus.ERROR, "timeout")
                except Exception as exc:
                    result = VerificationResult(VerificationStatus.ERROR, type(exc).__name__)
            seen[f.secret] = result
        f.verification_status = result.status
        f.verification_detail = result.detail

    await asyncio.gather(*(_one(f) for f in findings))
    return findings
```

### 3.4 Error → status mapping

| HTTP / outcome | Status |
|---|---|
| 200 + provider-specific success check (e.g. body parses, `ok: true` for Slack) | `VERIFIED` |
| 401 / 403 with clear invalid-auth shape | `DEAD` |
| 5xx / network error / timeout / unexpected body shape | `ERROR` |
| Pattern not in registry | `UNVERIFIABLE` |
| `--verify` not passed | `SKIPPED` (default field value) |

### 3.5 Integration with existing scan flow

One optional post-processing call in `gitexpose/cli.py`:

```python
if args.verify:
    from gitexpose.verification import verify_findings
    findings = await verify_findings(
        findings,
        concurrency=args.verify_concurrency,
        timeout=args.verify_timeout,
    )
```

No other change to existing scanner code. Reporters check for the new field; absence is treated as `SKIPPED`.

## 4. Data model

Two additions to `gitexpose/models.py`. Backward compatible.

```python
from enum import Enum

class VerificationStatus(str, Enum):
    VERIFIED      = "verified"       # provider confirmed live
    DEAD          = "dead"           # provider returned auth-rejection
    ERROR         = "error"          # network/timeout/unexpected
    SKIPPED       = "skipped"        # --verify not passed
    UNVERIFIABLE  = "unverifiable"   # pattern has no registered verifier

@dataclass
class Finding:
    # ... existing fields unchanged ...
    verification_status: VerificationStatus = VerificationStatus.SKIPPED
    verification_detail: str | None = None
```

## 5. CLI surface

Five new arguments on existing scan subcommands (`scan`, `supply-chain`):

| Flag | Default | Purpose |
|---|---|---|
| `--verify` | off | Enable active verification |
| `--verify-concurrency N` | 5 | Global concurrent verification limit |
| `--verify-timeout SECONDS` | 5.0 | Per-request timeout |
| `--verify-only-severity LEVEL` | (all) | Only verify findings ≥ LEVEL |
| `--no-verify-banner` | off | Suppress the consent banner |

Examples:

```bash
gitexpose scan https://target.com --verify
gitexpose supply-chain ./repo --verify --verify-concurrency 3
gitexpose scan https://target.com --verify --verify-only-severity HIGH -o sarif
```

Exit code semantics are unchanged. Verification status does not influence exit code in v0.3 (`--exit-on-verified-critical` deferred to v0.4 if requested).

## 6. Output integration

Per-reporter additions. Existing fields untouched.

| Reporter | Surface |
|---|---|
| JSON | new fields `verification_status`, `verification_detail` |
| SARIF 2.1.0 | `result.properties.verification_status` + result `tags` entry (`verified-live` / `verified-dead` / `verification-error`) |
| HTML | color badge next to severity badge (red `LIVE`, grey `DEAD`, yellow `?` for `ERROR`); no badge for `SKIPPED` / `UNVERIFIABLE` |
| CSV | two new trailing columns: `verification_status`, `verification_detail` |
| Console | with `--verify`, appended colored tag per finding line (`[VERIFIED]` / `[DEAD]` / `[ERROR: timeout]` / `[UNVERIFIABLE]`); no change without `--verify` |

## 7. Security & safety

Active verification means GitExpose now makes outbound requests carrying candidate credentials. Four guardrails:

### 7.1 Destination control

- URLs are baked into the `VERIFIERS` registry at build time; no user input flows into URL construction.
- The registry is the only source for verification destinations. No fallback to "discovered" hosts.
- A misclassified key (e.g., a Stripe key incidentally matching the OpenAI shape) is sent only to the host bound to its matched pattern. The receiving provider rejects it as `DEAD`.

### 7.2 Log redaction

- `helpers.redact(secret)` returns `<first-3>…<last-4>` (e.g., `"sk-…aB3z"`).
- Every log line, every `verification_detail` string, every exception message uses `redact()`.
- Unit test seeds every verifier with `sk-CANARY1234567890`-style sentinels and asserts the raw value never appears in captured stdout, stderr, or log output.

### 7.3 No side effects

- Every verifier is GET-only, **or** a POST that the provider explicitly documents as side-effect-free (Slack `auth.test`, Docker Hub `/v2/users/login`).
- Each provider module begins with a structured comment:
  ```python
  # Side-effect class: READ-ONLY
  # Endpoint: GET https://api.openai.com/v1/models
  # Reference: https://platform.openai.com/docs/api-reference/models
  ```
- A unit test for each verifier asserts the HTTP method is GET or matches an allowlist of documented side-effect-free POST endpoints.

### 7.4 User consent

- `--verify` is the consent signal.
- On `--verify`, a one-line banner is printed to stderr:
  ```
  [verify] Sending candidate credentials to provider APIs for liveness check.
  [verify] Hosts: api.openai.com, api.anthropic.com, api.github.com, sts.amazonaws.com, ...
  [verify] Pass --no-verify-banner to suppress.
  ```
- The banner is loud enough to surface in CI logs immediately.

## 8. Testing strategy

Three layers; all network-mocked. No live provider calls in CI.

### 8.1 Unit tests

- `tests/test_verification_helpers.py` — `bearer_token_check` against mocked HTTP client: 200 → `VERIFIED`, 401/403 → `DEAD`, 5xx → `ERROR`, timeout → `ERROR`, unexpected body → `ERROR`. `redact()` edge cases.
- `tests/test_verification_engine.py` — semaphore caps concurrent calls, in-run dedup, error path doesn't crash `gather`, `UNVERIFIABLE` for unregistered pattern, `SKIPPED` default when flag not passed.
- `tests/test_verification_log_leak.py` — canary test: run each verifier with a sentinel-shaped fake secret; assert the raw value never appears in captured output.

### 8.2 Per-provider tests

`tests/test_verification_providers.py` — two minimum per provider via `respx` (or `httpx.MockTransport`):
- "live" path: mocked 200 → returns `VERIFIED`
- "dead" path: mocked 401/403 → returns `DEAD`

Three additional tests for one-offs:
- Slack: 200 with `{"ok": false}` → `DEAD` (not `VERIFIED`)
- Docker Hub: invalid-creds JSON response → `DEAD`; valid response with JWT → `VERIFIED`
- AWS: signed-request envelope assertion + canonical `GetCallerIdentity` success/failure paths

### 8.3 Smoke / integration

`tests/test_smoke_v03.py` — extends `tests/fixtures/synthetic_repo/` with planted credentials whose patterns are in the verifier registry. Runs `gitexpose supply-chain ./synthetic_repo --verify` with all 16 verifier hosts stubbed by a single `respx` fixture returning deterministic 401. Asserts: every finding has a `verification_status`, `verified-dead` tag in SARIF output, exit code unchanged.

### 8.4 Target test count

~25–30 new tests on top of the current ~125. The repo should land around 150 tests after v0.3.

## 9. Carry-over scope (non-verification items)

| Item | Files touched | Effort |
|---|---|---|
| `mcp_server.py:432` fix | `gitexpose/advanced/mcp_server.py`, regression test | 0.25h |
| Tier 3 providers | `gitexpose/data/credential_patterns_v02.json`, pattern tests, `docs/COVERAGE.md` entry | 2h |
| GH Actions + pre-commit | `.github/workflows/gitexpose-scan.yml`, `.pre-commit-hooks.yaml`, `docs/INTEGRATIONS_CICD.md` | 1h |
| MITRE ATLAS coverage map | `docs/MITRE_ATLAS_COVERAGE.md` | 2h |
| GH Code Scanning doc | `docs/INTEGRATIONS_CODE_SCANNING.md`, sample workflow | 1h |
| CISA-incident callout | `README.md` "Why this matters" section | 0.5h |
| Repo cleanup | `.gitignore`, `docs/notes/` | 0.5h |

Subtotal: ~7.25h.

## 10. Effort & risk

### 10.1 Effort

| Component | Hours |
|---|---|
| Verification engine core (`engine.py`, `helpers.py`, `result.py`) | 2.0 |
| LLM providers (11 registry one-liners + tests) | 1.5 |
| GitHub PAT + GitLab PAT | 0.5 |
| Docker Hub verifier | 1.0 |
| AWS SigV4 verifier | 1.5 |
| Slack token verifier | 0.5 |
| CLI flags + consent banner | 0.5 |
| Reporter integration (JSON, SARIF, HTML, CSV, console) | 1.0 |
| Tests (units, per-provider, smoke) | 2.0 |
| **Verification subtotal** | **10.5** |
| Carry-over items | 7.25 |
| **Total v0.3** | **~17.75h** |

Realistic ship window: 1.5–2 weeks of part-time work.

### 10.2 Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| AWS SigV4 hand-rolled signing takes longer than 1.5h | Medium | Time-box at 2h; if exceeded, fall back to `botocore.auth.SigV4Auth` (adds `botocore` dep ~30MB transitive — acceptable for v0.3 if needed) |
| Provider API endpoint or response shape changes mid-release | Low | Each verifier is one isolated function; patchable in v0.3.1 without engine changes |
| Rate-limit surprises in CI use against large repos | Medium | Conservative `concurrency=5` default; consent banner names hosts; `--verify-only-severity` gives users a throttle |
| False `VERIFIED` from key misclassification | Very low | Misclassified key sent to wrong provider returns `DEAD` (auth fails). Self-correcting. Covered by a unit test asserting cross-pattern keys do not verify as live |
| Secret leakage via logs or error messages | Low | `redact()` everywhere + sentinel canary test (Section 8.1) |

## 11. Acceptance criteria

v0.3 ships when all of the following hold:

1. `gitexpose scan --verify` and `gitexpose supply-chain --verify` work end-to-end against the synthetic fixture repo, producing correct `VERIFIED` / `DEAD` outcomes for all 16 covered patterns (network-mocked).
2. Per-provider unit tests + engine tests + smoke tests all pass. Total test count ≥ 150.
3. SARIF output validates against the vendored 2.1.0 schema with verification tags present.
4. The consent banner prints to stderr on every `--verify` invocation (unless `--no-verify-banner` is set).
5. Log-leak canary test passes for every verifier.
6. `mcp_server.py:432` bug regression test passes.
7. Tier 3 providers (Helicone, Portkey, Voyage, Cohere, Modal, Runpod) detected on synthetic fixture.
8. Sample GitHub Actions workflow runs cleanly against the fixture repo.
9. `docs/MITRE_ATLAS_COVERAGE.md`, `docs/INTEGRATIONS_CICD.md`, `docs/INTEGRATIONS_CODE_SCANNING.md` exist and are reviewed for accuracy.
10. README has the CISA-incident callout.
11. Repo cleanup landed (`.gitignore` updates, root files moved or ignored).
12. Version bumped to 0.3.0 in `gitexpose/__init__.py`, `pyproject.toml`, `setup.py`. `CHANGELOG.md` updated. Annotated tag `v0.3.0` created.

## 12. Open questions for implementation plan

Deferred to the writing-plans phase, not blocking spec approval:

- Exact ordering of work (verification engine first vs. carry-over items first vs. interleaved).
- Decision on AWS SigV4: hand-rolled vs. `botocore` dependency — committed in code based on time-box outcome, not pre-decided.
- Whether `--verify-only-severity` accepts comma-separated multiple levels or just a single floor (default to floor; revisit if early usage suggests otherwise).
- Whether the consent banner is printed once per invocation or once per provider host group (default to once per invocation).
