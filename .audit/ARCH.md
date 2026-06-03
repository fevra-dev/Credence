# ARCH — GitExpose v0.8 detection modules (focused audit surface)

Generated: 2026-06-02
Chain: Generic (Python security scanner — no blockchain)
Audit framing: opus-audit-prompts-v2 §2 (Detection Engine / Signature Logic) + §4 (Input Parsing).
Domain Risk Matrix: detection signature → **Hard / every change**. This is a detection tool;
the threat model is an **attacker who knows the detector exists and wants to evade it**, plus a
**malicious input file that the scanner parses** (the scanner runs against untrusted repos).

## Target / trust level

GitExpose scans **untrusted local repositories and files**. Inputs are attacker-controllable:
`.git/config`, `.gitmodules`, agent/skill `*.py`, `mcp.json`, and arbitrary text files. Output
is finding-dicts → console / JSON / SARIF, consumed by CI gating (`--fail-on`) and humans.
Two adversary goals: (1) **evasion** — hide a real secret/risk so the scanner misses it (false
negative); (2) **abuse** — craft input that crashes the scan, causes resource exhaustion, or
poisons output (false positive / DoS / RCE). The CVE-2025-41390 class (RCE via malicious
`.git/config` `core.fsmonitor`) is the marquee threat for the git module.

## Modules in scope

### 1. `gitexpose/advanced/git_config_scanner.py` (163 LOC) — git-metadata credential parser
- **What it does:** parses `.git/config` + `.gitmodules` with `configparser` (strict=False,
  allow_no_value=True, interpolation=None), classifies `[remote]/[submodule] url=` and
  `[http] extraHeader=` for embedded credentials. Emits CRITICAL/HIGH/LOW findings.
- **Inputs (attacker-controlled):** raw `.git/config` / `.gitmodules` text.
- **Key invariant:** MUST NEVER invoke git (CVE-2025-41390). Parses as text only.
- **Detection heuristics to stress:** `_PREFIX_RE` (ghp_/github_pat_/ghs_/glpat-/hf_ + {8,}),
  `_USERPASS_RE` (`https?://[^/\s:@]+:[^/\s@]+@[^/\s]+`), base64 decode of extraHeader Basic.
- **Evasion questions:** What credential-bearing config does NOT match these regexes? Does
  configparser's parsing differ from git's (parser differential → a cred git reads but we miss)?
  `include.path`/`includeIf` directives (git follows them; we don't → FN). Multi-value `url=`
  (configparser keeps last → FN if first line has the cred). Case/whitespace/quoting tricks.
  Non-`Basic` auth schemes in extraHeader. Token prefixes outside the 5 listed (Bitbucket,
  Gitea, AWS CodeCommit, npm). Does a malformed config throw outside the try → crash the scan?

### 2. `gitexpose/agent_exposure/debug_print.py` (109 LOC) — credential-print AST detector
- **What it does:** `ast.parse` each `*.py`, walks Call nodes; flags `print()`/`logging.<level>()`
  whose positional args reference a credential-named Name/Attribute (`_CRED_NAME_RE`).
- **Inputs (attacker-controlled):** arbitrary Python source.
- **Detection heuristics to stress:** `_CRED_NAME_RE` (api_key|apikey|access_key|secret|
  client_secret|token|bearer|password|passwd|credential|private_key), `_LOGGING_LEVELS`
  (debug/info/warning/warn/error/critical/exception — note: `log` removed to avoid np.log FP).
- **Evasion questions:** Every way to leak a credential to stdout/logs that this MISSES:
  keyword args (documented FN), `sys.stdout.write`, `%`/`.format()`/`+` concatenation building a
  string then printing it, `logging.log(INFO, x)` (level-as-arg, `.log` not in set), f-string with
  a credential in a nested call, aliased print (`p = print; p(api_key)`), `os.write(1, ...)`,
  rich.print, an indirection through a non-credential-named variable (`x = api_key; print(x)` →
  miss). Resource: a giant/deeply-nested .py → `ast.parse` cost? Bytes cap is 1MB.

### 3. `gitexpose/agent_exposure/mcp_score.py` (156 LOC) — MCP posture scorer
- **What it does:** scores an MCP server 0-100; emits per-issue findings (static cred, plaintext
  http, unknown origin, unpinned version) + INFO posture summary.
- **Inputs (attacker-controlled):** `mcp.json` server dict.
- **Detection heuristics to stress:** `_SECRET_VALUE_RE` (sk_live_/sk-/ghp_/glpat-/hf_/AKIA/xox..
  OR _KEY/_TOKEN/_SECRET/PASSWORD/APIKEY), `_PLACEHOLDER_RE` (${..}|$VAR|{{..}}|<..>),
  `KNOWN_MCP_SERVERS` allowlist, `_host` via urlparse.
- **Evasion questions:** A real static credential that evades `mcp_static_credential` —
  e.g. a literal secret whose value matches `_PLACEHOLDER_RE` shape (`<sk_live_realkey>`? does
  the placeholder suppression now HIDE a real cred?), a secret in a non-`env` field (args, url
  query, headers), `auth: "oauth"` set while still embedding a static cred (oauth gate suppresses).
  Origin-allowlist bypass: `https://mcp.stripe.com.evil.com` (does `_host` substring-match or exact?
  it's exact hostname, but check), `https://mcp.stripe.com@evil.com` (urlparse hostname = evil.com,
  good — confirm), uppercase host, trailing dot `mcp.stripe.com.`, IDN/punycode homoglyph.
  Plaintext-http bypass: `HTTP://`, `hxxp`, missing scheme. Score gaming: stack bonuses to mask
  deductions. urlparse exceptions (ValueError/UnicodeError caught — anything else?).

### 4. `gitexpose/advanced/secret_registry.py` (138 LOC) — orphan cross-source signal + hash registry
- **What it does:** `enrich()` mutates secret findings: adds SHA256 `secret_value_hash`,
  `source_frequency` band; persists hashes (NOT raw values) to `~/.gitexpose/registry.json`.
- **Inputs (attacker-controlled):** finding-dicts (derived from scanned files); the registry file
  itself if an attacker can write `~/.gitexpose/registry.json`.
- **Privacy invariant:** raw secret values MUST NEVER hit disk. Source labels (file paths) DO.
- **Evasion questions:** Can a raw value leak to disk via any path (exception, the source-label
  list, a finding key)? `normalize()` (strip+unquote) collision: two different secrets → same hash
  (`pass%2Bword` vs `pass+word`) — intentional for dedup, but can an attacker force a collision to
  mislabel a real orphan as `replicated` (suppress priority)? Registry poisoning: a pre-seeded
  `registry.json` with attacker-chosen hashes/counts inflates `source_frequency` → demotes a real
  leak below triage. Malformed registry JSON (caught → reset to {}). `_is_secret_finding` heuristic
  — what secret finding does it NOT recognize (→ no hash, no fingerprint, escapes dedup)? Is the
  registry file written world-readable (mode)? Concurrent writers (no lock) → corruption / lost
  hashes under CI parallelism.

### 5. `gitexpose/cli_gating.py` (42 LOC) — `--fail-on` severity exit gate
- **What it does:** `exit_code_for(findings, fail_on)` → 1 if any finding severity >= threshold.
- **Detection heuristics to stress:** severity normalization `(f.get("severity") or "INFO").upper()`.
- **Evasion questions:** A finding that should gate but doesn't — a non-standard/missing/None/
  lowercase/whitespace severity string → defaults to INFO rank 0 → escapes a default `high` gate
  (a real CRITICAL finding mislabeled `"Critical "` or `"crit"` → rank 0 → CI passes). Is that an
  output-integrity bug where a detector elsewhere emits an off-spec severity?

## Cross-cutting

- **Parser differential** (§4): configparser vs git; ast vs python runtime; urlparse vs browser/curl.
- **Silent failure** is the worst class here (opus-prompts §15): wrong/empty result, no exception —
  e.g. a try/except that swallows a parse error and returns `[]` (scan reports clean on a repo that
  actually has a leak). Every `except: return []` / `continue` is a candidate silent-FN site.
- **ReDoS:** check every regex (`_PREFIX_RE`, `_USERPASS_RE`, `_CRED_NAME_RE`, `_SECRET_VALUE_RE`,
  `_PLACEHOLDER_RE`) for catastrophic backtracking on adversarial input.
- **Resource exhaustion:** 1MB per-file cap exists; is it enforced everywhere before read/parse?

## Out of scope for this pass
Pre-v0.8 modules (web scanner, verification, OSV, cyclonedx), the rename (cosmetic), CI config.
Focus: the 5 modules above, evasion + parser-abuse framing.
