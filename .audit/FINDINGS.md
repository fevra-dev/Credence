# FINDINGS — GitExpose v0.8 detection modules
Generated: 2026-06-03
Hunters run: vulnhunter (opus), variant-analysis (sonnet), sharp-edges+insecure-defaults (sonnet), manual semgrep-equivalent static pass
Scope: git_config_scanner.py, debug_print.py, mcp_score.py, secret_registry.py, cli_gating.py
Framing: opus-audit-prompts-v2 §2 (Detection Engine) + §4 (Input Parsing). Adversary = evader (cause false-negative) or malicious-input (crash/poison).
(Prior v0.5 audit archived → FINDINGS-v0.5-2026-05-28.md)

## Summary
13 deduped candidates: **0 crit, 6 high, 5 med, 2 low**. Plus strong NEGATIVES: no ReDoS, no subprocess/eval/exec (CVE-2025-41390 invariant holds), urlparse origin-allowlist is exact-match (not bypassable by `.evil.com`/`@evil.com`), config parse failures fail-safe.
Convergence (multiple hunters independently): F-001 (placeholder-suppresses-real-cred ×3), F-002 (off-spec-severity gate ×2), F-006 (debug-print indirection/`.log` ×2). High-confidence cluster.

NOTE: these are CANDIDATES. /audit (fp-check) decides TP/FP. For a detection tool, a reliable false-negative on a CRITICAL-class secret is itself a high-severity product defect even if "working as coded."

---

## Candidates

### F-001  `_PLACEHOLDER_RE` suppresses a REAL credential wrapped in `<...>` / `{{...}}`
- Location: gitexpose/agent_exposure/mcp_score.py:74-79
- Claim: The env-passthrough FP fix (`not _PLACEHOLDER_RE.match(v)`) over-suppresses. `<sk_live_realkey>` and `{{ghp_...}}` match `_PLACEHOLDER_RE` AND `_SECRET_VALUE_RE` → `mcp_static_credential` never fires. Unlike `${VAR}`/`$VAR` (true shell expansion), `<...>`/`{{...}}` are NOT runtime-expanded, so a literal `<realkey>` is a live secret the detector now hides.
- Severity (guess): HIGH (detector converts a true-positive into silence — worst class for a detection tool)
- Reproducer sketch: `mcp.json` → `{"mcpServers":{"x":{"url":"https://mcp.evil.com","env":{"API_KEY":"<sk_live_51RealKeyMaterial>"}}}}` → 0 findings. Verified against code by 2 hunters.
- Fix direction: restrict suppression to `${VAR}`/`$VAR` only; OR if the inner content itself matches `_SECRET_VALUE_RE`, still fire (placeholder named `<API_KEY>` is fine; `<sk_live_…material…>` is not).
- Source: vulnhunter (F-01) + variant-analysis (V3) + sharp-edges (ID-9)

### F-002  Off-spec severity string → rank 0 → escapes default `--fail-on high` gate (fail-open)
- Location: gitexpose/cli_gating.py:22-24
- Claim: `SEVERITY_ORDER.get((f.get("severity") or "INFO").upper(), 0)` maps any non-canonical severity (`"Critical "` trailing space, `"crit"`, `"CRITICAL\n"`, `" HIGH"`, None) to rank 0 → never trips the default `high` gate. This is the single output chokepoint every detector flows through; a real CRITICAL finding with an off-spec severity silently greenlights CI.
- Severity (guess): HIGH (output-integrity fail-open at the gate)
- Reproducer sketch: `exit_code_for([{"severity":"Critical "}], "high")` → returns 0. Verified.
- Fix direction: `.strip()` the severity; map an unrecognized-but-present severity to a **fail-closed default** (treat as CRITICAL + log warning), not 0. "I don't understand this severity" must not mean "ignore it."
- Source: vulnhunter (F-02) + manual static
- Note: variant-analysis confirmed NO current v0.8 detector emits off-spec severity (all canonical), so today this is latent/defensive — but it's the load-bearing gate; fix it fail-closed.

### F-003  `[url] insteadOf` / `pushInsteadOf` / `pushurl` credential rewrite never scanned
- Location: gitexpose/advanced/git_config_scanner.py:88-98 (`_scan_remote_like` only inspects sections with a `url` option)
- Claim: A `[url "https://TOKEN@github.com/"] insteadOf = https://github.com/` section has only an `insteadOf` option → skipped. Git substitutes this credential-bearing prefix into every fetch/push, so the token is live but invisible. Same gap for `pushurl`.
- Severity (guess): HIGH (CRITICAL-class token git actively uses, fully missed)
- Reproducer sketch: `.git/config` with the `[url "...TOKEN...@github.com/"]` block above + a clean `[remote origin]`. Verified MISS.
- Fix direction: scan ALL option values AND section-header text for `_PREFIX_RE`/`_USERPASS_RE`, not just the literal `url` option. Include `insteadof`, `pushinsteadof`, `pushurl`.
- Source: vulnhunter (F-03)

### F-004  Registry world-readable (0644) + unauthenticated → info-leak AND poisoning
- Location: gitexpose/advanced/secret_registry.py:108-111 (`mkdir` + `write_text`, no mode)
- Claim: `~/.gitexpose/registry.json` written at umask-default 0644 (world-readable); parent dir 0755. Contains secret HASHES + source FILE PATHS (which files hold secrets). On a shared CI runner/multi-user host, any user reads it. Separately, it's read back with no integrity check → an attacker (or repo owner gaming a scan) pre-seeds `{<sha256 of real secret>: [60 fake sources]}` → `frequency_band` returns `replicated` → triage tooling deprioritizes a real private leak. Hash is unsalted SHA256 of the normalized value, which the repo owner can compute.
- Severity (guess): HIGH (info-leak default + triage-suppression poisoning)
- Reproducer sketch: enable `--track` on a shared host → `cat ~/.gitexpose/registry.json` as another user. Poisoning: seed registry.json before scan. Verified.
- Fix direction: (a) `os.open(..., 0o600)` for the file + `makedirs(mode=0o700)` then `chmod` (umask-proof); (b) registry should only be a FLOOR signal — a high cross-source count must never DOWNGRADE priority/severity, only the local single-source observation drives `orphan_candidate`; (c) optional per-install HMAC key on stored hashes so a foreign registry can't pre-target a known secret.
- Source: sharp-edges (ID-1) + vulnhunter (F-04)

### F-005  GitHub `gho_`/`ghu_`/`ghr_`, GitLab `gldt-`, colon-less token-as-username missed
- Location: gitexpose/advanced/git_config_scanner.py:33 (`_PREFIX_RE`) + 35 (`_USERPASS_RE`)
- Claim: `_PREFIX_RE` covers only `ghp_|github_pat_|ghs_|glpat-|hf_`. GitHub OAuth/user/refresh tokens (`gho_`/`ghu_`/`ghr_`), GitLab deploy (`gldt-`), Bitbucket (`ATBB`) are absent. When such a token is in userinfo WITHOUT a colon (`https://TOKEN@host` — valid git form), `_USERPASS_RE` (requires `user:pass@`) ALSO misses → zero findings on a live token.
- Severity (guess): HIGH (real CRITICAL-class tokens entirely missed)
- Reproducer sketch: `url = https://gho_RealOAuthToken@github.com/x/y` → both regexes MISS. Verified.
- Fix direction: add `gho_|ghu_|ghr_|gldt-|ATBB` to `_PREFIX_RE`; add a colon-less userinfo branch `https?://[^/\s:@]{20,}@[^/\s]+` → at least LOW.
- Source: vulnhunter (F-05)

### F-006  Debug-print evaded by indirection, `logging.log(level,...)`, `sys.stdout.write`, concat
- Location: gitexpose/agent_exposure/debug_print.py:38-62 (name-only positional-arg matching)
- Claim: Fires only on a credential-NAMED Name/Attribute as a positional arg to print/logging.<level>. Misses: `x=api_key; print(x)` (indirection); `logging.log(INFO, api_key)` / `logger.log(20, token)` (`.log` deliberately excluded to kill the np.log FP — but real log() now missed); `sys.stdout.write(api_key)`; `msg='k='+api_key; print(msg)` (concat); keyword args & aliased `p=print` (already-documented FNs).
- Severity (guess): MEDIUM (broad low-effort FN class on the headline arXiv-cited detector; name-only matching is a known fundamental limit)
- Reproducer sketch: the snippets above. Verified DETECTED still: direct `print(api_key)`, f-string, `.format`, `%`.
- Fix direction: re-add `log` behind a receiver guard (`func.value` is `logging`/`logger`-ish → fires `logger.log(INFO,token)`, excludes `np.log`); optional intra-function alias taint for indirection; document `sys.stdout.write` FN alongside the kwarg note.
- Source: vulnhunter (F-06) + variant-analysis (V1)

### F-007  `extraHeader` only matches `Basic`; `Bearer`/`token` schemes missed
- Location: gitexpose/advanced/git_config_scanner.py:130 (`re.search(r"Basic\s+...")`)
- Claim: A PAT carried as `extraHeader = AUTHORIZATION: Bearer ghp_...` or `token <pat>` is not detected at all (no `Basic` substring). Plaintext, live.
- Severity (guess): MEDIUM (real HIGH-class PAT, no finding)
- Reproducer sketch: `[http "https://github.com/"] extraHeader = AUTHORIZATION: Bearer ghp_RealToken`. Verified MISS.
- Fix direction: match `(Basic|Bearer|token)\s+(\S+)`; b64-decode Basic, run `_PREFIX_RE` directly on Bearer/token value.
- Source: vulnhunter (F-07)

### F-008  UTF-8 BOM (and backslash line-continuation) crash configparser → whole config silently skipped
- Location: gitexpose/advanced/git_config_scanner.py:46-55 (`_read`, `except configparser.Error: return None`)
- Claim: A leading UTF-8 BOM (from some Windows editors) raises `MissingSectionHeaderError` (a `configparser.Error`) → caught → ENTIRE file skipped → clean report on a repo with a real credential. Backslash line-continuation in a URL is a parser-differential variant (git joins lines; configparser keeps the `\` → `_PREFIX_RE` fails on the split token).
- Severity (guess): MEDIUM (silent FN — worst class; trigger is unusual but real)
- Reproducer sketch: prepend a UTF-8 BOM to a `.git/config` containing a `ghp_` remote URL → 0 findings. Verified `MissingSectionHeaderError`.
- Fix direction: strip a leading BOM before `read_string`; post-process values with `re.sub(r'\\\n\s*','',value)` to match git's line-join.
- Source: variant-analysis (V2, V4)

### F-009  `.git/config` symlink followed, no size guard before read → path-traversal read + DoS
- Location: gitexpose/advanced/git_config_scanner.py:151-158 (`is_file()` then `read_text()`, no `is_symlink`/size check)
- Claim: `git_config_scanner.scan` is the ONLY code that opens anything under `.git/` (the walk skips `.git/`), and it does so with no symlink or size guard. A malicious repo where `.git/config` is a symlink to `/dev/zero`/100GB-sparse → `read_text()` hangs/OOM (DoS); symlink to `~/.ssh/id_rsa`/`/proc/self/environ` → reads arbitrary file into memory. The 1MB cap in local_fs_scanner does NOT apply here (separate code path).
- Severity (guess): MEDIUM (DoS / arbitrary-file read on scanning an untrusted repo)
- Reproducer sketch: `ln -s /dev/zero target/.git/config; gitexpose supply-chain target`. Verified the read path has no guard.
- Fix direction: `if git_config.is_symlink(): skip+warn`; add `stat().st_size > _MAX_BYTES` guard before `read_text` (mirror local_fs_scanner).
- Source: sharp-edges (ID-5)

### F-010  `exit_code_for` KeyError on unrecognized `fail_on` (programmatic callers)
- Location: gitexpose/cli_gating.py:22 (`SEVERITY_ORDER[fail_on.upper()]` bare subscript)
- Claim: Click's `Choice` protects the CLI, but a library caller passing `"none"`/`""`/`"crit"` gets an unhandled `KeyError` traceback instead of a clean error/int. Signature implies int return.
- Severity (guess): LOW (CLI safe; API footgun)
- Reproducer sketch: `exit_code_for([], "none")` → KeyError. Verified.
- Fix direction: `.get()` + explicit `raise ValueError(f"unknown severity {fail_on!r}")`.
- Source: sharp-edges (ID-2) + manual static

### F-011  1MB per-file cap silently skips files with NO warning (fail-open)
- Location: gitexpose/agent_exposure/debug_print.py:100-101 (`continue`, no log); gitexpose/advanced/local_fs_scanner.py:55-56 (size-skip, no log)
- Claim: A real secret in a 1.1MB file (vendored SDK, compiled proto, large fixture) is silently missed; scan reports 0 findings / exit 0. The skip isn't logged even at DEBUG in debug_print.
- Severity (guess): MEDIUM (fail-open default, invisible to operator)
- Reproducer sketch: 1.1MB `.py` with `print(api_key)` → not scanned, no warning. Verified no log at the size-skip.
- Fix direction: `logger.warning(...)` at the size-skip; surface skipped-file count in summary.
- Source: sharp-edges (ID-4)

### F-012  MCP `command`/`args` not scanned for embedded secrets (scorer fails open)
- Location: gitexpose/agent_exposure/mcp_score.py:140-156 (`parse_servers` discards command/args) + 60-137 (`score_server` only reads `env`)
- Claim: `{"command":"npx","args":["--token","ghp_realtoken"],"env":{}}` scores 85/100, emits no `mcp_static_credential`, exits 0 under default gate. The Grant-based adapter DOES extract args, but the posture scorer is a separate narrower pipeline.
- Severity (guess): MEDIUM (static cred in args array missed entirely by the scorer)
- Reproducer sketch: the config above. Verified args discarded by parse_servers.
- Fix direction: carry `args` through parse_servers (flattened) and apply `_SECRET_VALUE_RE`; or route the scorer through the adapter's data shape.
- Source: sharp-edges (ID-8)

### F-013  known-example downgrade still feeds a CRITICAL credential_cluster
- Location: gitexpose/advanced/secret_registry.py:enrich (downgrades example→INFO) + gitexpose/advanced/credential_cluster.py:46-64 (`_is_secret` checks type, not severity)
- Claim: `enrich` downgrades `AKIAIOSFODNN7EXAMPLE` to INFO, but `credential_cluster._is_secret` keys on `type` not `severity`, so the example still counts toward a 2-type cluster → `credential_cluster` emitted at CRITICAL partly on a known-harmless key.
- Severity (guess): LOW (severity-inflation FP, not a miss)
- Reproducer sketch: repo with `AKIAIOSFODNN7EXAMPLE` + one real key → CRITICAL cluster. Verified the type-not-severity check.
- Fix direction: `_is_secret` (or the cluster member filter) should drop `severity == "INFO"` findings before counting.
- Source: sharp-edges (ID-7)

---

## Negatives (verified clean — useful for /audit)
- **No ReDoS:** all 5 regexes are linear; 50-60KB adversarial inputs complete in <2ms. No nested quantifiers over overlapping classes.
- **CVE-2025-41390 invariant HOLDS:** no `subprocess`/`os.system`/`eval`/`exec`/`Popen` in any of the 5 modules (only a docstring mention). git module is pure text parsing.
- **Origin allowlist is exact-host, NOT substring:** `mcp.stripe.com.evil.com` → flagged; `mcp.stripe.com@evil.com` → urlparse host = evil.com → flagged. No allowlist bypass. (trailing-dot `mcp.stripe.com.` over-flags LOW — cosmetic FP, not evasion.)
- **Config parse failures fail SAFE** (return None, scan continues) — no crash outside the try; per-file isolation in debug_print prevents one bad file aborting the scan.
- **1MB cap IS checked before read** in debug_print (via `stat().st_size`) — `ast.parse` can't be fed an unbounded file that way (the gap is the separate git_config path, F-009).
- **No off-spec severity emitted by any current v0.8 detector** (all canonical uppercase) — F-002 is latent/defensive, not currently triggered.

## Recommended /audit priority
fp-check these first (highest product impact): **F-001** (hides a real cred), **F-002** (fail-open gate), **F-003 + F-005 + F-007** (git-config coverage gaps — an attacker keeps a working token the scanner can't see), **F-004** (registry perms + poisoning). Then the MEDIUM silent-FN cluster (F-008, F-009, F-011, F-012).
