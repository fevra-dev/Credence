# AUDIT — GitExpose v0.8 detection modules
Date: 2026-06-03
Input: .audit/FINDINGS.md (13 candidates). Verification: each bypass reproduced against live code
(exploitability gate), then fixed TDD with the reproducer as a permanent regression test.
Shipped as: v0.8.1.

## Verdicts (the 6 HIGH candidates — all verified TP, all fixed)

| ID | Verdict | Reproduced | Fix | Regression test |
|---|---|---|---|---|
| F-001 MCP `<sk_live_>` placeholder hides real cred | **TP** | `mcp_static_credential` absent on `<sk_live_…>` env | `_is_placeholder` now suppresses only when inner text is NOT a secret literal (`_SECRET_LITERAL_RE`, value-prefixes only — not the key-name branch, which kept `${OPENAI_API_KEY}`/`<API_KEY>` benign) | test_real_credential_wrapped_in_angle_brackets_still_fires (+curly, +named-still-suppressed) |
| F-002 off-spec severity escapes `--fail-on high` | **TP** | `exit_code_for([{severity:"Critical "}],"high")==0` | `_rank()` strips+normalizes; present-but-unknown severity → CRITICAL fail-closed + warn; absent/empty still INFO. `exit_code_for` raises ValueError on bad threshold (also closes F-010). | test_offspec_severity_fails_closed_not_open, test_absent_or_empty_severity_still_treated_as_info, test_unknown_fail_on_threshold_raises_valueerror |
| F-003 `[url] insteadOf`/`pushurl` token missed | **TP** | 0 findings on `[url "…TOKEN@github.com/"] insteadOf=` | `_scan_remote_like` now scans the section HEADER + all URL-bearing options (url/pushurl/insteadof/pushinsteadof) | test_insteadof_rewrite_token_is_detected, test_pushurl_token_is_detected |
| F-004 registry world-readable (0644) + poisonable | **TP** (perms) | file mode 0o644 | `save()` writes file 0o600 via `os.open` opener + dir 0o700, umask-proof (chmod after mkdir) | test_registry_file_and_dir_are_not_world_readable |
| F-005 `gho_/ghu_/ghr_/gldt-` + colon-less token missed | **TP** | 0 findings on `gho_…@github.com` | `_PREFIX_RE` extended (gho_/ghu_/ghr_/gldt-/ATBB); new `_USERINFO_RE` colon-less branch → LOW | test_github_oauth_prefix_tokens_detected, test_colonless_token_as_username_is_flagged |
| F-007 `Bearer`/`token` extraHeader missed | **TP** | 0 findings on `extraHeader = AUTHORIZATION: Bearer ghp_…` | `_scan_extraheader` now matches Basic (decode) AND Bearer/token (trailing value) | test_extraheader_bearer_and_token_schemes_detected |

## F-004(b) — poisoning/downgrade (PARTIALLY addressed, tracked)
The registry can still be pre-seeded to inflate `source_frequency` to `replicated`. Permissions fix
(0600) removes the cross-user read/seed vector on a shared host. The deeper hardening (registry as a
FLOOR-only signal that never DOWNGRADES, optional per-install HMAC on stored hashes) is deferred —
`source_frequency` is documented as a triage HINT not a verdict, and never drives severity. Logged for
a future pass; not a v0.8.1 blocker.

## MEDIUM/LOW candidates — deferred to a follow-up (documented, not v0.8.1)
F-006 (debug-print indirection/`logging.log`/`sys.stdout.write` FNs — fundamental limit of name-only
AST matching; the `logging.log(level,…)` re-add behind a receiver guard is the best single follow-up),
F-008 (UTF-8 BOM/line-continuation configparser silent-skip — one-line BOM strip worth doing next),
F-009 (`.git/config` symlink/size guard — DoS/arbitrary-read on untrusted repos; worth doing next),
F-010 (KeyError — FIXED as a side effect of F-002), F-011 (1MB silent-skip no-warning),
F-012 (MCP args/command not scanned), F-013 (known-example still feeds CRITICAL cluster).
These are real but lower product-impact; batch them into a v0.8.2 hardening pass.

## Net
6/6 HIGH findings verified TP and fixed with regression tests; full suite 457 passed / 1 skipped.
No FP regressions (clean configs stay clean; original detections + the original env-passthrough FP
suppression all preserved). CVE-2025-41390 no-subprocess invariant unchanged.
