# Naming Candidates — From *GitExpose* to an Exposure-Intelligence Tool

> **The brief.** GitExpose started as a git secret scanner. It is becoming an
> **Exposure Intelligence** tool for the **AI-infrastructure layer** — MCP configs,
> agent skill files, model cards, dataset pipelines, LiteLLM proxies, `.claude/settings.json`,
> Hugging Face artifacts, git-metadata credentials, and supply-chain signals — tagged with
> MITRE ATLAS / OWASP-LLM and designed to run *alongside* TruffleHog/Gitleaks, not replace them.
> "Git" in the name now undersells the scope. This doc proposes a new one.

---

## What a good name has to do here

1. **Outgrow "Git".** The git layer is one surface among many (MCP, HF, datasets, agents). The name must not anchor to git.
2. **Signal *exposure intelligence*, not just *scanning*.** The product's edge is context — ATLAS/OWASP tagging, orphan/replication scoring, "runs alongside" dedup — not raw detector count.
3. **Read well to the target audience.** Red-team / threat-intel / AI-security reviewers. It should sound like a tool a senior engineer built, not a weekend regex script.
4. **Be a clean CLI citizen.** Short, lowercase, ASCII binary name. Pronounceable. Typo-resistant.
5. **Avoid the "-leaks" derivative trap.** Gitleaks, Betterleaks, Nosey Parker, Kingfisher, TruffleHog are taken and crowd the "X-leaks" space. Standing apart reads as more original than echoing the category leader.
6. **Carry a little lineage.** Bonus if it nods to "Expose," so anyone who knew GitExpose sees the through-line.

**Scoring legend:** ●●●●● strong · ○○○○○ weak. Criteria: **Fit** (AI-infra exposure-intelligence), **Distinct** (stands apart), **CLI** (binary ergonomics), **Lineage** (continuity from GitExpose), **Clash** (low collision risk = more dots).

---

## Top 3 finalists

### 1. **Exposé**  ·  command: `expose`  ·  *recommended*

An *exposé* is an investigative reveal of something hidden — exactly what the tool
does to secrets buried in AI-infra files. It keeps the **"Expose" brand equity** of
GitExpose while dropping "Git," reframes the product from *scanner* to *intelligence/report*,
and the ASCII command `expose` is clean and memorable.

- **Fit** ●●●●● · **Distinct** ●●●●○ · **CLI** ●●●●● · **Lineage** ●●●●● · **Clash** ●●●○○
- Brand stylized **Exposé**; package/binary ASCII `expose` (verify availability — fall back to `exposecli` / `expose-ai`).
- Risk: "expose" is a common English verb → possible PyPI collision; the accent is brand-only (never in code).

### 2. **Credence**  ·  command: `credence` / `cred`  ·  *most distinctive*

**Cred**ential + intelligen**ce**, and *credence* itself means trust/belief — a tool
that decides which exposed credentials deserve belief (orphan vs. replicated, live vs. dead).
Sophisticated, no "-leaks" baggage, no "git" anchor, and the intelligence framing is *in the word*.

- **Fit** ●●●●○ · **Distinct** ●●●●● · **CLI** ●●●●○ · **Lineage** ●●○○○ · **Clash** ●●●●○
- Loses the GitExpose lineage, but gains the strongest standalone identity on the list.

### 3. **Aperture**  ·  command: `aperture` / `ap`  ·  *cleanest metaphor*

In photography the **aperture controls exposure** — a precise, Dieter-Rams-clean single word
that encodes the product concept without saying "scan." Reads as a deliberate, designed tool.

- **Fit** ●●●●○ · **Distinct** ●●●●○ · **CLI** ●●●●○ · **Lineage** ●●●○○ · **Clash** ●●○○○
- Risk: "Aperture" is a fairly used name (Apple's retired app, Portal's Aperture Science) → higher collision/SEO risk. Distinct enough *in security*, but verify.

---

## The wildcard — maximum positioning legibility

### **AgentLeak** / **AgentLeaks**  ·  command: `agentleak`

If the goal is for a reviewer to understand the product in **one glance**, this is it:
"the Gitleaks/TruffleHog for the *agent* layer." Positioning is baked into the name.

- **Fit** ●●●●○ · **Distinct** ●●●○○ · **CLI** ●●●●○ · **Lineage** ●●●○○ · **Clash** ●●●●○
- Trade-offs: (a) leans into the "-leak" derivative pattern you otherwise want to escape, and
  (b) over-indexes on *agents* when the tool also covers HF datasets, git-metadata, and supply chain.
  Great legibility, slightly narrower brand.

---

## Full scorecard

| Name | Command | Fit | Distinct | CLI | Lineage | Clash | Verdict |
|---|---|:--:|:--:|:--:|:--:|:--:|---|
| **Exposé** | `expose` | ●●●●● | ●●●●○ | ●●●●● | ●●●●● | ●●●○○ | **Finalist — recommended** |
| **Credence** | `credence` | ●●●●○ | ●●●●● | ●●●●○ | ●●○○○ | ●●●●○ | **Finalist — distinctive** |
| **Aperture** | `aperture` | ●●●●○ | ●●●●○ | ●●●●○ | ●●●○○ | ●●○○○ | **Finalist — metaphor** |
| **AgentLeak** | `agentleak` | ●●●●○ | ●●●○○ | ●●●●○ | ●●●○○ | ●●●●○ | Wildcard — max legibility |
| **Floodlight** | `floodlight` | ●●●●○ | ●●●●○ | ●●●○○ | ●●○○○ | ●●●●○ | Strong alt — reveal-in-dark |
| **Lumen** | `lumen` | ●●●○○ | ●●●○○ | ●●●●● | ●●○○○ | ●○○○○ | Clean but Lumen Tech clash |
| **Lantern** | `lantern` | ●●●○○ | ●●●○○ | ●●●●○ | ●●○○○ | ●●●○○ | Approachable, softer |
| **Backlight** | `backlight` | ●●●○○ | ●●●●○ | ●●●○○ | ●●○○○ | ●●●●○ | Subtle reveal metaphor |
| **Daylight** | `daylight` | ●●●○○ | ●●●○○ | ●●●●○ | ●●○○○ | ●●●○○ | "Bring into daylight" |
| **ExposureIQ** | `exposureiq` | ●●●●○ | ●●○○○ | ●●○○○ | ●●●●○ | ●●●○○ | Literal but SaaS-generic |
| **SurfaceIQ** | `surfaceiq` | ●●●○○ | ●●○○○ | ●●○○○ | ●○○○○ | ●●●○○ | Attack-surface framing |
| **AgentExpose** | `agentexpose` | ●●●●○ | ●●●○○ | ●●●○○ | ●●●●○ | ●●●●○ | Explicit, a bit clunky |

---

## Name families (the full idea-space)

- **Lineage (keep "Expose" equity):** Exposé · AgentExpose · ExposureIQ · ExposeAI
- **Photographic exposure:** Aperture · Backlight · Overexpose
- **Light reveals the dark:** Floodlight · Lumen · Lantern · Daylight · Limelight · Searchlight
- **Credential-intelligence coinage:** Credence
- **Positioning-baked (AI/agent):** AgentLeak · AgentExpose · ModelGuard
- **Surface / intel literal:** SurfaceIQ · ExposureIQ

---

## If we rename: the migration cost (so it's eyes-open)

A rename is real churn — flag, don't hand-wave:

1. **PyPI package** — new distribution name. Either publish under the new name fresh, or
   publish a final `gitexpose` release whose description points to the successor.
2. **Console entry points** — `pyproject.toml` `[project.scripts]` (`gitexpose`, `agent-audit`
   today) → new binary names; consider keeping `gitexpose` as a deprecated alias for one minor.
3. **Repo / GitHub** — rename repo (GitHub auto-redirects old URLs), update badges, CI workflow
   names, release-asset naming.
4. **Docs** — README header/tagline, CHANGELOG note, COVERAGE.md, sample GitHub Action, install snippets.
5. **Internal package dir** — optional and *expensive* (`gitexpose/` → `<newname>/` touches every
   import + test). Recommend **keeping the Python package dir `gitexpose/` internally** for v0.8 and
   renaming the *brand + CLI + PyPI dist* only — decouples the user-facing rename from a giant
   import-churn refactor.

**Availability checklist (verify before committing a name):**
- [ ] PyPI distribution name free (`pip index` / pypi.org)
- [ ] GitHub repo/org name free
- [ ] No major security-tool collision (search "<name> security scanner")
- [ ] ASCII CLI binary reads cleanly, no shell builtin clash (`expose`, `cred`, `ap` are safe-ish)
- [ ] Domain optional but nice (`.dev` / `.io`)

---

## Recommendation

**Lead with `Exposé` (command `expose`).** It is the only candidate that scores ●●●●● on both
*Fit* and *Lineage*: it keeps the brand thread from GitExpose, sheds "Git," reframes the tool as
*intelligence/reveal* rather than *scan*, and gives a clean ASCII command. Hold **Credence** as the
strong fallback if `expose`/`exposé` collides on PyPI or you want a fully standalone identity, and
**Aperture** as the design-forward third. Decouple the rename: rebrand **name + CLI + PyPI dist**
now; keep the internal `gitexpose/` package dir to avoid import churn in v0.8.
