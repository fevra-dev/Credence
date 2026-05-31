# GitExpose v0.6.1 CLI Entry-Point Unification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the installed `gitexpose` binary expose the advanced subcommands (`supply-chain`, `git-history`, `agent-audit`, …) while preserving today's bare-target `gitexpose example.com` web scan — a non-breaking v0.6.1 patch that fixes the broken sample GitHub Action and pre-commit hook.

**Architecture:** The unified group already exists as `cli_advanced.cli`. The entry point `gitexpose.cli:main` is rewritten as a thin wrapper that prepends a default `scan` command when argv doesn't name a subcommand (and isn't `--help`/`--version`), then delegates to the group. The mature web scanner (`cli.py`) becomes the canonical `scan`; the advanced multi-module aggregator is renamed `full-audit`. Import direction stays one-way (`cli_advanced` imports `cli`; `cli`'s import of the group is lazy, inside `main()`), so there is no cycle and the entry-point string is unchanged.

**Tech Stack:** Python ≥3.9, `click`. Tests: `pytest`, `click.testing.CliRunner`. Run tests with `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/` (system Python, NOT `uv run`).

**Spec:** `docs/superpowers/specs/2026-05-31-cli-entry-point-unification-design.md`

---

## File Structure

**Modify:**
- `gitexpose/cli_advanced.py` — rename the `scan` aggregator → `full-audit`; fix the stale `version_option`; register the web scanner as `scan` (bottom-of-file import).
- `gitexpose/cli.py` — rename the web-scan command `main` → `scan`; add the `_route_argv` helper + new thin `main()` wrapper (lazy group import).
- `tests/test_supply_chain_cli.py` — update the one test that invokes the old `cli.main` web-scan command.
- `pyproject.toml`, `gitexpose/__init__.py` — version → `0.6.1`.
- `README.md`, `CHANGELOG.md`, `docs/v0.6-planning-notes.md` — docs.

**Create:**
- `tests/test_cli_routing.py` — routing tests (the §5 behavior matrix) + group command-resolution tests.

**Import direction (no cycle):** `cli_advanced.py` imports `cli.py` (for the `scan` command, at the bottom). `cli.py` imports `cli_advanced.py` **only inside `main()`** (lazy), never at module top. So importing `cli_advanced` fully assembles the group (including `scan`); importing `cli` alone is cycle-free.

---

## Task 1: Rename the advanced aggregator → `full-audit` + fix the stale version

**Files:**
- Modify: `gitexpose/cli_advanced.py`
- Test: `tests/test_cli_routing.py` (create)

- [ ] **Step 1: Write failing tests in `tests/test_cli_routing.py`**

```python
"""Routing + command-resolution tests for the unified `gitexpose` CLI (v0.6.1)."""

import gitexpose
from click.testing import CliRunner

from gitexpose.cli_advanced import cli


def test_full_audit_command_registered():
    # the advanced multi-module aggregator now lives under `full-audit`
    assert "full-audit" in cli.commands


def test_version_option_matches_package():
    # the group's --version must reflect the real package version, not a stale literal
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert gitexpose.__version__ in result.output
```

- [ ] **Step 2: Run to verify failure**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_cli_routing.py -v`
Expected: FAIL — `full-audit` not in commands (it's still `scan`); `--version` prints `0.4.0`, not the package version.

- [ ] **Step 3: Add the package-version import to `gitexpose/cli_advanced.py`**

Find the import block (after `import click`, near the top) and add:

```python
from . import __version__
```

- [ ] **Step 4: Fix the stale `version_option` in `gitexpose/cli_advanced.py`**

Change:

```python
@click.version_option(version="0.4.0", prog_name="GitExpose")
def cli():
```

to:

```python
@click.version_option(version=__version__, prog_name="GitExpose")
def cli():
```

- [ ] **Step 5: Rename the aggregator command in `gitexpose/cli_advanced.py`**

The first command on the group is the multi-module aggregator. Change its decorator and function name (body unchanged):

```python
@cli.command()
...
def scan(target, concurrency, timeout, output, out_file, git_dump, react2shell,
         ml_models, llm_exposure, unicode_detect, source_maps, cicd, api_discovery,
         full_audit, verbose, quiet):
```

to:

```python
@cli.command("full-audit")
...
def full_audit(target, concurrency, timeout, output, out_file, git_dump, react2shell,
               ml_models, llm_exposure, unicode_detect, source_maps, cicd, api_discovery,
               full_audit, verbose, quiet):
```

> Only the `@cli.command()` → `@cli.command("full-audit")` line and the `def scan(` → `def full_audit(` line change. The decorator stack (`@click.argument`, the `@click.option`s) and the entire function body stay byte-for-byte the same. Note the existing `full_audit` *parameter* (from `--full-audit`) is unrelated to the new function name — both can coexist.

- [ ] **Step 6: Run tests to verify pass**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_cli_routing.py -v`
Expected: both PASS.

- [ ] **Step 7: Run the full suite (no regressions from the rename)**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/ -q`
Expected: all green (no test invokes the group's `scan` by name — verified during planning).

- [ ] **Step 8: Commit**

```bash
git add gitexpose/cli_advanced.py tests/test_cli_routing.py
git commit -m "refactor(v0.6.1): rename advanced scan aggregator -> full-audit; fix stale --version"
```

---

## Task 2: Web scanner becomes `scan`; wrapper `main()`; register on group

**Files:**
- Modify: `gitexpose/cli.py`, `gitexpose/cli_advanced.py`, `tests/test_supply_chain_cli.py`
- Test: `tests/test_cli_routing.py` (append)

- [ ] **Step 1: Append failing tests to `tests/test_cli_routing.py`**

```python
from gitexpose.cli import _route_argv


def _known():
    return set(cli.commands)


def test_bare_target_routes_to_scan():
    assert _route_argv(["example.com"], _known()) == ["scan", "example.com"]


def test_bare_target_with_options_routes_to_scan():
    assert _route_argv(["example.com", "-o", "sarif"], _known()) == \
        ["scan", "example.com", "-o", "sarif"]


def test_leading_option_routes_to_scan():
    # the tricky case: a leading flag still means "web scan"
    assert _route_argv(["-f", "targets.txt"], _known()) == ["scan", "-f", "targets.txt"]


def test_explicit_scan_unchanged():
    assert _route_argv(["scan", "example.com"], _known()) == ["scan", "example.com"]


def test_subcommands_unchanged():
    for cmd in ("supply-chain", "git-history", "agent-audit", "full-audit"):
        assert _route_argv([cmd, "."], _known()) == [cmd, "."]


def test_version_and_help_passthrough():
    assert _route_argv(["--version"], _known()) == ["--version"]
    assert _route_argv(["--help"], _known()) == ["--help"]
    assert _route_argv(["-h"], _known()) == ["-h"]


def test_no_args_unchanged():
    assert _route_argv([], _known()) == []


def test_group_exposes_scan_and_subcommands():
    names = set(cli.commands)
    assert {"scan", "full-audit", "supply-chain", "git-history", "agent-audit"} <= names


def test_scan_subcommand_is_web_scanner_with_sarif():
    # SARIF is unique to the mature web scanner (cli.py) — proves `scan` is the right one
    result = CliRunner().invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "sarif" in result.output
```

- [ ] **Step 2: Run to verify failure**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_cli_routing.py -v`
Expected: FAIL — `cli._route_argv` doesn't exist; `scan` not in `cli.commands`.

- [ ] **Step 3: In `gitexpose/cli.py`, rename the web-scan command `main` → `scan`**

Change the command decorator (currently `@click.command()` above `def main(`):

```python
@click.command()
@click.argument("targets", nargs=-1)
```

to:

```python
@click.command("scan")
@click.argument("targets", nargs=-1)
```

and change the function signature line:

```python
def main(
    targets: tuple,
```

to:

```python
def scan(
    targets: tuple,
```

> Only the decorator name and `def main(` → `def scan(` change. All options and the entire body (version flag, scanner, reporters, exit codes) stay identical. This command object's name is now `"scan"`.

- [ ] **Step 4: In `gitexpose/cli.py`, replace the `if __name__` block with the routing helper + new `main()` wrapper**

Change the tail of the file:

```python
if __name__ == "__main__":
    main()
```

to:

```python
_PASSTHROUGH = {"--help", "-h", "--version"}


def _route_argv(argv, known):
    """Prepend the default `scan` command unless argv already names a subcommand
    or is a group-level --help/--version. Keeps bare-target `gitexpose <host>` and
    leading-option `gitexpose -f targets.txt` routing to the web scanner."""
    if argv and argv[0] not in known and argv[0] not in _PASSTHROUGH:
        return ["scan", *argv]
    return list(argv)


def main():
    """Console entry point: the unified `gitexpose` group with a default `scan` command."""
    from .cli_advanced import cli as cli_group  # lazy import → no import cycle
    known = set(cli_group.commands)
    cli_group.main(args=_route_argv(sys.argv[1:], known), prog_name="gitexpose")


if __name__ == "__main__":
    main()
```

> `sys` is already imported at the top of `cli.py`. `main()` is now a plain function (the entry point), not a click command.

- [ ] **Step 5: In `gitexpose/cli_advanced.py`, register the web scanner as `scan` (bottom of file)**

At the very end of the file, immediately before the existing `if __name__ == "__main__":` block, add:

```python
# Register the mature web scanner (gitexpose/cli.py) as the canonical `scan` subcommand.
# Imported here (not in cli.py at module level) so the import stays one-way / cycle-free.
from .cli import scan as _web_scan  # noqa: E402
cli.add_command(_web_scan)
```

> If the file ends with `if __name__ == "__main__":\n    cli()`, place the two lines above it. The `scan` command's registered name comes from `@click.command("scan")`.

- [ ] **Step 6: Update the now-broken test in `tests/test_supply_chain_cli.py`**

Replace `test_main_cli_accepts_sarif_output_format` (it invokes the old `cli.main` web-scan command, which is now the plain wrapper):

```python
def test_main_cli_accepts_sarif_output_format():
    """`gitexpose --help` lists sarif as an output choice."""
    from click.testing import CliRunner

    from gitexpose.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert "sarif" in result.output
```

with:

```python
def test_main_cli_accepts_sarif_output_format():
    """`gitexpose scan --help` lists sarif as an output choice."""
    from click.testing import CliRunner

    from gitexpose.cli import scan

    runner = CliRunner()
    result = runner.invoke(scan, ["--help"])
    assert "sarif" in result.output
```

- [ ] **Step 7: Run tests to verify pass**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_cli_routing.py tests/test_supply_chain_cli.py -v`
Expected: all PASS.

- [ ] **Step 8: Run the full suite**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/ -q`
Expected: all green.

- [ ] **Step 9: Commit**

```bash
git add gitexpose/cli.py gitexpose/cli_advanced.py tests/test_cli_routing.py tests/test_supply_chain_cli.py
git commit -m "feat(v0.6.1): unify CLI entry point — gitexpose binary exposes all subcommands, bare-target preserved"
```

---

## Task 3: Version bump + docs

**Files:**
- Modify: `pyproject.toml`, `gitexpose/__init__.py`, `README.md`, `CHANGELOG.md`, `docs/v0.6-planning-notes.md`

- [ ] **Step 1: Bump version to 0.6.1**

In `pyproject.toml`: `version = "0.6.0"` → `version = "0.6.1"`.
In `gitexpose/__init__.py`: `__version__ = "0.6.0"` → `__version__ = "0.6.1"`.

> The entry-point string `gitexpose = "gitexpose.cli:main"` in both `pyproject.toml` and `setup.py` stays unchanged — `main` is now the wrapper.

- [ ] **Step 2: Add a `CHANGELOG.md` v0.6.1 section** (immediately under `# Changelog`)

```markdown
## v0.6.1 — 2026-05-31 — CLI entry-point unification

### Fixed
- The installed `gitexpose` binary now exposes the advanced subcommands — `scan`, `supply-chain`, `git-history`, `agent-audit`, `react2shell`, `ml-scan`, `llm-scan`, `unicode-scan`, `mcp`, `list-tools`, `full-audit`. Previously the console script only ran the web scanner, so the documented `gitexpose supply-chain`/`git-history`/`agent-audit` commands (and the sample GitHub Action + pre-commit hook) didn't work from an install — they required `python -m gitexpose.cli_advanced`.
- The group's `--version` reported a stale `0.4.0`; it now reflects the package version.

### Changed
- Bare-target `gitexpose <host>` and `gitexpose -f targets.txt` still run the web scanner (now the default `scan` command) — **non-breaking**.
- The advanced multi-module aggregator (`--full-audit` sweep) moved from `scan` to **`gitexpose full-audit`**; the mature web scanner is the canonical `gitexpose scan`. (Its sub-modules `react2shell`/`ml-scan`/`llm-scan`/`unicode-scan` remain standalone subcommands.)
```

- [ ] **Step 3: Update `README.md`**

- Version badge → `0.6.1`.
- Where the Quick Start shows web-scan vs. subcommands, confirm both forms work and add a one-liner distinguishing the two scans:

```bash
# Bare target still works (web scan)
gitexpose example.com -o sarif

# Equivalent explicit form
gitexpose scan example.com -o sarif

# Multi-module aggregate sweep (react2shell + ml + llm + unicode + …)
gitexpose full-audit example.com --full-audit
```

The existing `gitexpose supply-chain …`, `gitexpose git-history …`, and `gitexpose agent-audit …` examples now work as written from the installed binary — no edits needed beyond confirming they're present.

- [ ] **Step 4: Close the entry-point gap in `docs/v0.6-planning-notes.md`**

Under the "Known gap" section, mark it resolved:

```markdown
> **RESOLVED in v0.6.1** — the `gitexpose` binary now exposes all subcommands via a unified
> group with a default `scan` (bare-target preserved). The advanced aggregator moved to
> `full-audit`. See docs/superpowers/specs/2026-05-31-cli-entry-point-unification-design.md.
```

And remove "Unify the CLI entry point" from the v0.7 backlog list (it's done).

- [ ] **Step 5: Run the full suite, then commit**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/ -q`
Expected: all green.

```bash
git add pyproject.toml gitexpose/__init__.py README.md CHANGELOG.md docs/v0.6-planning-notes.md
git commit -m "docs(v0.6.1): bump to 0.6.1; CHANGELOG + README + close entry-point gap"
```

---

## Task 4: Manual verification (pre-release gate)

> Manual maintainer step before tagging — same gated pattern as v0.5.1/v0.6.0. Uses an editable install so the real `gitexpose` console script is exercised (not just `python -m`).

- [ ] **Step 1: Editable install into a scratch venv**

```bash
/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m venv /tmp/ge-061-venv
/tmp/ge-061-venv/bin/pip install -q -e . 2>&1 | tail -2
```

- [ ] **Step 2: Verify the binary now exposes subcommands + bare-target both work**

```bash
mkdir -p /tmp/ge-061/.cursor && echo '{"mcpServers":{"sh":{"command":"bash"}}}' > /tmp/ge-061/.cursor/mcp.json
/tmp/ge-061-venv/bin/gitexpose --version            # expect 0.6.1
/tmp/ge-061-venv/bin/gitexpose --help               # expect the command list incl scan/supply-chain/agent-audit/full-audit
/tmp/ge-061-venv/bin/gitexpose agent-audit /tmp/ge-061 -o json | head   # expect a CRITICAL shell_exec finding (exit 1)
/tmp/ge-061-venv/bin/gitexpose supply-chain /tmp/ge-061 --offline       # expect it to run (no "No such command")
/tmp/ge-061-venv/bin/gitexpose scan --help          # expect sarif in the output choices
```
Expected: `--version` → `GitExpose v0.6.1` (or `0.6.1`); `agent-audit`/`supply-chain` run their commands (the v0.6.0 binary would have treated these as targets); `scan --help` shows `sarif`.

- [ ] **Step 3: Clean up**

```bash
rm -rf /tmp/ge-061 /tmp/ge-061-venv
```

- [ ] **Step 4: If green, ship** — merge `v0.6.1` → `main`, tag `v0.6.1`, push `main` + `v0.6.1` + the tag via `git push origin refs/tags/v0.6.1` (avoids branch/tag ambiguity), let the Release workflow build wheel+sdist, then `gh release edit v0.6.1 --notes-file …`. Confirm the self-scan GitHub Action (`gitexpose-scan.yml`) now succeeds (it was failing precisely because `gitexpose supply-chain .` didn't resolve).

---

## Self-Review (completed during planning)

**1. Spec coverage** — every spec section maps to a task:
- §3 mechanism (argv preprocessing, `_route_argv`, lazy group import, no cycle) → Task 2.
- §4 component changes: `cli.py` rename + wrapper → Task 2; `cli_advanced.py` rename + version fix + scan registration → Tasks 1 & 2; version bump → Task 3; docs → Task 3; entry-point string unchanged → Task 3 note.
- §5 behavior matrix → Task 2 routing tests (every row, incl. `-f` leading option and `--version`/`--help` passthrough).
- §6 error handling (no new failure modes; `--version`/`--help` never eaten) → Task 2 `test_version_and_help_passthrough`.
- §7 testing (routing tests, regression of the `cli.main` test, full suite) → Tasks 1, 2.
- §8 docs/release (README/CHANGELOG/planning-notes, version, manual gate) → Tasks 3, 4.

**2. Placeholder scan** — no TBD/TODO; every code step shows the exact old→new edit or full code. The two `cli_advanced.py` edits (rename, registration) and three `cli.py` edits (decorator, signature, tail) are spelled out verbatim.

**3. Type/name consistency** — the renamed command is `scan` (function `scan`, name `"scan"`) consistently in `cli.py` (Task 2 Step 3), the group registration (`from .cli import scan`, Task 2 Step 5), and the updated test (`from gitexpose.cli import scan`, Task 2 Step 6). `_route_argv(argv, known)` signature matches between `cli.py` (Step 4) and every test call (Step 1). `full-audit` is used identically in the rename (Task 1 Step 5), the routing test (Task 2 `test_subcommands_unchanged`), and the CHANGELOG/README (Task 3). `main()` is the plain wrapper everywhere after Task 2.

**Ordering note:** Task 1 renames the aggregator off the `scan` name *before* Task 2 registers the web scanner as `scan` — avoiding a two-commands-named-`scan` collision. No test asserts `"scan" not in cli.commands` at the Task-1 intermediate state (which would break after Task 2).
