# GitExpose v0.6.1 — CLI Entry-Point Unification Design

> Brainstormed 2026-05-31. A focused patch release: make the installed `gitexpose`
> binary expose the advanced subcommands (`supply-chain`, `git-history`, `agent-audit`, …)
> that it has documented since v0.4 but never actually wired up — while preserving today's
> bare-target `gitexpose example.com` web-scan behavior. No new detections; pure CLI plumbing.

## 1. Motivation

The `gitexpose` console script maps to `gitexpose.cli:main` — a single `@click.command()`
that scans **web targets only**. The advanced command group (`gitexpose.cli_advanced:cli` —
`scan`, `react2shell`, `ml-scan`, `llm-scan`, `unicode-scan`, `mcp`, `list-tools`,
`supply-chain`, `git-history`, `agent-audit`) is reachable **only** via
`python -m gitexpose.cli_advanced <cmd>`.

This is not cosmetic — it actively breaks two shipped integration points:

- **The sample GitHub Action** (`.github/workflows/gitexpose-scan.yml`) runs
  `gitexpose supply-chain .`, which cannot work against the web-scan-only binary. *This is
  why the self-scan workflow fails on every push* (the earlier "intentional fixtures" theory
  was wrong).
- **The pre-commit hook** (`.pre-commit-hooks.yaml`) uses `entry: gitexpose supply-chain`,
  broken for any downstream repo that adopted it.

The README documents a **hybrid** UX the binary never supported: `gitexpose example.com`
(bare-target web scan, ~4 examples) *and* `gitexpose supply-chain`/`git-history`/`agent-audit`/`scan`
(subcommands, ~12 examples). The fix restores the documented subcommand behavior **and**
preserves bare-target web-scan, so every documented invocation becomes accurate.

This gap predates v0.6 (true since v0.4/v0.5); it is shipped as a **v0.6.1 patch**, mirroring
the v0.5.1 hardening release. The next *capability* release (v0.7, "Agent Exposure, Deepened")
is tracked separately.

## 2. Scope

### In scope (v0.6.1)
- Make the installed `gitexpose` binary a command group exposing all subcommands.
- Preserve bare-target `gitexpose example.com` / `gitexpose -f targets.txt -o sarif` (route to `scan`).
- Resolve the two-`scan` collision: the **mature web scanner** (`cli.py`) becomes the canonical
  `scan`; the advanced multi-module aggregator is renamed `full-audit`.
- Fix the stale `version_option(version="0.4.0")` on the group.
- Docs (README/CHANGELOG/planning-notes) + version bump to `0.6.1`.

### Out of scope (deferred)
- Merging the web/advanced scanners' feature sets (they stay distinct: `scan` = web; `full-audit` = aggregator).
- SARIF output for the advanced modules.
- Any new detection or finding type.
- Moving the entry-point *string* (it stays `gitexpose.cli:main`).

### Deliberate properties
- **Non-breaking.** Every invocation that worked before still works identically; the change is purely additive (subcommands become reachable) plus one internal rename (advanced `scan` → `full-audit`, which never worked from the binary anyway).
- **No new runtime dependencies.** The default-command routing is hand-rolled argv preprocessing, not a new library.

## 3. Architecture

The unified group already exists as `cli_advanced.cli`. The entry point `gitexpose.cli:main`
is rewritten as a thin wrapper that delegates to it after injecting a default `scan` command
when appropriate.

```
gitexpose.cli:main  (entry point — UNCHANGED string)
   └─ argv preprocessing: prepend "scan" when args don't name a subcommand / --help / --version
        └─ cli_advanced.cli  (the click.Group)
             ├─ scan          ← the mature web scanner (moved from cli.py), default for bare-target
             ├─ full-audit    ← the advanced aggregator (renamed from `scan`)
             ├─ supply-chain  ┐
             ├─ git-history   │ already on the group (v0.4/v0.5/v0.6)
             ├─ agent-audit   │
             ├─ react2shell / ml-scan / llm-scan / unicode-scan / mcp / list-tools  ┘
```

No import cycle: `cli.py` imports `cli_advanced.cli`; `cli_advanced` does not import `cli`.

### Default-command mechanism (chosen: argv preprocessing)

```python
# gitexpose/cli.py
_PASSTHROUGH = {"--help", "-h", "--version"}

def main():
    import sys
    from .cli_advanced import cli as cli_group
    known = set(cli_group.commands)     # derived from the group → never drifts
    argv = sys.argv[1:]
    if argv and argv[0] not in known and argv[0] not in _PASSTHROUGH:
        argv = ["scan", *argv]          # bare-target / leading option → web scan
    cli_group.main(args=argv, prog_name="gitexpose")
```

`known` is derived from `cli_group.commands` (the registered command names — click
hyphenates function names, e.g. `ml_scan` → `ml-scan`), so adding a future subcommand
needs no edit here and there is no hardcoded-name drift.

Rejected alternatives: a custom `click.Group` (`DefaultGroup`) subclass — idiomatic but
tangles with click's option parser for leading options (`-f`) and `--version`/`--help`,
more edge cases; a second console script (`gitexpose-x`) — doesn't fix the GH Action /
pre-commit references and adds an ugly name.

## 4. Component changes

**`gitexpose/cli.py`**
- Rename the web-scan command `main` → `scan` as `@click.command("scan")` (all options/body verbatim).
- `from .cli_advanced import cli as cli_group` and `cli_group.add_command(scan)` (registers it as `scan` on the group).
- New thin `def main():` wrapper (argv preprocessing above) — the entry point.
- The web-scan command's own `--version` flag becomes `gitexpose scan --version`; the group-level `--version` is the primary one (acceptable redundancy).

**`gitexpose/cli_advanced.py`**
- Rename the advanced aggregator `@cli.command()` `scan` (def `scan`) → `@cli.command("full-audit")` (def `full_audit`); behavior unchanged.
- `@click.version_option(version="0.4.0", …)` → `version=__version__` (import from `gitexpose`).
- `if __name__ == "__main__": cli()` stays (module invocation still works).

**`pyproject.toml` / `setup.py`** — entry-point string unchanged (`gitexpose.cli:main`). Version → `0.6.1`.

**`gitexpose/__init__.py`** — `__version__ = "0.6.1"`.

**Docs** — README (clarify `scan` vs `full-audit`; confirm bare-target works; subcommand examples now accurate), CHANGELOG (v0.6.1 section), `docs/v0.6-planning-notes.md` (close the entry-point gap). The GH Action and pre-commit hook need **no change**.

## 5. Behavior matrix (test contract)

| Invocation | Resolves to |
|---|---|
| `gitexpose example.com` | `scan example.com` (web) |
| `gitexpose example.com -o sarif` | `scan` (web) |
| `gitexpose -f targets.txt` | `scan -f targets.txt` (web) — leading-option case |
| `gitexpose scan example.com` | web scan |
| `gitexpose full-audit example.com --react2shell` | advanced aggregator |
| `gitexpose supply-chain .` | supply-chain (fixes GH Action) |
| `gitexpose git-history .` | git-history |
| `gitexpose agent-audit ./repo` | agent-audit |
| `gitexpose --version` | group version (NOT scan) |
| `gitexpose --help` | group help (NOT scan) |
| `gitexpose` (no args) | group help |

Edge case (documented, accepted): a web target whose name is exactly a subcommand token
(e.g. a host literally named `scan`) is treated as that command; the user disambiguates with
`gitexpose scan scan`.

## 6. Error handling

- Unknown subcommand that is also not a plausible target → click's normal "No such command" via the group (after the `scan` prepend, an invalid target is handled by the scanner as today).
- `--version`/`--help` always pass through to the group (never eaten by the default prepend).
- No new failure modes introduced; the wrapper only reorders argv.

## 7. Testing

- **CLI routing tests** (new) — assert every row of the §5 matrix via `CliRunner` against the
  unified group / a `main()` invocation harness, especially: `-f` leading-option routes to `scan`;
  `--version`/`--help` do **not** route to `scan`; `supply-chain`/`agent-audit`/`git-history`
  resolve to their commands; `full-audit` resolves and the old `scan`-as-aggregator name is gone.
- **Regression** — existing web-scan tests (whatever invokes the old `cli.main`) updated to the
  new command object; existing `cli_advanced` command tests unchanged.
- Full suite stays green (359 + new routing tests). Run with system Python 3.12, not `uv run`.

## 8. Documentation & release

- README: confirm bare-target still works; document `gitexpose scan` (web) vs `gitexpose full-audit` (aggregator); the existing `supply-chain`/`git-history`/`agent-audit` examples now work as written.
- CHANGELOG `v0.6.1` section: "Fixed — advanced subcommands (`supply-chain`/`git-history`/`agent-audit`/…) now work from the installed `gitexpose` binary (previously web-scan only); bare-target `gitexpose <host>` preserved. Renamed the advanced multi-module aggregator to `full-audit`."
- `docs/v0.6-planning-notes.md`: mark the CLI entry-point gap closed in v0.6.1.
- Version bump to `0.6.1`. Gated on manual verification (`gitexpose supply-chain .`, `gitexpose example.com`, `gitexpose --version`) before tag/push, same pattern as v0.5.1/v0.6.0.
