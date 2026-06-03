# Credence CI/CD Integration Guide

Credence ships ready-to-use configs for GitHub Actions and pre-commit. This
doc shows how to wire them into your pipeline.

## GitHub Actions

The sample workflow at `.github/workflows/credence-scan.yml` runs Credence on
every PR and uploads results to GitHub Code Scanning via SARIF. To use it:

1. Copy the workflow file into your own repo at the same path.
2. Ensure your repo has Code Scanning enabled (Settings → Security → Code
   Scanning → Set up advanced).
3. Push the workflow. On the next PR, findings appear in the PR's "Security"
   tab and as inline annotations.

### Customizing

| Variable | Default | Why change |
|---|---|---|
| `python-version` | 3.12 | Pin to your team's Python |
| `--output-file` | `credence-results.sarif` | Match your Code Scanning config |
| `--verify` flag | off | Add `--verify` for live-credential confirmation. Note: this sends candidate credentials to provider APIs from your CI runners. Most teams should NOT enable this in CI without explicit security approval. |

### Adding `--verify` to CI (advanced)

If you understand the trade-offs and want CI to confirm liveness, add `--verify`
to the scan step. **Read `docs/INTEGRATIONS_CODE_SCANNING.md` first.**

```yaml
      - name: Run supply-chain scan with verification
        run: |
          credence supply-chain . \
            --verify \
            --no-verify-banner \
            --verify-only-severity HIGH \
            --output sarif \
            --output-file credence-results.sarif
```

## pre-commit

The pre-commit config at `.pre-commit-hooks.yaml` exposes two hooks:

- `credence-staged` — fast, scans only the files staged for the current commit
- `credence-full` — thorough, scans the entire working tree (use as a manual
  stage or for an occasional full pass)

### Local setup

In your repo's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/fevra-dev/Credence
    rev: v0.3.0
    hooks:
      - id: credence-staged
```

Then:

```bash
pip install pre-commit
pre-commit install
git commit -m "test"  # credence now runs against staged files
```

### What the hook blocks

By default, the `credence-staged` hook reports findings to stderr and exits
non-zero if any CRITICAL finding is present in the staged file set. You can
tune this by overriding the entry point in your own config:

```yaml
      - id: credence-staged
        entry: credence supply-chain --severity-threshold HIGH
```
