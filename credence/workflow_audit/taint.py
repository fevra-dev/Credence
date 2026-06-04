"""Job-scoped taint resolution (spec §3, F-001/F-003).

Builds ResolvedStep views: which run-block variables carry secrets (resolved
through workflow/job/step env bindings), and which files were written from
decoded/secret content (decode-to-file, Task 7). Sink rules in Plan 2 evaluate
over this resolved view instead of one step's raw string.
"""

from __future__ import annotations

import re
from typing import Dict, List

from .models import Job, ResolvedStep, Workflow
from .normalize import normalize_run

# ${{ secrets.NAME }} (allow whitespace variants)
_SECRET_REF_RE = re.compile(r"\$\{\{\s*(secrets\.[A-Za-z0-9_-]+)\s*\}\}")

# decoder writing to a redirected file: `... base64 -d > path` / `>> path`
_DECODE_TOKENS = (
    "base64 -d", "base64 --decode", "base32 -d", "xxd -r", "xxd -p -r",
    "openssl enc -d", "gunzip", "gzip -d", "uudecode", "gpg -d", "gpg --decrypt",
)
_REDIRECT_RE = re.compile(r">>?\s*([\w./~-]+)")


def _secret_bindings(env: Dict[str, str]) -> Dict[str, str]:
    """Return {VAR: 'secrets.NAME'} for env entries whose value is a secret ref."""
    out: Dict[str, str] = {}
    for var, value in env.items():
        m = _SECRET_REF_RE.search(value or "")
        if m:
            out[var] = m.group(1)
    return out


def _decoded_files(normalized_run: str) -> set:
    out = set()
    if not normalized_run:
        return out
    low = normalized_run.lower()
    if not any(tok in low for tok in _DECODE_TOKENS):
        return out
    for m in _REDIRECT_RE.finditer(normalized_run):
        out.add(m.group(1))
    return out


def _filter_to_referenced(secret_vars: Dict[str, str], run_text: str) -> Dict[str, str]:
    """Keep only secret_vars whose VAR name is referenced in run_text."""
    if not run_text:
        return {}
    return {var: ref for var, ref in secret_vars.items() if var in run_text}


def resolve_job(workflow: Workflow, job: Job) -> List[ResolvedStep]:
    base: Dict[str, str] = {}
    base.update(_secret_bindings(workflow.env))
    base.update(_secret_bindings(job.env))

    cumulative_files: set = set()
    resolved: List[ResolvedStep] = []
    for step in job.steps:
        all_secret_vars: Dict[str, str] = dict(base)
        all_secret_vars.update(_secret_bindings(step.env))
        norm = normalize_run(step.run or "")
        # Only surface vars actually referenced in this step's run text
        secret_vars = _filter_to_referenced(all_secret_vars, step.run or "")
        cumulative_files |= _decoded_files(norm)
        resolved.append(ResolvedStep(
            step=step,
            job=job,
            workflow=workflow,
            secret_vars=secret_vars,
            tainted_files=set(cumulative_files),   # snapshot incl. this step's writes
            normalized_run=norm,
        ))
    return resolved
