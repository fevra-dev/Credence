# credence/cli_gating.py
"""Shared --fail-on severity exit gate for local subcommands.

Findings are always printed by the caller; this module only decides the process
exit code. A finding trips the gate when its severity rank is >= the threshold.
Findings without a severity are treated as INFO (rank 0) so they only trip the
loosest gate (--fail-on info), never the default HIGH gate.
"""
from __future__ import annotations

import logging
from typing import Dict, List

import click

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

FAIL_ON_CHOICES = ["info", "low", "medium", "high", "critical"]


def _rank(severity) -> int:
    """Rank a finding's severity, fail-CLOSED on anything unexpected.

    Absent/None/empty severity → INFO (rank 0): a finding that genuinely carries
    no severity is informational. But a PRESENT-but-unrecognized severity string
    (e.g. "Critical " with a stray space, "crit", "CRITICAL\\n") must NOT silently
    drop to rank 0 and escape the gate — that would let a real critical finding
    greenlight CI. We normalize (strip + upper) first; if it's still unknown we
    treat it as CRITICAL and warn, so the gate fails closed rather than open.
    """
    if severity is None:
        return 0
    norm = str(severity).strip().upper()
    if norm == "":
        return 0
    rank = SEVERITY_ORDER.get(norm)
    if rank is None:
        logger.warning(
            "cli_gating: unrecognized severity %r — treating as CRITICAL "
            "(fail-closed) so it cannot silently escape the --fail-on gate.",
            severity,
        )
        return SEVERITY_ORDER["CRITICAL"]
    return rank


def exit_code_for(findings: List[Dict], fail_on: str) -> int:
    """Return 1 if any finding's severity >= the fail_on threshold, else 0."""
    floor = SEVERITY_ORDER.get(fail_on.strip().upper()) if fail_on else None
    if floor is None:
        raise ValueError(
            f"unknown --fail-on threshold {fail_on!r}; "
            f"expected one of {FAIL_ON_CHOICES}"
        )
    for f in findings:
        if _rank(f.get("severity")) >= floor:
            return 1
    return 0


def add_fail_on_arg(func):
    """Attach the shared --fail-on option to a Click command.

    Default 'high': only HIGH/CRITICAL findings fail CI. Use 'info' to fail on
    any finding (the pre-v0.8 behaviour); 'critical' to fail on CRITICAL only.
    """
    return click.option(
        "--fail-on",
        type=click.Choice(FAIL_ON_CHOICES),
        default="high",
        show_default=True,
        help="Minimum finding severity that makes the command exit non-zero.",
    )(func)
