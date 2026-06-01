# gitexpose/cli_gating.py
"""Shared --fail-on severity exit gate for local subcommands.

Findings are always printed by the caller; this module only decides the process
exit code. A finding trips the gate when its severity rank is >= the threshold.
Findings without a severity are treated as INFO (rank 0) so they only trip the
loosest gate (--fail-on info), never the default HIGH gate.
"""
from __future__ import annotations

from typing import Dict, List

import click

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

FAIL_ON_CHOICES = ["info", "low", "medium", "high", "critical"]


def exit_code_for(findings: List[Dict], fail_on: str) -> int:
    """Return 1 if any finding's severity >= the fail_on threshold, else 0."""
    floor = SEVERITY_ORDER[fail_on.upper()]
    for f in findings:
        rank = SEVERITY_ORDER.get((f.get("severity") or "INFO").upper(), 0)
        if rank >= floor:
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
