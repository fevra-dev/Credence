"""Workflow-threat detection engine (GitHub Actions poisoned-pipeline auditor)."""

from .models import (
    Severity, Confidence, Platform,
    Step, Job, Workflow, ResolvedStep,
    WorkflowFinding, WorkflowAuditResult,
)
from .parser import parse_workflow, parse_action, run_script_refs
from .normalize import normalize_run
from .taint import resolve_job
from .allowlist import (
    is_platform_host, is_installer_host, parse_suppressions, Suppression,
)

__all__ = [
    "Severity", "Confidence", "Platform",
    "Step", "Job", "Workflow", "ResolvedStep",
    "WorkflowFinding", "WorkflowAuditResult",
    "parse_workflow", "parse_action", "run_script_refs",
    "normalize_run", "resolve_job",
    "is_platform_host", "is_installer_host", "parse_suppressions", "Suppression",
]
