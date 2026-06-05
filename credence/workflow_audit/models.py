"""Data models for the workflow-threat engine.

Findings flow out of scan() as plain dicts (WorkflowFinding.to_dict()) so they
plug into credence.cli_gating.exit_code_for, which reads an uppercase string
"severity" key. Internally rules use the typed dataclasses below.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Platform(str, Enum):
    GITHUB_ACTIONS = "github_actions"
    UNKNOWN = "unknown"


@dataclass
class Step:
    index: int
    name: Optional[str]
    uses: Optional[str]
    run: Optional[str]
    env: Dict[str, str] = field(default_factory=dict)
    with_: Dict[str, Any] = field(default_factory=dict)
    shell: Optional[str] = None
    line: int = 0


@dataclass
class Job:
    job_id: str
    runs_on: Any = None              # str | list | None
    permissions: Any = None          # dict | "write-all" | "read-all" | None
                                   # NOTE: None can mean either absent or an explicit
                                   # `permissions: null`; use `permissions_absent` to
                                   # distinguish the two cases.
    permissions_absent: bool = True
    env: Dict[str, str] = field(default_factory=dict)
    steps: List[Step] = field(default_factory=list)
    uses: Optional[str] = None       # reusable workflow call ("uses:" at job level)
    secrets_inherit: bool = False
    line: int = 0


@dataclass
class Workflow:
    path: str
    name: Optional[str] = None
    on_events: List[str] = field(default_factory=list)   # normalized trigger names
    permissions: Any = None
    permissions_absent: bool = True
    env: Dict[str, str] = field(default_factory=dict)
    jobs: List[Job] = field(default_factory=list)
    raw_text: str = ""
    parse_ok: bool = True
    is_composite_action: bool = False


@dataclass
class ResolvedStep:
    """A Step augmented with job-scoped taint resolution (built by taint.py)."""
    step: Step
    job: Job
    workflow: Workflow
    secret_vars: Dict[str, str] = field(default_factory=dict)  # VAR -> "secrets.PROD"
    tainted_files: Set[str] = field(default_factory=set)       # decode/secret-written files
    normalized_run: str = ""


@dataclass
class WorkflowFinding:
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    platform: Platform
    file_path: str
    message: str
    job: Optional[str] = None
    step_index: Optional[int] = None
    step_name: Optional[str] = None
    line: int = 0
    snippet: str = ""
    cicd_sec: List[str] = field(default_factory=list)
    mitre: List[str] = field(default_factory=list)
    remediation: str = ""
    source: str = "working_tree"        # "working_tree" | "history"
    commit: Optional[str] = None
    commit_short: Optional[str] = None
    author: Optional[str] = None
    committer: Optional[str] = None
    commit_date: Optional[str] = None
    identity_flags: List[str] = field(default_factory=list)
    persists_in_history_only: bool = False
    suppressed: bool = False
    suppression_reason: Optional[str] = None
    fingerprint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "platform": self.platform.value,
            "file_path": self.file_path,
            "message": self.message,
            "job": self.job,
            "step_index": self.step_index,
            "step_name": self.step_name,
            "line": self.line,
            "snippet": self.snippet,
            "frameworks": {"cicd_sec": self.cicd_sec, "mitre": self.mitre},
            "remediation": self.remediation,
            "source": self.source,
            "commit": self.commit,
            "commit_short": self.commit_short,
            "author": self.author,
            "committer": self.committer,
            "commit_date": self.commit_date,
            "identity_flags": self.identity_flags,
            "persists_in_history_only": self.persists_in_history_only,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
            "fingerprint": self.fingerprint,
        }


@dataclass
class WorkflowAuditResult:
    findings: List[WorkflowFinding] = field(default_factory=list)
    scanned_files: int = 0
    scanned_commits: int = 0
    scanned_unreachable: int = 0
