"""
Data models for Credence.

Defines the core data structures used throughout the application.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(Enum):
    """Vulnerability severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(Enum):
    """Path categories for grouping."""

    GIT = "git"
    ENV = "environment"
    CONFIG = "configuration"
    BACKUP = "backup"
    VCS = "version_control"
    DEBUG = "debug"
    SENSITIVE = "sensitive"


@dataclass
class PathDefinition:
    """Definition of a sensitive path to check."""

    path: str  # e.g., ".git/config"
    category: Category  # Category enum
    severity: Severity  # Severity if found
    description: str  # Human description
    signatures: List[str] = field(default_factory=list)  # Response body signatures
    content_types: List[str] = field(default_factory=list)  # Valid content types


@dataclass
class ScanResult:
    """Result of scanning a single URL/path combination."""

    url: str  # Full URL that was scanned
    path: str  # The path that was checked
    target: str  # Base target URL
    status_code: int  # HTTP status code (0 if error)
    vulnerable: bool  # Whether vulnerability confirmed
    severity: Severity  # Severity level
    category: Category  # Category
    description: str  # Description of finding
    evidence: str  # Evidence string (signature matched, etc)
    response_length: int = 0  # Response body length
    content_type: str = ""  # Response content-type
    error: Optional[str] = None  # Error message if request failed
    # v0.2 additions: compliance metadata
    attack_class: Optional[str] = None  # OWASP LLM Top 10 ID, e.g. "LLM06"
    atlas_technique: Optional[str] = None  # MITRE ATLAS technique, e.g. "AML.T0019"
    # v0.3 additions: active verification
    verification_status: str = "skipped"  # one of: verified, dead, error, skipped, unverifiable
    verification_detail: Optional[str] = None  # short reason: "200", "401", "timeout", etc.


@dataclass
class TargetReport:
    """Aggregated results for a single target."""

    target: str  # Base target URL
    total_paths_checked: int  # Number of paths scanned
    vulnerable_count: int  # Number of vulnerabilities
    findings: List[ScanResult]  # List of positive findings
    errors: List[str]  # Errors encountered
    scan_duration_ms: int  # Time to scan this target


@dataclass
class ScanReport:
    """Complete scan report across all targets."""

    targets_scanned: int  # Number of targets
    targets_vulnerable: int  # Targets with findings
    total_findings: int  # Total vulnerabilities
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    scan_start: str  # ISO timestamp
    scan_end: str  # ISO timestamp
    scan_duration_ms: int  # Total duration
    target_reports: List[TargetReport]  # Per-target results

