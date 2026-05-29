"""Data models for the supply-chain SCA subsystem.

A Dependency is one resolved package from a lock file. A Vulnerability is one
OSV.dev advisory affecting it. Both are plain dataclasses; the CLI/reporter
layers convert them to the finding-dict shape used elsewhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class Dependency:
    name: str                       # normalized (PEP 503 for PyPI, lowercase for npm)
    version: str
    ecosystem: str                  # OSV ecosystem name: "PyPI" | "npm"
    purl: str                       # e.g. "pkg:pypi/requests@2.31.0"
    direct: bool                    # direct vs transitive (from lock-file structure)
    source_file: str                # e.g. "poetry.lock"
    integrity_hash: Optional[str] = None   # captured for BOM hashes + v0.6 poisoning checks
    resolved_url: Optional[str] = None     # captured for v0.6 poisoning checks


@dataclass
class Vulnerability:
    vuln_id: str                    # CVE-… / GHSA-… / MAL-…
    severity: str                   # CRITICAL|HIGH|MEDIUM|LOW
    summary: str
    advisory_url: str
    cvss_score: Optional[float] = None
    fixed_version: Optional[str] = None
    aliases: List[str] = field(default_factory=list)
    known_exploited: bool = False
