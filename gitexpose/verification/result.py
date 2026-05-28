"""VerificationStatus enum and VerificationResult dataclass."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class VerificationStatus(str, Enum):
    """Outcome of a single verification attempt.

    str-Enum so values serialize as plain strings in JSON / SARIF property bags
    without `.value` boilerplate at the call site.
    """

    VERIFIED = "verified"          # provider confirmed live
    DEAD = "dead"                  # provider returned auth-rejection (401 / 403)
    ERROR = "error"                # network / timeout / unexpected response shape
    SKIPPED = "skipped"            # --verify not passed (default)
    UNVERIFIABLE = "unverifiable"  # pattern has no registered verifier


@dataclass(frozen=True)
class VerificationResult:
    """Result of one verification attempt against one secret."""

    status: VerificationStatus
    detail: Optional[str] = None   # short reason: "200", "401", "timeout", "200 ok=true"
