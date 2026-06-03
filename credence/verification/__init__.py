"""Active verification engine for Credence v0.3.

Sends low-footprint, side-effect-free authentication checks to provider APIs
to confirm whether a discovered credential is live. Opt-in via --verify.
"""

from .result import VerificationResult, VerificationStatus

__all__ = ["VerificationResult", "VerificationStatus", "verify_secrets"]


def __getattr__(name: str):  # pragma: no cover — lazy import to keep this module light
    if name == "verify_secrets":
        from .engine import verify_secrets
        return verify_secrets
    raise AttributeError(name)
