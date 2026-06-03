"""Shared helpers for verification providers.

bearer_token_check() is the 80%-case helper: send a single GET to a provider's
documented liveness endpoint, map response → VerificationStatus.

redact() is the universal log-redaction helper. Used by every verifier and the
engine. Unit-tested to ensure no raw secret survives in any log line.
"""

from __future__ import annotations

from typing import Optional

import httpx

from .result import VerificationResult, VerificationStatus


def redact(secret: Optional[str]) -> str:
    """Return a log-safe representation of `secret`.

    Format: first 3 chars + ellipsis + last 4 chars (e.g., "sk-…wxyz").
    For secrets shorter than 8 chars, returns "***".
    """
    if not secret or len(secret) < 8:
        return "***"
    return f"{secret[:3]}…{secret[-4:]}"


# Default per-request timeout. Caller may override via the engine.
_DEFAULT_TIMEOUT = 5.0


async def bearer_token_check(
    secret: str,
    *,
    url: str,
    header: str,
    scheme: Optional[str],
    timeout: float = _DEFAULT_TIMEOUT,
) -> VerificationResult:
    """Send a GET to `url` with the credential in `header` and map status → result.

    `scheme` is the optional auth-header prefix:
      - "Bearer" → `Authorization: Bearer sk-abc`
      - None     → `x-api-key: sk-ant-xyz`  (no prefix; raw token in header)
    """
    # Defense-in-depth: the secret is placed verbatim into an HTTP header value,
    # and httpx does not reject control characters. Today every verifiable
    # pattern's regex constrains the secret to CRLF-free character classes, so
    # this is unreachable — but we don't want bearer_token_check to depend on
    # that caller-side contract. Reject any secret with CR/LF/NUL so a future
    # looser pattern can't smuggle a split or injected header onto the wire.
    if any(c in secret for c in ("\r", "\n", "\x00")):
        return VerificationResult(VerificationStatus.ERROR, "illegal-control-char")

    value = f"{scheme} {secret}" if scheme else secret
    headers = {header: value, "User-Agent": "Credence-Verify/0.3"}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers=headers)
    except httpx.TimeoutException:
        return VerificationResult(VerificationStatus.ERROR, "timeout")
    except httpx.HTTPError as exc:
        return VerificationResult(VerificationStatus.ERROR, type(exc).__name__)

    code = response.status_code
    if code == 200:
        return VerificationResult(VerificationStatus.VERIFIED, "200")
    if code in (401, 403):
        return VerificationResult(VerificationStatus.DEAD, str(code))
    return VerificationResult(VerificationStatus.ERROR, str(code))
