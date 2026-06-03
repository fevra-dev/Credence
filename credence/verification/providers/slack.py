"""Slack token liveness verifier.

Uses `auth.test`, which is the documented side-effect-free endpoint for token
validation. CRITICAL: Slack returns HTTP 200 for INVALID tokens too — the actual
result is in the JSON body's `ok` field.

# Side-effect class: READ-ONLY (documented auth check)
# Reference: https://api.slack.com/methods/auth.test
"""

from __future__ import annotations

import httpx

from ..result import VerificationResult, VerificationStatus


_URL = "https://slack.com/api/auth.test"


async def verify(secret: str, *, timeout: float = 5.0) -> VerificationResult:
    headers = {
        "Authorization": f"Bearer {secret}",
        "User-Agent": "GitExpose-Verify/0.3",
    }
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(_URL, headers=headers)
    except httpx.TimeoutException:
        return VerificationResult(VerificationStatus.ERROR, "timeout")
    except httpx.HTTPError as exc:
        return VerificationResult(VerificationStatus.ERROR, type(exc).__name__)

    if response.status_code != 200:
        return VerificationResult(VerificationStatus.ERROR, str(response.status_code))
    try:
        body = response.json()
    except ValueError:
        return VerificationResult(VerificationStatus.ERROR, "non-json-200")
    if not isinstance(body, dict):
        return VerificationResult(VerificationStatus.ERROR, "non-object-200")
    if body.get("ok") is True:
        return VerificationResult(VerificationStatus.VERIFIED, "200 ok=true")
    return VerificationResult(VerificationStatus.DEAD, f"200 ok=false: {body.get('error', 'unknown')}")
