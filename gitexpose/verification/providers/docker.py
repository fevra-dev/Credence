"""Docker Hub liveness verifier.

Docker Hub PATs authenticate via `POST /v2/users/login` with a JSON body
containing username + password (the PAT). A 200 response with a `token` field in
the body indicates a live credential. 401/403 → DEAD. Any other shape → ERROR.

# Side-effect class: READ-ONLY (auth check, returns JWT; does NOT create resources)
# Reference: https://docs.docker.com/reference/api/hub/latest/#tag/authentication
"""

from __future__ import annotations

import httpx

from ..result import VerificationResult, VerificationStatus


_LOGIN_URL = "https://hub.docker.com/v2/users/login"


async def verify(secret: str, *, timeout: float = 5.0) -> VerificationResult:
    """Check whether `secret` (a Docker Hub PAT) authenticates successfully."""
    body = {"username": "gitexpose-verify", "password": secret}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                _LOGIN_URL,
                json=body,
                headers={"User-Agent": "GitExpose-Verify/0.3"},
            )
    except httpx.TimeoutException:
        return VerificationResult(VerificationStatus.ERROR, "timeout")
    except httpx.HTTPError as exc:
        return VerificationResult(VerificationStatus.ERROR, type(exc).__name__)

    code = response.status_code
    if code in (401, 403):
        return VerificationResult(VerificationStatus.DEAD, str(code))
    if code != 200:
        return VerificationResult(VerificationStatus.ERROR, str(code))

    try:
        body_json = response.json()
    except ValueError:
        return VerificationResult(VerificationStatus.ERROR, "non-json-200")
    if not isinstance(body_json, dict) or not body_json.get("token"):
        return VerificationResult(VerificationStatus.DEAD, "200 no-token")
    return VerificationResult(VerificationStatus.VERIFIED, "200 token-present")
