"""AWS STS GetCallerIdentity verifier with hand-rolled SigV4 signing.

# Side-effect class: READ-ONLY
# Endpoint: POST https://sts.amazonaws.com/ — Action=GetCallerIdentity
# Reference: https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
#
# The secret string format expected by this verifier is "<access_key>:<secret_key>"
# The CLI layer is responsible for pairing AWS findings; an unpaired secret
# returns ERROR with detail "expected access:secret pair".
"""

from __future__ import annotations

import datetime
import hashlib
import hmac

import httpx

from ..result import VerificationResult, VerificationStatus

_HOST = "sts.amazonaws.com"
_REGION = "us-east-1"
_SERVICE = "sts"
_URL = f"https://{_HOST}/"
_PAYLOAD = "Action=GetCallerIdentity&Version=2011-06-15"


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _build_signed_request(access_key: str, secret_key: str) -> dict[str, str]:
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    payload_hash = hashlib.sha256(_PAYLOAD.encode("utf-8")).hexdigest()

    canonical_headers = (
        f"content-type:application/x-www-form-urlencoded\n"
        f"host:{_HOST}\n"
        f"x-amz-date:{amz_date}\n"
    )
    signed_headers = "content-type;host;x-amz-date"

    canonical_request = (
        f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )
    credential_scope = f"{date_stamp}/{_REGION}/{_SERVICE}/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    )

    k_date    = _sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region  = _sign(k_date, _REGION)
    k_service = _sign(k_region, _SERVICE)
    k_signing = _sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    authorization = (
        f"AWS4-HMAC-SHA256 "
        f"Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )
    return {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Amz-Date": amz_date,
        "Authorization": authorization,
        "User-Agent": "GitExpose-Verify/0.3",
    }


async def verify(secret: str, *, timeout: float = 5.0) -> VerificationResult:
    if ":" not in secret:
        return VerificationResult(
            VerificationStatus.ERROR,
            "expected access:secret pair",
        )
    access_key, _, secret_key = secret.partition(":")
    if not access_key.startswith("AKIA") or not secret_key:
        return VerificationResult(
            VerificationStatus.ERROR,
            "expected access:secret pair",
        )

    headers = _build_signed_request(access_key, secret_key)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(_URL, headers=headers, content=_PAYLOAD)
    except httpx.TimeoutException:
        return VerificationResult(VerificationStatus.ERROR, "timeout")
    except httpx.HTTPError as exc:
        return VerificationResult(VerificationStatus.ERROR, type(exc).__name__)

    code = response.status_code
    if code == 200 and "GetCallerIdentityResponse" in response.text:
        return VerificationResult(VerificationStatus.VERIFIED, "200")
    if code in (401, 403):
        return VerificationResult(VerificationStatus.DEAD, str(code))
    return VerificationResult(VerificationStatus.ERROR, str(code))
