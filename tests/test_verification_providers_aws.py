"""Tests for AWS STS GetCallerIdentity verifier (SigV4-signed)."""

import pytest
import respx
import httpx

from gitexpose.verification.providers import VERIFIERS
from gitexpose.verification.result import VerificationStatus


VALID_PAIR = "AKIA" + "A" * 16 + ":" + "x" * 40
INVALID_PAIR = "AKIA" + "A" * 16 + ":" + "y" * 40


@pytest.mark.asyncio
@respx.mock
async def test_aws_verified_on_signed_200():
    """STS returns 200 with an XML envelope for a valid signed request."""
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:user/test</Arn>
    <UserId>AIDAEXAMPLEEXAMPLE</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>"""
    respx.post("https://sts.amazonaws.com/").mock(
        return_value=httpx.Response(200, text=xml, headers={"Content-Type": "text/xml"})
    )
    result = await VERIFIERS["aws_access_key"](VALID_PAIR)
    assert result.status == VerificationStatus.VERIFIED


@pytest.mark.asyncio
@respx.mock
async def test_aws_dead_on_403_signature_invalid():
    respx.post("https://sts.amazonaws.com/").mock(
        return_value=httpx.Response(403, text="<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>")
    )
    result = await VERIFIERS["aws_access_key"](INVALID_PAIR)
    assert result.status == VerificationStatus.DEAD


@pytest.mark.asyncio
async def test_aws_returns_error_when_pair_malformed():
    """If the secret string isn't `AKIA…:secret`, return ERROR — caller didn't pair."""
    result = await VERIFIERS["aws_access_key"]("AKIA-not-paired")
    assert result.status == VerificationStatus.ERROR
    assert "pair" in (result.detail or "").lower()


@pytest.mark.asyncio
@respx.mock
async def test_aws_request_is_sigv4_signed():
    """Smoke: confirm the Authorization header looks SigV4-shaped."""
    route = respx.post("https://sts.amazonaws.com/").mock(
        return_value=httpx.Response(200, text="<GetCallerIdentityResponse></GetCallerIdentityResponse>")
    )
    await VERIFIERS["aws_access_key"](VALID_PAIR)
    req = route.calls.last.request
    auth = req.headers["Authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 ")
    assert "Credential=AKIA" in auth
    assert "SignedHeaders=" in auth
    assert "Signature=" in auth
