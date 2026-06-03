"""AWS access+secret pairing: SecretExtractor emits access & secret as separate
findings; the engine must pair same-source ones into 'ACCESS:SECRET' for the
verifier, without clobbering value_full."""

import pytest
import respx
import httpx

from credence.verification.engine import pair_aws_credentials, verify_secrets
from credence.verification.result import VerificationStatus


def test_pair_aws_sets_verify_input_for_same_source():
    findings = [
        {"type": "aws_access_key", "value_full": "AKIAIOSFODNN7EXAMPLE", "source": ".env"},
        {"type": "aws_secret_key", "value_full": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "source": ".env"},
    ]
    pair_aws_credentials(findings)
    access = next(f for f in findings if f["type"] == "aws_access_key")
    assert access["_verify_input"] == "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert access["value_full"] == "AKIAIOSFODNN7EXAMPLE"


def test_pair_aws_skips_when_no_same_source_secret():
    findings = [
        {"type": "aws_access_key", "value_full": "AKIAIOSFODNN7EXAMPLE", "source": "a.env"},
        {"type": "aws_secret_key", "value_full": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "source": "b.env"},
    ]
    pair_aws_credentials(findings)
    access = next(f for f in findings if f["type"] == "aws_access_key")
    assert "_verify_input" not in access


@pytest.mark.asyncio
@respx.mock
async def test_verify_uses_paired_input_for_aws():
    respx.post("https://sts.amazonaws.com/").mock(
        return_value=httpx.Response(200, text="<GetCallerIdentityResponse></GetCallerIdentityResponse>")
    )
    findings = [
        {"type": "aws_access_key", "value_full": "AKIA" + "A" * 16, "source": ".env"},
        {"type": "aws_secret_key", "value_full": "x" * 40, "source": ".env"},
    ]
    pair_aws_credentials(findings)
    await verify_secrets(findings)
    access = next(f for f in findings if f["type"] == "aws_access_key")
    assert access["verification_status"] == VerificationStatus.VERIFIED.value


@pytest.mark.asyncio
@respx.mock
async def test_aws_pairing_end_to_end_through_extractor():
    """Regression: value_full for aws_secret_key includes match context; pairing
    must extract the clean 40-char secret or SigV4 signs the wrong key and a LIVE
    key reports DEAD."""
    import httpx
    from credence.secrets.secret_extractor import SecretExtractor
    respx.post("https://sts.amazonaws.com/").mock(
        return_value=httpx.Response(200, text="<GetCallerIdentityResponse></GetCallerIdentityResponse>")
    )
    content = (
        'aws_access_key_id="AKIAIOSFODNN7EXAMPLE"\n'
        'aws_secret="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
    )
    secrets = await SecretExtractor().extract(content, source=".env")
    types = {s["type"] for s in secrets}
    assert "aws_access_key" in types and "aws_secret_key" in types, f"got {types}"
    pair_aws_credentials(secrets)
    await verify_secrets(secrets)
    access = next(s for s in secrets if s["type"] == "aws_access_key")
    assert access["verification_status"] == VerificationStatus.VERIFIED.value


def test_verify_input_is_internal_only():
    """pair_aws_credentials sets _verify_input; callers must scrub it before
    emitting findings (it contains the secret)."""
    findings = [
        {"type": "aws_access_key", "value_full": "AKIA" + "A" * 16, "source": ".env"},
        {"type": "aws_secret_key", "value_full": "x" * 40, "source": ".env"},
    ]
    pair_aws_credentials(findings)
    # The key exists internally...
    assert "_verify_input" in findings[0]
    # ...and a simple scrub removes it (the pattern the CLI uses)
    for f in findings:
        f.pop("_verify_input", None)
    assert all("_verify_input" not in f for f in findings)
