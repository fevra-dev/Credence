"""Canary test: no verifier may leak its raw secret into logs, stdout, stderr, or
the VerificationResult.detail field. Run every registered verifier with a
sentinel and grep all captured output."""

import logging

import pytest
import respx
import httpx

from credence.verification.providers import VERIFIERS

SENTINEL = "CANARY-DO-NOT-LEAK-1234567890ABCDEFGHIJ"


@pytest.mark.asyncio
@pytest.mark.parametrize("pattern_name", sorted(VERIFIERS.keys()))
@respx.mock
async def test_no_verifier_leaks_raw_secret(pattern_name, caplog, capsys):
    # Mock every host the verifier might call to 401 (DEAD) so we don't make
    # live network calls and we hit the error-path code in the verifier.
    respx.route().mock(return_value=httpx.Response(401, text="unauthorized"))

    secret_value = (
        f"AKIA{SENTINEL[:16]}:{SENTINEL}"  # for AWS, which requires a pair
        if pattern_name == "aws_access_key"
        else SENTINEL
    )

    with caplog.at_level(logging.DEBUG, logger="credence"):
        result = await VERIFIERS[pattern_name](secret_value)

    captured = capsys.readouterr()
    haystacks = [
        captured.out,
        captured.err,
        " ".join(record.getMessage() for record in caplog.records),
        result.detail or "",
    ]
    for haystack in haystacks:
        assert SENTINEL not in haystack, (
            f"{pattern_name} leaked SENTINEL into: {haystack!r}"
        )
