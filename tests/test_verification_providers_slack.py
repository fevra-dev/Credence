"""Tests for Slack token verifier — uses auth.test endpoint."""

import pytest
import respx
import httpx

from credence.verification.providers import VERIFIERS
from credence.verification.result import VerificationStatus


@pytest.mark.asyncio
@respx.mock
async def test_slack_verified_when_ok_true():
    respx.post("https://slack.com/api/auth.test").mock(
        return_value=httpx.Response(200, json={"ok": True, "team": "TestTeam"})
    )
    result = await VERIFIERS["slack_token"]("xoxb-fake")
    assert result.status == VerificationStatus.VERIFIED


@pytest.mark.asyncio
@respx.mock
async def test_slack_dead_when_ok_false():
    """Critical: Slack returns 200 with {ok: false} for invalid tokens — that's DEAD."""
    respx.post("https://slack.com/api/auth.test").mock(
        return_value=httpx.Response(200, json={"ok": False, "error": "invalid_auth"})
    )
    result = await VERIFIERS["slack_token"]("xoxb-bad")
    assert result.status == VerificationStatus.DEAD


@pytest.mark.asyncio
@respx.mock
async def test_slack_error_on_500():
    respx.post("https://slack.com/api/auth.test").mock(
        return_value=httpx.Response(500)
    )
    result = await VERIFIERS["slack_token"]("xoxb-x")
    assert result.status == VerificationStatus.ERROR
