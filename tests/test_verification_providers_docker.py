"""Tests for Docker Hub verifier — uses POST /v2/users/login."""

import pytest
import respx
import httpx

from credence.verification.providers import VERIFIERS
from credence.verification.result import VerificationStatus


@pytest.mark.asyncio
@respx.mock
async def test_docker_hub_verified_on_jwt_response():
    """A live PAT returns 200 with a JWT in the body."""
    respx.post("https://hub.docker.com/v2/users/login").mock(
        return_value=httpx.Response(200, json={"token": "eyJ.fake.jwt"})
    )
    result = await VERIFIERS["docker_hub_pat"]("dckr_pat_fake_token_value")
    assert result.status == VerificationStatus.VERIFIED


@pytest.mark.asyncio
@respx.mock
async def test_docker_hub_dead_on_401_unauthorized():
    respx.post("https://hub.docker.com/v2/users/login").mock(
        return_value=httpx.Response(401, json={"detail": "Incorrect authentication credentials."})
    )
    result = await VERIFIERS["docker_hub_pat"]("dckr_pat_invalid")
    assert result.status == VerificationStatus.DEAD


@pytest.mark.asyncio
@respx.mock
async def test_docker_hub_dead_when_response_lacks_token():
    """Server returns 200 but no JWT — should be DEAD (auth shape rejected)."""
    respx.post("https://hub.docker.com/v2/users/login").mock(
        return_value=httpx.Response(200, json={"detail": "no token"})
    )
    result = await VERIFIERS["docker_hub_pat"]("dckr_pat_weird")
    assert result.status == VerificationStatus.DEAD


@pytest.mark.asyncio
@respx.mock
async def test_docker_hub_error_on_500():
    respx.post("https://hub.docker.com/v2/users/login").mock(
        return_value=httpx.Response(500)
    )
    result = await VERIFIERS["docker_hub_pat"]("dckr_pat_x")
    assert result.status == VerificationStatus.ERROR
