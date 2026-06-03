"""Tests for code-platform verifiers (GitHub PAT, GitLab PAT)."""

import pytest
import respx
import httpx

from credence.verification.providers import VERIFIERS
from credence.verification.result import VerificationStatus


@pytest.mark.asyncio
@respx.mock
async def test_github_pat_verified_on_200():
    respx.get("https://api.github.com/user").mock(return_value=httpx.Response(200))
    result = await VERIFIERS["github_pat"]("ghp_fake")
    assert result.status == VerificationStatus.VERIFIED


@pytest.mark.asyncio
@respx.mock
async def test_github_pat_dead_on_401():
    respx.get("https://api.github.com/user").mock(return_value=httpx.Response(401))
    result = await VERIFIERS["github_pat"]("ghp_fake")
    assert result.status == VerificationStatus.DEAD


@pytest.mark.asyncio
@respx.mock
async def test_gitlab_pat_verified_on_200():
    respx.get("https://gitlab.com/api/v4/user").mock(return_value=httpx.Response(200))
    result = await VERIFIERS["gitlab_pat"]("glpat-fake")
    assert result.status == VerificationStatus.VERIFIED


@pytest.mark.asyncio
@respx.mock
async def test_gitlab_pat_dead_on_401():
    respx.get("https://gitlab.com/api/v4/user").mock(return_value=httpx.Response(401))
    result = await VERIFIERS["gitlab_pat"]("glpat-fake")
    assert result.status == VerificationStatus.DEAD


@pytest.mark.asyncio
@respx.mock
async def test_github_pat_sends_bearer_authorization():
    route = respx.get("https://api.github.com/user").mock(return_value=httpx.Response(200))
    await VERIFIERS["github_pat"]("ghp_abc")
    assert route.calls.last.request.headers["Authorization"] == "Bearer ghp_abc"


@pytest.mark.asyncio
@respx.mock
async def test_github_token_alias_verified_on_200():
    """SecretExtractor emits type 'github_token' (not 'github_pat'); the registry
    must verify that type or GitHub tokens silently go unverified."""
    respx.get("https://api.github.com/user").mock(return_value=httpx.Response(200))
    result = await VERIFIERS["github_token"]("ghp_fake")
    assert result.status == VerificationStatus.VERIFIED


def test_github_token_type_is_registered():
    """Guard against the type-name mismatch regression."""
    assert "github_token" in VERIFIERS
