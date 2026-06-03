"""Tests for LLM provider verifiers."""

import pytest
import respx
import httpx

from credence.verification.providers import VERIFIERS
from credence.verification.result import VerificationStatus

# Each tuple: (pattern_name, expected_host, expected_header)
LLM_PROVIDERS = [
    ("openai_api_key",            "api.openai.com",        "Authorization"),
    ("openai_project_key",        "api.openai.com",        "Authorization"),
    ("openai_service_account_key","api.openai.com",        "Authorization"),
    ("anthropic_api_key",         "api.anthropic.com",     "x-api-key"),
    ("groq_api_key",              "api.groq.com",          "Authorization"),
    ("openrouter_api_key",        "openrouter.ai",         "Authorization"),
    ("xai_api_key",               "api.x.ai",              "Authorization"),
    ("cerebras_api_key",          "api.cerebras.ai",       "Authorization"),
    ("huggingface_token",         "huggingface.co",        "Authorization"),
    ("elevenlabs_context_bound",  "api.elevenlabs.io",     "xi-api-key"),
    ("pinecone_api_key",          "api.pinecone.io",       "Api-Key"),
    ("langsmith_api_key_v2",      "api.smith.langchain.com","x-api-key"),
    ("langsmith_api_key_legacy",  "api.smith.langchain.com","x-api-key"),
]


@pytest.mark.parametrize("pattern, host, header", LLM_PROVIDERS)
def test_llm_provider_registered(pattern, host, header):
    assert pattern in VERIFIERS, f"{pattern} not in VERIFIERS"


@pytest.mark.asyncio
@pytest.mark.parametrize("pattern, host, header", LLM_PROVIDERS)
@respx.mock
async def test_llm_provider_returns_verified_on_200(pattern, host, header):
    respx.get(f"https://{host}").mock(side_effect=lambda req: httpx.Response(200))
    respx.route(host=host).mock(return_value=httpx.Response(200))
    verifier = VERIFIERS[pattern]
    result = await verifier("fake-secret")
    assert result.status == VerificationStatus.VERIFIED


@pytest.mark.asyncio
@pytest.mark.parametrize("pattern, host, header", LLM_PROVIDERS)
@respx.mock
async def test_llm_provider_returns_dead_on_401(pattern, host, header):
    respx.route(host=host).mock(return_value=httpx.Response(401))
    verifier = VERIFIERS[pattern]
    result = await verifier("fake-secret")
    assert result.status == VerificationStatus.DEAD
