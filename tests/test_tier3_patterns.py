"""Tests for Tier 3 provider credential patterns."""

import asyncio

from credence.secrets.secret_extractor import SecretExtractor


def _extract(content: str):
    return asyncio.run(SecretExtractor().extract(content))


def test_helicone_api_key_detected():
    secrets = _extract("HELICONE_API_KEY=sk-helicone-" + "a" * 40)
    assert any(s["type"] == "helicone_api_key" for s in secrets)


def test_portkey_api_key_detected():
    secrets = _extract("PORTKEY_API_KEY=" + "Z" * 32)
    assert any(s["type"] == "portkey_api_key" for s in secrets)


def test_voyage_api_key_detected():
    secrets = _extract("VOYAGE_API_KEY=pa-" + "a" * 40)
    assert any(s["type"] == "voyage_api_key" for s in secrets)


def test_cohere_api_key_detected():
    secrets = _extract("COHERE_API_KEY=co-" + "x" * 40)
    assert any(s["type"] == "cohere_api_key" for s in secrets)


def test_modal_token_pair_detected():
    """Modal uses paired token (ak-… + as-…)."""
    secrets = _extract(
        "MODAL_TOKEN_ID=ak-" + "1" * 32 + "\n"
        "MODAL_TOKEN_SECRET=as-" + "2" * 32 + "\n"
    )
    types = {s["type"] for s in secrets}
    assert "modal_token_id" in types
    assert "modal_token_secret" in types


def test_runpod_api_key_detected():
    """Runpod uses a generic uppercase alphanumeric key, context-bound."""
    secrets = _extract("RUNPOD_API_KEY=" + "Y" * 40)
    assert any(s["type"] == "runpod_api_key" for s in secrets)


def test_all_tier3_have_owasp_atlas_metadata():
    secrets = _extract(
        "HELICONE_API_KEY=sk-helicone-" + "a" * 40 + "\n"
        "COHERE_API_KEY=co-" + "x" * 40 + "\n"
    )
    for s in secrets:
        if s["type"] in {"helicone_api_key", "cohere_api_key"}:
            assert s["attack_class"] == "LLM06"
            assert s["atlas_technique"] == "AML.T0019"
