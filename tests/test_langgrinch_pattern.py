"""LangGrinch `lc` credential pattern (CVE-2025-68664)."""

import asyncio

from credence.secrets.secret_extractor import SecretExtractor


def _extract(content: str):
    return asyncio.run(SecretExtractor().extract(content))


def test_langgrinch_lc_key_detected():
    secrets = _extract("LANGCHAIN_LC_KEY=lc-" + "a" * 36)
    assert any(s["type"] == "langgrinch_lc_key" for s in secrets)


def test_langgrinch_lc_key_has_metadata():
    secrets = _extract("key=lc-" + "Z" * 40)
    lc = next(s for s in secrets if s["type"] == "langgrinch_lc_key")
    assert lc["attack_class"] == "LLM03"
    assert lc["atlas_technique"]


def test_langgrinch_does_not_match_langsmith():
    secrets = _extract("LANGSMITH=lsv2_pt_" + "x" * 40)
    assert not any(s["type"] == "langgrinch_lc_key" for s in secrets)
