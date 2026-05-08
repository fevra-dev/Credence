"""End-to-end tests: SecretExtractor matches v0.2 patterns from JSON corpus."""

import asyncio

from gitexpose.secrets.secret_extractor import SecretExtractor


def _extract(content: str):
    """Sync helper around async extract()."""
    extractor = SecretExtractor()
    return asyncio.run(extractor.extract(content, source="test"))


def test_groq_key_detected():
    secrets = _extract("export GROQ_API_KEY=gsk_" + "a" * 52)
    types = {s["type"] for s in secrets}
    assert "groq_api_key" in types


def test_anthropic_key_detected():
    secrets = _extract("ANTHROPIC_API_KEY=sk-ant-" + "x" * 95)
    assert any(s["type"] == "anthropic_api_key" for s in secrets)


def test_openai_project_key_detected():
    secrets = _extract("OPENAI_API_KEY=sk-proj-" + "Z" * 60)
    assert any(s["type"] == "openai_project_key" for s in secrets)


def test_huggingface_token_detected():
    secrets = _extract("HF_TOKEN=hf_" + "a" * 35)
    assert any(s["type"] == "huggingface_token" for s in secrets)


def test_pinecone_key_detected():
    secrets = _extract("PINECONE_API_KEY=pcsk_" + "x" * 50)
    assert any(s["type"] == "pinecone_api_key" for s in secrets)


def test_langsmith_v2_key_detected():
    secrets = _extract("LANGCHAIN_API_KEY=lsv2_pt_" + "z" * 50)
    assert any(s["type"] == "langsmith_api_key_v2" for s in secrets)


def test_stripe_test_key_detected():
    secrets = _extract("STRIPE_KEY=sk_test_" + "X" * 30)
    assert any(s["type"] == "stripe_test_key" for s in secrets)


def test_discord_bot_token_detected():
    secrets = _extract(
        "DISCORD_TOKEN=" + "M" + "a" * 24 + "." + "b" * 7 + "." + "c" * 35
    )
    assert any(s["type"] == "discord_bot_token" for s in secrets)


def test_discord_webhook_detected():
    secrets = _extract(
        "WEBHOOK=https://discord.com/api/webhooks/123456789/abcDEFghi-_"
    )
    assert any(s["type"] == "discord_webhook" for s in secrets)


def test_telegram_bot_token_detected():
    secrets = _extract("TG_BOT_TOKEN=12345678:" + "a" * 35)
    assert any(s["type"] == "telegram_bot_token" for s in secrets)


def test_twilio_account_sid_detected():
    secrets = _extract("TWILIO_SID=AC" + "a1b2" * 8)
    assert any(s["type"] == "twilio_account_sid" for s in secrets)


def test_gitlab_pat_detected():
    secrets = _extract("GITLAB_TOKEN=glpat-" + "x" * 20)
    assert any(s["type"] == "gitlab_pat" for s in secrets)


def test_docker_hub_pat_detected():
    secrets = _extract("DOCKER_PAT=dckr_pat_" + "z" * 28)
    assert any(s["type"] == "docker_hub_pat" for s in secrets)


def test_elevenlabs_context_bound_detected():
    secrets = _extract("XI_API_KEY=" + "f" * 32)
    assert any(s["type"] == "elevenlabs_context_bound" for s in secrets)


def test_elevenlabs_context_bound_not_triggered_without_env_var():
    # Plain 32-hex string with no XI_API_KEY context — must not trigger
    secrets = _extract("some_hash = " + "f" * 32)
    assert not any(s["type"] == "elevenlabs_context_bound" for s in secrets)


def test_groq_does_not_match_prose_collision():
    """Negative: prefix as English word in prose."""
    secrets = _extract("gsk_was_a_thing in older versions")
    assert not any(s["type"] == "groq_api_key" for s in secrets)


def test_extracted_secrets_include_owasp_atlas_metadata():
    secrets = _extract("GROQ_API_KEY=gsk_" + "a" * 52)
    groq = next(s for s in secrets if s["type"] == "groq_api_key")
    assert groq["attack_class"] == "LLM06"
    assert groq["atlas_technique"] == "AML.T0019"
