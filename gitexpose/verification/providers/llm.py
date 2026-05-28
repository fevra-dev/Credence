"""Liveness verifier entries for LLM-ecosystem providers.

Every entry below resolves to bearer_token_check with the provider's documented
liveness endpoint baked in. URLs and headers are sourced from each provider's
public API documentation.

# Side-effect class: READ-ONLY across all entries
# Every endpoint here is documented as a no-cost, side-effect-free read.
"""

from __future__ import annotations

from functools import partial

from ..helpers import bearer_token_check

# Each entry: pattern_name → partial(bearer_token_check, url=..., header=..., scheme=...)
LLM_VERIFIERS = {
    # OpenAI family (3 patterns, same endpoint)
    "openai_api_key":             partial(bearer_token_check, url="https://api.openai.com/v1/models",        header="Authorization", scheme="Bearer"),
    "openai_project_key":         partial(bearer_token_check, url="https://api.openai.com/v1/models",        header="Authorization", scheme="Bearer"),
    "openai_service_account_key": partial(bearer_token_check, url="https://api.openai.com/v1/models",        header="Authorization", scheme="Bearer"),

    # Anthropic — uses x-api-key header without Bearer prefix
    "anthropic_api_key":          partial(bearer_token_check, url="https://api.anthropic.com/v1/models",     header="x-api-key",     scheme=None),

    # Groq — OpenAI-compatible API
    "groq_api_key":               partial(bearer_token_check, url="https://api.groq.com/openai/v1/models",   header="Authorization", scheme="Bearer"),

    # OpenRouter — OpenAI-compatible
    "openrouter_api_key":         partial(bearer_token_check, url="https://openrouter.ai/api/v1/auth/key",   header="Authorization", scheme="Bearer"),

    # Perplexity — OpenAI-compatible
    "perplexity_api_key":         partial(bearer_token_check, url="https://api.perplexity.ai/chat/completions", header="Authorization", scheme="Bearer"),

    # xAI (Grok) — OpenAI-compatible
    "xai_api_key":                partial(bearer_token_check, url="https://api.x.ai/v1/models",              header="Authorization", scheme="Bearer"),

    # Cerebras — OpenAI-compatible
    "cerebras_api_key":           partial(bearer_token_check, url="https://api.cerebras.ai/v1/models",       header="Authorization", scheme="Bearer"),

    # Hugging Face — whoami endpoint
    "huggingface_token":          partial(bearer_token_check, url="https://huggingface.co/api/whoami-v2",    header="Authorization", scheme="Bearer"),

    # ElevenLabs — user endpoint
    "elevenlabs_context_bound":   partial(bearer_token_check, url="https://api.elevenlabs.io/v1/user",       header="xi-api-key",    scheme=None),

    # Pinecone — uses Api-Key header without prefix
    "pinecone_api_key":           partial(bearer_token_check, url="https://api.pinecone.io/databases",       header="Api-Key",       scheme=None),

    # LangSmith — workspaces endpoint
    "langsmith_api_key_v2":       partial(bearer_token_check, url="https://api.smith.langchain.com/api/v1/workspaces", header="x-api-key", scheme=None),
    "langsmith_api_key_legacy":   partial(bearer_token_check, url="https://api.smith.langchain.com/api/v1/workspaces", header="x-api-key", scheme=None),
}
