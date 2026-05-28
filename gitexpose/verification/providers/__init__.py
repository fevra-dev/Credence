"""VERIFIERS registry — single source of truth for provider verifier callables.

Each entry: pattern_name (str) → Callable[[str], Awaitable[VerificationResult]]

Lookup is by `pattern_name` matching the `type` field of secret-dicts (which is
the same as the JSON pattern name in `gitexpose/data/credential_patterns_v02.json`).
"""

from __future__ import annotations

from .llm import LLM_VERIFIERS

# Composed registry. Code providers, Docker Hub, Slack, and AWS are added in
# subsequent tasks. Each registry section is a dict-merge.
VERIFIERS = {
    **LLM_VERIFIERS,
}

__all__ = ["VERIFIERS"]
