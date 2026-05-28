"""VERIFIERS registry — single source of truth for provider verifier callables.

Each entry: pattern_name (str) → Callable[[str], Awaitable[VerificationResult]]

Subsequent tasks (LLM providers, code providers, Docker Hub, Slack, AWS) extend
this registry. This task creates the empty scaffold so engine.py can import it.
"""

from __future__ import annotations

VERIFIERS: dict = {}

__all__ = ["VERIFIERS"]
