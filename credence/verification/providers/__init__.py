"""VERIFIERS registry — single source of truth for provider verifier callables.

Each entry: pattern_name (str) → Callable[[str], Awaitable[VerificationResult]]

Lookup is by `pattern_name` matching the `type` field of secret-dicts (which is
the same as the JSON pattern name in `credence/data/credential_patterns_v02.json`).
"""

from __future__ import annotations

from .llm import LLM_VERIFIERS
from .code import CODE_VERIFIERS
from . import docker, slack, aws

VERIFIERS = {
    **LLM_VERIFIERS,
    **CODE_VERIFIERS,
    "docker_hub_pat":  docker.verify,
    "slack_token":     slack.verify,
    "aws_access_key":  aws.verify,
}

__all__ = ["VERIFIERS"]
