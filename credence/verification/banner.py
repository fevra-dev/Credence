"""Consent banner for --verify mode.

Prints to stderr (not stdout, so it doesn't pollute piped JSON/SARIF output).
"""

from __future__ import annotations

import sys

_BANNER = """\
[verify] Sending candidate credentials to provider APIs for liveness check.
[verify] Hosts: api.openai.com, api.anthropic.com, api.groq.com, openrouter.ai,
[verify]        api.x.ai, api.cerebras.ai, huggingface.co,
[verify]        api.elevenlabs.io, api.pinecone.io, api.smith.langchain.com,
[verify]        api.github.com, gitlab.com, hub.docker.com, slack.com,
[verify]        sts.amazonaws.com
[verify] Pass --no-verify-banner to suppress.
"""


def print_verify_banner(suppress: bool = False) -> None:
    """Print the consent banner unless suppress=True."""
    if suppress:
        return
    sys.stderr.write(_BANNER)
    sys.stderr.flush()
