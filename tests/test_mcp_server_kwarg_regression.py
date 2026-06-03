"""Regression tests for the v0.2 carry-over bug in mcp_server.py."""

import inspect

import pytest

from credence.advanced.mcp_server import GitExposeMCPServer
from credence.secrets.secret_extractor import SecretExtractor


def test_secret_extractor_extract_has_no_validate_kwarg():
    """API contract: extract() does NOT take a validate kwarg.
    If this changes, re-audit every callsite (specifically mcp_server.py)."""
    sig = inspect.signature(SecretExtractor.extract)
    assert "validate" not in sig.parameters, (
        "If you added a `validate` kwarg to extract(), re-audit mcp_server.py "
        "which used to call extract(content, validate=...)."
    )


@pytest.mark.asyncio
async def test_mcp_server_execute_secret_extraction_succeeds_with_validate():
    """Integration: _execute_secret_extraction completes without falling into
    the try/except error path when validate=True is requested."""
    server = GitExposeMCPServer()
    result = await server._execute_secret_extraction({
        "content": "GROQ_API_KEY=gsk_" + "a" * 52,
        "validate": True,
    })
    # Must NOT have swallowed an exception via the try/except path
    assert "error" not in result, f"Function fell into error path: {result.get('error')}"
    assert "secrets_found" in result
    assert result["secrets_found"] >= 1
    # The masked output uses the public key "valid" (do not change this)
    assert "secrets" in result
    for secret in result["secrets"]:
        assert "valid" in secret  # public output key — kept as-is
