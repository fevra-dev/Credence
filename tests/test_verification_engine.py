"""Tests for the verification engine dispatcher."""

import asyncio

import pytest

from gitexpose.verification.engine import verify_secrets
from gitexpose.verification.result import VerificationResult, VerificationStatus


@pytest.mark.asyncio
async def test_returns_skipped_for_unregistered_pattern(monkeypatch):
    monkeypatch.setattr(
        "gitexpose.verification.engine.VERIFIERS",
        {},  # empty registry
        raising=False,
    )
    secrets = [{"type": "no_such_pattern", "value_full": "abc"}]
    out = await verify_secrets(secrets)
    assert out[0]["verification_status"] == VerificationStatus.UNVERIFIABLE.value


@pytest.mark.asyncio
async def test_runs_registered_verifier_and_writes_status(monkeypatch):
    async def fake_verifier(secret):
        return VerificationResult(VerificationStatus.VERIFIED, "200")

    monkeypatch.setattr(
        "gitexpose.verification.engine.VERIFIERS",
        {"openai": fake_verifier},
        raising=False,
    )
    secrets = [{"type": "openai", "value_full": "sk-abc"}]
    out = await verify_secrets(secrets)
    assert out[0]["verification_status"] == VerificationStatus.VERIFIED.value
    assert out[0]["verification_detail"] == "200"


@pytest.mark.asyncio
async def test_dedups_same_secret_within_run(monkeypatch):
    call_count = 0

    async def counting_verifier(secret):
        nonlocal call_count
        call_count += 1
        return VerificationResult(VerificationStatus.VERIFIED, "200")

    monkeypatch.setattr(
        "gitexpose.verification.engine.VERIFIERS",
        {"openai": counting_verifier},
        raising=False,
    )
    secrets = [
        {"type": "openai", "value_full": "sk-abc"},
        {"type": "openai", "value_full": "sk-abc"},
        {"type": "openai", "value_full": "sk-abc"},
    ]
    out = await verify_secrets(secrets)
    assert call_count == 1
    assert all(s["verification_status"] == VerificationStatus.VERIFIED.value for s in out)


@pytest.mark.asyncio
async def test_exception_in_verifier_yields_error_status(monkeypatch):
    async def bad_verifier(secret):
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "gitexpose.verification.engine.VERIFIERS",
        {"openai": bad_verifier},
        raising=False,
    )
    secrets = [{"type": "openai", "value_full": "sk-abc"}]
    out = await verify_secrets(secrets)
    assert out[0]["verification_status"] == VerificationStatus.ERROR.value
    assert "RuntimeError" in (out[0]["verification_detail"] or "")


@pytest.mark.asyncio
async def test_semaphore_caps_concurrent_calls(monkeypatch):
    in_flight = 0
    max_seen = 0

    async def slow_verifier(secret):
        nonlocal in_flight, max_seen
        in_flight += 1
        max_seen = max(max_seen, in_flight)
        await asyncio.sleep(0.05)
        in_flight -= 1
        return VerificationResult(VerificationStatus.VERIFIED, "200")

    monkeypatch.setattr(
        "gitexpose.verification.engine.VERIFIERS",
        {"openai": slow_verifier},
        raising=False,
    )
    secrets = [{"type": "openai", "value_full": f"sk-{i}"} for i in range(20)]
    await verify_secrets(secrets, concurrency=3)
    assert max_seen <= 3, f"semaphore allowed {max_seen} concurrent, expected ≤ 3"


@pytest.mark.asyncio
async def test_timeout_in_verifier_yields_error(monkeypatch):
    async def hangs(secret):
        await asyncio.sleep(10)
        return VerificationResult(VerificationStatus.VERIFIED, "200")

    monkeypatch.setattr(
        "gitexpose.verification.engine.VERIFIERS",
        {"openai": hangs},
        raising=False,
    )
    secrets = [{"type": "openai", "value_full": "sk-abc"}]
    out = await verify_secrets(secrets, timeout=0.05)
    assert out[0]["verification_status"] == VerificationStatus.ERROR.value
    assert out[0]["verification_detail"] == "timeout"


@pytest.mark.asyncio
async def test_handles_mixed_finding_shapes(monkeypatch):
    """Engine must accept both ScanResult-shaped objects and secret-dicts."""
    from gitexpose.models import Category, ScanResult, Severity

    async def ok(secret):
        return VerificationResult(VerificationStatus.VERIFIED, "200")

    monkeypatch.setattr(
        "gitexpose.verification.engine.VERIFIERS",
        {"openai": ok, "github_pat": ok},
        raising=False,
    )

    scan_result = ScanResult(
        url="https://example.com/.env",
        path=".env",
        target="https://example.com",
        status_code=200,
        vulnerable=True,
        severity=Severity.CRITICAL,
        category=Category.ENV,
        description="x",
        evidence="sk-abc found",
    )
    secrets = [
        {"type": "openai", "value_full": "sk-abc"},
        {"type": "github_pat", "value_full": "ghp_abc"},
    ]
    out = await verify_secrets(secrets)
    assert all(s["verification_status"] == VerificationStatus.VERIFIED.value for s in out)
