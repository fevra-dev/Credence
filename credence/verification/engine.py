"""Async dispatcher for the verification engine.

Walks a list of secret-dicts, looks each up in the VERIFIERS registry, and writes
back two keys per secret: `verification_status` and `verification_detail`. Uses a
shared semaphore to cap provider-side load and in-run dedup keyed by raw secret
value.

Does NOT mutate any other finding fields. Existing fields are preserved.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Awaitable, Callable, Dict, List, Mapping

from .result import VerificationResult, VerificationStatus
from .providers import VERIFIERS  # the canonical registry

logger = logging.getLogger(__name__)

_AWS_SECRET_RE = re.compile(r"[0-9a-zA-Z/+=]{40}")

_DEFAULT_CONCURRENCY = 5
_DEFAULT_TIMEOUT = 5.0


def _secret_value(record: Mapping[str, Any]) -> str:
    """Pull the raw secret string out of a record.

    Prefers `_verify_input` (e.g., the AWS "access:secret" pair built by
    pair_aws_credentials), then falls back to value_full / secret.
    """
    return record.get("_verify_input") or record.get("value_full") or record.get("secret") or ""


def pair_aws_credentials(secrets: List[Dict[str, Any]]) -> None:
    """For each aws_access_key finding, if an aws_secret_key finding shares the
    same `source`, set `_verify_input` = '<access>:<secret>' so the AWS verifier
    can confirm liveness. Mutates in place. Unpaired access keys are left as-is
    (they verify as ERROR 'expected access:secret pair')."""
    secrets_by_source: Dict[str, str] = {}
    for f in secrets:
        if f.get("type") == "aws_secret_key":
            src = f.get("source") or ""
            raw = f.get("value_full") or ""
            m = _AWS_SECRET_RE.search(raw)
            clean = m.group(0) if m else raw
            secrets_by_source.setdefault(src, clean)
    for f in secrets:
        if f.get("type") == "aws_access_key":
            src = f.get("source") or ""
            secret_key = secrets_by_source.get(src)
            if secret_key:
                f["_verify_input"] = f"{f.get('value_full', '')}:{secret_key}"


def _pattern_name(record: Mapping[str, Any]) -> str:
    """Pull the pattern identifier out of a record."""
    return record.get("type") or record.get("pattern_name") or ""


async def verify_secrets(
    secrets: List[Dict[str, Any]],
    *,
    concurrency: int = _DEFAULT_CONCURRENCY,
    timeout: float = _DEFAULT_TIMEOUT,
) -> List[Dict[str, Any]]:
    """Verify every secret in `secrets` whose pattern is in VERIFIERS.

    Mutates each dict in-place (sets verification_status + verification_detail)
    and also returns the list.

    Concurrency is capped via a shared semaphore. Identical raw secrets within a
    single call are verified once (in-run dedup).
    """
    sem = asyncio.Semaphore(concurrency)
    results: Dict[str, VerificationResult] = {}   # secret -> completed result
    events: Dict[str, asyncio.Event] = {}         # secret -> in-flight signal

    async def _resolve(
        secret: str,
        verifier: Callable[[str], Awaitable[VerificationResult]],
    ) -> VerificationResult:
        """Verify `secret` at most once per run, even under concurrency.

        The check-then-register below contains no `await`, so under asyncio's
        cooperative scheduling it is atomic: exactly one coroutine becomes the
        computer for a given secret; the rest await its Event. This prevents the
        request amplification where K identical findings would each fire an
        outbound auth request to the provider.
        """
        if secret in results:
            return results[secret]
        ev = events.get(secret)
        if ev is not None:                # another coroutine is computing it
            await ev.wait()
            return results[secret]
        ev = events[secret] = asyncio.Event()   # we are the computer (no await above)

        async with sem:
            try:
                result = await asyncio.wait_for(verifier(secret), timeout=timeout)
            except asyncio.TimeoutError:
                result = VerificationResult(VerificationStatus.ERROR, "timeout")
            except Exception as exc:  # noqa: BLE001 — capture provider failures
                logger.debug("Verifier raised: %s", type(exc).__name__)
                result = VerificationResult(VerificationStatus.ERROR, type(exc).__name__)
        results[secret] = result
        ev.set()                          # release any waiters
        return result

    async def _one(record: Dict[str, Any]) -> None:
        pattern = _pattern_name(record)
        secret = _secret_value(record)

        verifier: Callable[[str], Awaitable[VerificationResult]] | None = VERIFIERS.get(pattern)
        if verifier is None:
            record["verification_status"] = VerificationStatus.UNVERIFIABLE.value
            record["verification_detail"] = None
            return

        result = await _resolve(secret, verifier)
        record["verification_status"] = result.status.value
        record["verification_detail"] = result.detail

    await asyncio.gather(*(_one(r) for r in secrets))
    return secrets
