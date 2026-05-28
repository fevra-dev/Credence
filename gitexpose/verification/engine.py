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
from typing import Any, Awaitable, Callable, Dict, List, Mapping

from .result import VerificationResult, VerificationStatus
from .providers import VERIFIERS  # the canonical registry

logger = logging.getLogger(__name__)


_DEFAULT_CONCURRENCY = 5
_DEFAULT_TIMEOUT = 5.0


def _secret_value(record: Mapping[str, Any]) -> str:
    """Pull the raw secret string out of a record.

    Records may be:
      - secret-dicts from SecretExtractor (key: 'value_full')
      - ScanResult-shaped dicts (we use 'evidence' or similar — caller normalizes)
    """
    return record.get("value_full") or record.get("secret") or ""


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
    seen: Dict[str, VerificationResult] = {}

    async def _one(record: Dict[str, Any]) -> None:
        pattern = _pattern_name(record)
        secret = _secret_value(record)

        verifier: Callable[[str], Awaitable[VerificationResult]] | None = VERIFIERS.get(pattern)
        if verifier is None:
            record["verification_status"] = VerificationStatus.UNVERIFIABLE.value
            record["verification_detail"] = None
            return

        if secret in seen:
            result = seen[secret]
        else:
            async with sem:
                try:
                    result = await asyncio.wait_for(verifier(secret), timeout=timeout)
                except asyncio.TimeoutError:
                    result = VerificationResult(VerificationStatus.ERROR, "timeout")
                except Exception as exc:  # noqa: BLE001 — capture provider failures
                    logger.debug("Verifier raised for %s: %s", pattern, type(exc).__name__)
                    result = VerificationResult(VerificationStatus.ERROR, type(exc).__name__)
            seen[secret] = result

        record["verification_status"] = result.status.value
        record["verification_detail"] = result.detail

    await asyncio.gather(*(_one(r) for r in secrets))
    return secrets
