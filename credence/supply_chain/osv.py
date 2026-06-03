"""Async OSV.dev client.

Flow: POST /v1/querybatch (≤1000 packages/request) returns vuln IDs per query;
then hydrate each unique ID via GET /v1/vulns/{id} for severity/fix/summary.
Network failures degrade to an empty map so the caller can fall back to the
curated KNOWN_BAD_VERSIONS list. Sends only package names + versions — no secrets.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, List, Optional
from urllib.parse import quote

import httpx

from .models import Dependency, Vulnerability
from .cvss import severity_from_osv

logger = logging.getLogger(__name__)

_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
_BATCH_SIZE = 1000
_DEFAULT_TIMEOUT = 10.0
_DEFAULT_CONCURRENCY = 8
_USER_AGENT = "GitExpose-SCA/0.5"


def _fixed_version(osv_vuln: dict) -> Optional[str]:
    for affected in osv_vuln.get("affected") or []:
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event:
                    return event["fixed"]
    return None


def _to_vulnerability(osv_vuln: dict) -> Vulnerability:
    vuln_id = osv_vuln.get("id", "UNKNOWN")
    severity, score = severity_from_osv(osv_vuln)
    return Vulnerability(
        vuln_id=vuln_id,
        severity=severity,
        cvss_score=score,
        summary=osv_vuln.get("summary") or osv_vuln.get("details", "")[:200] or vuln_id,
        advisory_url=f"https://osv.dev/vulnerability/{vuln_id}",
        fixed_version=_fixed_version(osv_vuln),
        aliases=list(osv_vuln.get("aliases") or []),
        known_exploited=bool((osv_vuln.get("database_specific") or {}).get("known_exploited", False)),
    )


async def query_osv(
    deps: List[Dependency],
    *,
    timeout: float = _DEFAULT_TIMEOUT,
    concurrency: int = _DEFAULT_CONCURRENCY,
    max_deps: int = 5000,
) -> Dict[str, List[Vulnerability]]:
    """Return {purl: [Vulnerability, ...]} for the given dependencies.

    Returns {} on any network failure (caller degrades to the curated list).
    """
    if not deps:
        return {}
    deps = deps[:max_deps]
    result: Dict[str, List[Vulnerability]] = {d.purl: [] for d in deps}

    try:
        async with httpx.AsyncClient(
            timeout=timeout, headers={"User-Agent": _USER_AGENT}
        ) as client:
            # Phase 1: batch query → vuln IDs per dependency.
            purl_to_ids: Dict[str, List[str]] = {}
            for start in range(0, len(deps), _BATCH_SIZE):
                chunk = deps[start:start + _BATCH_SIZE]
                queries = [
                    {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
                    for d in chunk
                ]
                resp = await client.post(_QUERYBATCH_URL, json={"queries": queries})
                resp.raise_for_status()
                # A 200 with a malformed/non-JSON body must not crash the scan —
                # skip the batch and continue (spec §9). resp.json() raises
                # ValueError (JSONDecodeError); an unexpected shape raises
                # AttributeError/TypeError.
                try:
                    results = resp.json().get("results", [])
                    for dep, entry in zip(chunk, results):
                        ids = [v["id"] for v in (entry or {}).get("vulns", []) if v.get("id")]
                        if ids:
                            purl_to_ids[dep.purl] = ids
                except Exception as exc:  # noqa: BLE001 — degrade-able enrichment
                    logger.warning("OSV querybatch parse failed (%s); skipping batch.",
                                   type(exc).__name__)

            # Phase 2: hydrate each unique vuln ID once. Cap the total to bound
            # outbound fan-out (a dep with many advisories — or a hostile OSV —
            # must not amplify into unbounded requests). Sorted for determinism.
            unique_ids = sorted({vid for ids in purl_to_ids.values() for vid in ids})[:max_deps]
            sem = asyncio.Semaphore(concurrency)
            hydrated: Dict[str, Vulnerability] = {}

            async def _hydrate(vid: str) -> None:
                # vid comes from the (external) OSV response — URL-encode it so it
                # cannot alter the request path. Any per-vuln failure (network,
                # malformed body) is logged and skipped, never crashing the scan.
                async with sem:
                    try:
                        r = await client.get(_VULN_URL.format(id=quote(vid, safe="")))
                        if r.status_code == 200:
                            hydrated[vid] = _to_vulnerability(r.json())
                    except Exception as exc:  # noqa: BLE001 — degrade-able enrichment
                        logger.warning("OSV hydration failed for %r (%s); skipping.",
                                       vid, type(exc).__name__)

            await asyncio.gather(*(_hydrate(vid) for vid in unique_ids))

            for purl, ids in purl_to_ids.items():
                result[purl] = [hydrated[i] for i in ids if i in hydrated]
    except httpx.HTTPError as exc:
        logger.warning("OSV lookup failed (%s); falling back to curated list.", type(exc).__name__)
        return {}

    return result
