"""Turn OSV results into vulnerable_dependency finding-dicts + exploitability ranking.

The CVSS-scoring discipline (spec §6): rank by exploitability *context*
(direct / fix-available / unpinned / credential co-presence), with CVSS as a
secondary key — not the primary one. A finding nobody has proven exploitable is
a hypothesis, not a vulnerability.
"""

from __future__ import annotations

from typing import Dict, List, Set

from .models import Dependency, Vulnerability

_ATTACK_CLASS = "OWASP A06:2021 Vulnerable & Outdated Components"

# AI middleware packages keep an ATLAS tag (mirrors known_bad_versions).
_AI_MIDDLEWARE = frozenset({
    "litellm", "langchain", "langchain-core", "langchain-community",
    "llama-index", "llama-index-core", "autogen", "crewai", "openai", "anthropic",
})

_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def build_vuln_findings(
    osv_map: Dict[str, List[Vulnerability]],
    deps: List[Dependency],
    *,
    unpinned_packages: Set[str],
    cred_sources: Set[str],
) -> List[Dict]:
    """Build vulnerable_dependency finding-dicts from the OSV map.

    `unpinned_packages` = normalized names flagged unpinned by dependency_pinning.
    `cred_sources` = source files where a credential finding was detected
    (used for the credential-co-presence exploitability signal).
    """
    by_purl = {d.purl: d for d in deps}
    findings: List[Dict] = []
    for purl, vulns in osv_map.items():
        dep = by_purl.get(purl)
        if dep is None:
            continue
        pinned = dep.name not in unpinned_packages
        cred_co_present = dep.source_file in cred_sources
        for v in vulns:
            findings.append({
                "type": "vulnerable_dependency",
                "package": dep.name,
                "version": dep.version,
                "ecosystem": dep.ecosystem,
                "purl": dep.purl,
                "vuln_id": v.vuln_id,
                "aliases": v.aliases,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "fixed_version": v.fixed_version,
                "fix_available": v.fixed_version is not None,
                "summary": v.summary,
                "advisory_url": v.advisory_url,
                "source": dep.source_file,
                "direct": dep.direct,
                "pinned": pinned,
                "cred_co_present": cred_co_present,
                "known_exploited": v.known_exploited,
                "attack_class": _ATTACK_CLASS,
                "atlas_technique": "AML.T0019" if dep.name in _AI_MIDDLEWARE else None,
                "verification_status": "skipped",
                "verification_detail": None,
            })
    return findings


def exploitability_sort_key(finding: Dict) -> tuple:
    """Primary sort by exploitability context; CVSS is only the tiebreaker.

    Higher tuple = more exploitable = sorted first (use reverse=True).
    """
    return (
        1 if finding.get("cred_co_present") else 0,
        1 if finding.get("known_exploited") else 0,
        1 if finding.get("direct") else 0,
        1 if not finding.get("pinned") else 0,
        1 if finding.get("fix_available") else 0,
        _SEV_ORDER.get((finding.get("severity") or "").upper(), 0),
        finding.get("cvss_score") or 0.0,
    )
