"""Post-processor: paired-secret cluster + multi-provider-key file flagging.

Runs over the flat list of finding-dicts emitted by SecretExtractor and the
supply-chain scanners. Adds two new finding types alongside originals:

  - credential_cluster:           >=2 distinct secret types in same file
  - multi_provider_credential_file: cluster appears in a known aggregator path
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Dict, List

# Paths whose names indicate purpose-built multi-provider credential aggregators.
# A cluster finding in these gets upgraded to multi_provider_credential_file.
_MULTI_PROVIDER_AGGREGATORS = (
    re.compile(r"(^|/)OAI_CONFIG_LIST(\.|$)"),
    re.compile(r"(^|/)litellm[_-]?config\.(yaml|yml|json)$", re.IGNORECASE),
    re.compile(r"(^|/)\.continue/agents/.*\.yaml$"),
)

# Suffix tokens that indicate a finding type is a credential.
# Substring matching (not endswith) so versioned variants like
# langsmith_api_key_v2 and langsmith_api_key_legacy are correctly identified.
_SECRET_TYPE_TOKENS = (
    "_api_key",
    "_token",
    "_pat",
    "_webhook",
    "_key",
    "_sid",
    "_password",
    "_url",  # DB connection strings: postgres_url, mongodb_url, mysql_url
    "private_key",
    "jwt_token",
)

# Explicit allow-list for credential types whose names don't fit the substring heuristic.
_EXPLICIT_SECRET_TYPES = frozenset({
    "elevenlabs_context_bound",
})


def _is_secret(finding: Dict) -> bool:
    t = finding.get("type", "")
    if not t:
        return False
    if t in _EXPLICIT_SECRET_TYPES:
        return True
    return any(token in t for token in _SECRET_TYPE_TOKENS)


def _is_aggregator_path(source: str) -> bool:
    return any(p.search(source or "") for p in _MULTI_PROVIDER_AGGREGATORS)


def process(findings: List[Dict], registry=None) -> List[Dict]:
    """Return original findings plus any cluster/multi-provider findings.

    Before clustering, enrich secret findings with secret_value_hash and (when a
    registry is supplied) source_frequency. Enrichment mutates findings in place.
    """
    from .secret_registry import enrich
    enrich(findings, registry)
    by_source: Dict[str, List[Dict]] = defaultdict(list)
    for f in findings:
        if _is_secret(f):
            by_source[f.get("source", "")].append(f)

    additions: List[Dict] = []
    for source, secrets in by_source.items():
        types = sorted({s.get("type") for s in secrets if s.get("type")})
        if len(types) < 2:
            continue
        cluster = {
            "type": "credential_cluster",
            "source": source,
            "severity": "CRITICAL",
            "attack_class": "LLM06",
            "atlas_technique": "AML.T0019",
            "member_types": types,
            "member_findings": secrets,
            "description": (
                f"{len(types)} distinct secret types co-occur in {source}. "
                "Blast-radius: compromise of this file leaks credentials for "
                "multiple providers simultaneously."
            ),
        }
        additions.append(cluster)
        if _is_aggregator_path(source):
            additions.append({
                "type": "multi_provider_credential_file",
                "source": source,
                "severity": "CRITICAL",
                "attack_class": "LLM06",
                "atlas_technique": "AML.T0019",
                "member_types": types,
                "description": (
                    f"{source} is a known multi-provider credential aggregator path "
                    f"and contains {len(types)} distinct secret types. Single point "
                    "of compromise for the entire AI provider matrix."
                ),
            })

    return findings + additions
