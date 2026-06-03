"""SARIF 2.1.0 emitter for agent-exposure finding-dicts (GitHub Code Scanning).

Focused serializer for the plain finding dicts that `agent_exposure.scan()` returns.
The web reporters' SARIFReporter is coupled to the ScanReport model and is not reused;
this mirrors its structure (rules + results + compliance taxonomy refs) for dicts.
"""

from __future__ import annotations

import json
from typing import Dict, List

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/fevra-dev/Credence"
_TAXONOMY_NAME = "Credence-compliance"

_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
          "LOW": "note", "INFO": "note"}


def _rule_id(f: Dict) -> str:
    t = f.get("type", "finding")
    cls = f.get("capability_class")
    return f"{t}/{cls}" if cls else t


def to_sarif(findings: List[Dict], tool_version: str) -> str:
    rules: Dict[str, Dict] = {}
    results: List[Dict] = []
    taxa: Dict[str, Dict] = {}   # id -> taxon

    for f in findings:
        rid = _rule_id(f)
        compliance = {k: f[k] for k in ("attack_class", "atlas_technique", "mitre_attack")
                      if f.get(k)}
        for tid in compliance.values():
            taxa.setdefault(tid, {"id": tid})

        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rid.replace("/", "_"),
                "shortDescription": {"text": f.get("type", "finding")},
                "fullDescription": {"text": f.get("description", rid)},
                "helpUri": _INFO_URI,
                "properties": dict(compliance),
            }

        level = _LEVEL.get((f.get("severity") or "INFO").upper(), "note")
        result_props = {k: f[k] for k in ("severity", "capability_class", "attack_class",
                                          "atlas_technique", "mitre_attack", "exfil_chain")
                        if f.get(k) is not None}
        result_obj = {
            "ruleId": rid,
            "level": level,
            "message": {"text": f.get("description") or f.get("type", "finding")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("source") or "unknown"},
                    "region": {"startLine": f.get("line", 1)},
                }
            }],
            "taxa": [{"toolComponent": {"name": _TAXONOMY_NAME}, "id": tid}
                     for tid in compliance.values()],
            "properties": result_props,
        }
        if f.get("secret_value_hash"):
            result_obj["partialFingerprints"] = {
                "secretValueHash/v1": f["secret_value_hash"]
            }
        if f.get("source_frequency"):
            result_obj["properties"]["source_frequency"] = f["source_frequency"]
        results.append(result_obj)

    doc = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Credence",
                "version": tool_version,
                "informationUri": _INFO_URI,
                "rules": list(rules.values()),
            }},
            "taxonomies": [{
                "name": _TAXONOMY_NAME,
                "shortDescription": {
                    "text": "OWASP LLM Top 10 / MITRE ATLAS / MITRE ATT&CK references"
                },
                "taxa": list(taxa.values()),
            }],
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)
