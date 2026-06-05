"""SARIF 2.1.0 emitter for workflow-audit (mirrors agent_exposure/sarif.py)."""

from __future__ import annotations

import json
from typing import Dict, List

_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
          "LOW": "note", "INFO": "note"}


def _rule_descriptors(findings: List[Dict]) -> List[Dict]:
    by_id: Dict[str, Dict] = {}
    for f in findings:
        by_id.setdefault(f["rule_id"], {
            "id": f["rule_id"],
            "name": f.get("title", f["rule_id"]),
            "shortDescription": {"text": f.get("title", f["rule_id"])},
            "properties": {"tags": (f.get("frameworks", {}).get("cicd_sec", [])
                                    + f.get("frameworks", {}).get("mitre", []))},
        })
    return list(by_id.values())


def _result(f: Dict) -> Dict:
    fw = f.get("frameworks", {})
    res = {
        "ruleId": f["rule_id"],
        "level": _LEVEL.get(f["severity"], "warning"),
        "message": {"text": f.get("message", f.get("title", ""))},
        "partialFingerprints": {"credence/v1": f.get("fingerprint", "")},
        "properties": {
            "tags": fw.get("cicd_sec", []) + fw.get("mitre", []),
            "confidence": f.get("confidence", ""),
            "source": f.get("source", "working_tree"),
            "identity_flags": f.get("identity_flags", []),
            "persists_in_history_only": f.get("persists_in_history_only", False),
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f["file_path"]},
                "region": {"startLine": max(1, int(f.get("line", 1)))},
            }
        }],
    }
    if f.get("suppressed"):
        res["suppressions"] = [{
            "kind": "inSource",
            "justification": f.get("suppression_reason") or "credence:ignore",
        }]
    return res


def to_sarif(findings: List[Dict]) -> str:
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "credence-workflow-audit",
                "informationUri": "https://github.com/fevra-dev/Credence",
                "rules": _rule_descriptors(findings),
            }},
            "results": [_result(f) for f in findings],
        }],
    }
    return json.dumps(doc, indent=2)
