"""SARIF 2.1.0 reporter — for GitHub Code Scanning compatibility."""

from __future__ import annotations

import json
from typing import Any, Dict, List

from .. import __version__
from ..models import ScanReport, ScanResult, Severity
from .base import BaseReporter

# Map GitExpose severity to SARIF level.
_LEVEL_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


class SARIFReporter(BaseReporter):
    """Generate SARIF 2.1.0 output."""

    def generate(self, report: ScanReport) -> str:
        sarif: Dict[str, Any] = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "runs": [self._build_run(report)],
        }
        return json.dumps(sarif, indent=2)

    def _build_run(self, report: ScanReport) -> Dict[str, Any]:
        results = list(self._iter_results(report))
        rules = list(self._iter_rules(report))
        taxonomies = self._build_taxonomies(report)
        return {
            "tool": {
                "driver": {
                    "name": "GitExpose",
                    "version": __version__,
                    "informationUri": "https://github.com/fevra-dev/GitExpose",
                    "rules": rules,
                }
            },
            "results": results,
            "taxonomies": taxonomies,
        }

    def _iter_results(self, report: ScanReport):
        for tr in report.target_reports:
            for f in tr.findings:
                yield self._result_for(f)

    def _result_for(self, f: ScanResult) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "ruleId": f.category.value if f.category else "exposure",
            "level": _LEVEL_MAP.get(f.severity, "warning"),
            "message": {"text": f"{f.description}: {f.evidence}".strip(": ")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.url},
                    }
                }
            ],
        }
        taxa: List[Dict[str, Any]] = []
        if f.atlas_technique:
            taxa.append({
                "id": f.atlas_technique,
                "toolComponent": {"name": "MITRE ATLAS"},
            })
        if f.attack_class:
            taxa.append({
                "id": f.attack_class,
                "toolComponent": {"name": "OWASP LLM Top 10"},
            })
        if taxa:
            result["taxa"] = taxa

        # Verification status
        verification_status = getattr(f, "verification_status", "skipped")
        properties: Dict[str, Any] = {"verification_status": verification_status}
        if verification_status == "verified":
            tag = "verified-live"
        elif verification_status == "dead":
            tag = "verified-dead"
        elif verification_status == "error":
            tag = "verification-error"
        else:
            tag = None
        if tag:
            properties["tags"] = [tag]
        result["properties"] = properties

        return result

    def _iter_rules(self, report: ScanReport) -> List[Dict[str, Any]]:
        seen: Dict[str, Dict[str, Any]] = {}
        for tr in report.target_reports:
            for f in tr.findings:
                rid = f.category.value if f.category else "exposure"
                if rid not in seen:
                    seen[rid] = {
                        "id": rid,
                        "name": rid.replace("_", " ").title(),
                        "shortDescription": {"text": f.description or rid},
                    }
        return list(seen.values())

    def _build_taxonomies(self, report: ScanReport) -> List[Dict[str, Any]]:
        return [
            {
                "name": "MITRE ATLAS",
                "version": "5.4.0",
                "informationUri": "https://atlas.mitre.org/",
                "shortDescription": {"text": "Adversarial Threat Landscape for AI Systems"},
            },
            {
                "name": "OWASP LLM Top 10",
                "version": "2025",
                "informationUri": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                "shortDescription": {"text": "OWASP Top 10 risks for LLM applications"},
            },
        ]
