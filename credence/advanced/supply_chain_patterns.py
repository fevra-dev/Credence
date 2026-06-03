"""Text patterns for TeamPCP-class supply-chain post-compromise indicators."""

from __future__ import annotations

import re
from typing import Dict, List

# Patterns are tuples: (name, regex, severity, attack_class, atlas_technique, description, file_filter)
# file_filter is None or a callable taking the filename.

_PATTERNS = [
    {
        "name": "pth_persistence",
        "regex": re.compile(
            r"(?:exec\s*\(|eval\s*\(|base64\s*\.\s*b64decode)",
        ),
        "severity": "CRITICAL",
        "attack_class": "LLM05",
        "atlas_technique": "AML.T0019",
        "description": (
            "Python .pth file containing exec/eval/base64 — runs on every Python "
            "interpreter invocation, surviving pip uninstall (TeamPCP technique)."
        ),
        "file_filter": lambda name: name.endswith(".pth"),
    },
    {
        "name": "ai_c2_beacon",
        "regex": re.compile(
            r"(?i)(?:on\s+(?:every|each)\s+(?:run|startup|invocation|session)|"
            r"phone\s+home|beacon|heartbeat|"
            r"(?:fetch|poll|check)\s+(?:new\s+)?(?:commands?|instructions?))"
            r"[^\n]{0,80}https?://",
        ),
        "severity": "CRITICAL",
        "attack_class": "LLM08",
        "atlas_technique": "AML.TA0015",
        "description": (
            "Skill instructs AI agent to operate as a persistent C2 implant "
            "(MITRE ATLAS AML.TA0015 — Command and Control via AI agent)."
        ),
        "file_filter": None,
    },
    {
        "name": "kubernetes_exfiltration",
        "regex": re.compile(
            r"(?i)(?:kubectl\s+(?:get\s+secrets?|exec|cp)|"
            r"/var/run/secrets/kubernetes\.io/serviceaccount|"
            r"KUBERNETES_SERVICE_HOST)",
        ),
        "severity": "CRITICAL",
        "attack_class": "LLM06",
        "atlas_technique": "AML.T0037",
        "description": (
            "Kubernetes secret enumeration / service-account token access "
            "(TeamPCP-class lateral movement indicator)."
        ),
        "file_filter": None,
    },
]


def scan_text(content: str, filename: str = "", source: str = "") -> List[Dict]:
    """Scan text for supply-chain post-compromise patterns."""
    findings: List[Dict] = []
    for spec in _PATTERNS:
        if spec["file_filter"] is not None and not spec["file_filter"](filename):
            continue
        match = spec["regex"].search(content)
        if not match:
            continue
        line_num = content[:match.start()].count("\n") + 1
        start = max(0, match.start() - 40)
        end = min(len(content), match.end() + 40)
        context = content[start:end].replace("\n", " ")
        findings.append({
            "type": spec["name"],
            "filename": filename,
            "source": source or filename,
            "line": line_num,
            "context": context,
            "severity": spec["severity"],
            "attack_class": spec["attack_class"],
            "atlas_technique": spec["atlas_technique"],
            "description": spec["description"],
        })
    return findings
