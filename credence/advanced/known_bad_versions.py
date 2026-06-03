"""Known-malicious AI package versions and the scanner that flags them."""

from __future__ import annotations

import re
from typing import Dict, List, Set

# Package -> set of known-compromised version strings.
# Sources:
#   - LiteLLM/TeamPCP: official LiteLLM advisory, March 24 2026
#   - Telnyx: TeamPCP follow-on, March 27 2026 (WAV-steganography payload)
#   - Xinference: late 2025, base64 payload in __init__.py
#   - gptplus / claudeai-eng / hermes-px: entirely-malicious packages — any version
KNOWN_BAD_VERSIONS: Dict[str, Set[str]] = {
    "litellm": {"1.82.7", "1.82.8"},
    "telnyx": {"4.87.1", "4.87.2"},
    "xinference": {"2.6.0", "2.6.1", "2.6.2"},
    "gptplus": {"*"},
    "claudeai-eng": {"*"},
    "hermes-px": {"*"},
}

_REQ_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)\s*"
    r"(?:\[[^\]]*\])?\s*"
    r"(?:==\s*(?P<version>[^\s;]+))?",
    re.MULTILINE,
)


def scan_requirements(content: str, source: str = "requirements.txt") -> List[Dict]:
    findings: List[Dict] = []
    for line in content.splitlines():
        # Strip inline comments and PEP 508 markers consistently with dependency_pinning
        stripped = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not stripped:
            continue
        match = _REQ_LINE.match(stripped)
        if not match:
            continue
        name = match.group("name").lower().replace("_", "-")
        version = match.group("version")
        if name not in KNOWN_BAD_VERSIONS:
            continue
        bad = KNOWN_BAD_VERSIONS[name]
        if "*" in bad or (version is not None and version in bad):
            findings.append({
                "type": "known_malicious_package_version",
                "package": name,
                "version": version or "*",
                "source": source,
                "severity": "CRITICAL",
                "attack_class": "LLM05",
                "atlas_technique": "AML.T0019",
                "evidence": f"{name}=={version or '*'} — known compromised version",
                "description": (
                    f"Package '{name}' at version '{version or '*'}' is on the "
                    "known-malicious-version corpus. Remove immediately and rotate "
                    "any credentials accessible to the install environment."
                ),
            })
    return findings
