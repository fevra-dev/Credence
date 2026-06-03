"""Slopsquatting — detect known LLM-hallucinated package names.

Background: Spracklen et al., "We Have a Package for You!" (USENIX 2025) showed
that ~20% of LLM-suggested code recommends non-existent packages. 43% of those
hallucinations are reproducible across runs, making them reliable targets to
pre-register as malware. The huggingface-cli case (30K downloads) confirmed the
attack class is real.
"""

from __future__ import annotations

import re
from typing import Dict, List

# Curated initial corpus. Sources:
#   - huggingface-cli: confirmed real-world (Alibaba README hallucination, 30K dls)
#   - High-risk variants from common LLM hallucinations of the form "<sdk>-<provider>"
KNOWN_SLOPSQUATS = frozenset({
    "huggingface-cli",
    "huggingface-py",
    "huggingface-sdk",
    "openai-sdk",
    "openai-python",
    "openai-api",
    "anthropic-sdk",
    "anthropicc",
    "langchai",
    "langchian",
    "langchain-py",
    "langchain-sdk",
    "deepseek-sdk",
    "deepseek-api",
    "deepseeksdk",
    "deepseekai",
    "gptplus",
    "claudeai-eng",
    "hermes-px",
    "crewai-tools-fake",
    "autogen-fake",
})


_REQ_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)\s*"
    r"(?:\[[^\]]*\])?",
    re.MULTILINE,
)


def _normalize(name: str) -> str:
    return name.lower().replace("_", "-").strip()


def check(name: str) -> bool:
    """Return True if name matches the known-slopsquat corpus."""
    return _normalize(name) in KNOWN_SLOPSQUATS


def scan_requirements(content: str, source: str = "requirements.txt") -> List[Dict]:
    findings: List[Dict] = []
    for line in content.splitlines():
        # Strip inline comments and PEP 508 markers (consistent with other supply-chain scanners)
        stripped = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not stripped:
            continue
        match = _REQ_LINE.match(stripped)
        if not match:
            continue
        name = _normalize(match.group("name"))
        if not check(name):
            continue
        findings.append({
            "type": "slopsquatting",
            "package": name,
            "source": source,
            "severity": "CRITICAL",
            "attack_class": "LLM05",
            "atlas_technique": "AML.T0019",
            "description": (
                f"Package '{name}' matches the known-slopsquat corpus — names that "
                "LLMs commonly hallucinate and that have been pre-registered as "
                "malware. Verify the legitimate package name before installing."
            ),
        })
    return findings
