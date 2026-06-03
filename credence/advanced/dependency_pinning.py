"""Detect unpinned AI middleware in dependency files (TeamPCP-class supply chain risk)."""

from __future__ import annotations

import re
from typing import Dict, List

# AI middleware packages where unpinned versions are a supply-chain risk.
# The TeamPCP March 2026 incident showed how a compromised maintainer token can
# push malicious versions in minutes. Pinning to a known-good version mitigates.
AI_MIDDLEWARE_PACKAGES = frozenset({
    "litellm",
    "langchain",
    "langchain-core",
    "langchain-community",
    "llama-index",
    "llama-index-core",
    "autogen",
    "crewai",
    "openai",
    "anthropic",
})

# requirements.txt-style lines: `package`, `package==version`, `package>=version`,
# with optional extras `package[extras]`. We only want a HARD pin (`==`).
_REQ_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)\s*"
    r"(?:\[[^\]]*\])?\s*"
    r"(?P<spec>(?:==|>=|>|~=|<|<=|!=)?[^\s;]*)?\s*$",
    re.MULTILINE,
)


class DependencyPinningScanner:
    """Scan requirements.txt-style content for unpinned AI middleware."""

    def scan(self, content: str, source: str = "requirements.txt") -> List[Dict]:
        findings: List[Dict] = []
        for line in content.splitlines():
            stripped = line.split("#", 1)[0].split(";", 1)[0].strip()
            if not stripped:
                continue
            match = _REQ_LINE.match(stripped)
            if not match:
                continue
            name = match.group("name").lower().replace("_", "-")
            spec = (match.group("spec") or "").strip()
            if name not in AI_MIDDLEWARE_PACKAGES:
                continue
            # Hard-pinned (==) is OK; everything else is unpinned for our purposes.
            if spec.startswith("=="):
                continue
            findings.append({
                "type": "unpinned_ai_middleware",
                "package": name,
                "source": source,
                "line": line,
                "severity": "HIGH",
                "attack_class": "LLM05",
                "atlas_technique": "AML.T0019",
                "description": (
                    f"AI middleware '{name}' is not pinned. A compromised maintainer "
                    "token (TeamPCP-class incident) would push malicious versions "
                    "without warning. Pin to a known-good version."
                ),
            })
        return findings
