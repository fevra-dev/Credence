"""AI-supply-chain content detectors (working-tree analysis).

Three detectors, all returning lists of finding-dicts in the SecretExtractor
shape (so reporters and the cluster post-processor handle them uniformly):
  - detect_polyglot(path): a text-extension file whose leading bytes are a
    binary/executable/archive signature (disguised payload). Hand-rolled
    magic-byte detection — no system-lib dependency, so it works everywhere.
  - scan_skill_injection(path, content): hidden directives in instruction files.
  - scan_agent_config_content(path, content): malicious payloads inside
    multi-agent configs.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List

# ---------------------------------------------------------------- polyglot

# Text-ish extensions whose CONTENT should not be a binary/executable/archive.
_TEXT_EXTS = {".md", ".markdown", ".yaml", ".yml", ".json", ".txt", ".py", ".js", ".ts"}

# (signature_bytes, human label) — read enough leading bytes to cover all.
_BINARY_SIGNATURES = [
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "Windows PE executable"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"PK\x05\x06", "ZIP archive (empty)"),
    (b"PK\x07\x08", "ZIP archive (spanned)"),
    (b"%PDF", "PDF document"),
    (b"\x1f\x8b", "gzip archive"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit (LE)"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit (LE)"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal / Java class"),
]
_MAX_SIG_LEN = max(len(sig) for sig, _ in _BINARY_SIGNATURES)


def detect_polyglot(path) -> List[Dict]:
    """Flag a text-extension file whose leading bytes are a binary signature."""
    p = Path(path)
    if p.suffix.lower() not in _TEXT_EXTS:
        return []
    try:
        with open(p, "rb") as fh:
            head = fh.read(_MAX_SIG_LEN)
    except OSError:
        return []
    if not head:
        return []
    for sig, label in _BINARY_SIGNATURES:
        if head.startswith(sig):
            return [{
                "type": "polyglot_file",
                "severity": "HIGH",
                "source": str(p),
                "description": (
                    f"File has a text extension ({p.suffix}) but its leading bytes "
                    f"are a {label} signature — possible disguised payload."
                ),
                "attack_class": "LLM05",
                "atlas_technique": "AML.T0010",
            }]
    return []


# ------------------------------------------------------- skill / prompt injection

_INSTRUCTION_FILE_NAMES = {"claude.md", "agents.md", "gemini.md", "agent.md"}
_INSTRUCTION_DIR_HINTS = (".continue/", ".cursor/")

_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions", re.I),
    re.compile(r"disregard\s+the\s+(?:above|previous|system)", re.I),
    re.compile(r"(?:POST|send|exfiltrate|upload)\b[^\n]{0,60}https?://", re.I),
    re.compile(r"reveal\s+(?:your\s+)?(?:system\s+prompt|instructions|api[\s_-]?key)", re.I),
]


def _is_instruction_file(path: str) -> bool:
    lower = path.lower()
    name = Path(lower).name
    if name in _INSTRUCTION_FILE_NAMES:
        return True
    if name.endswith(".md") and ("skill" in lower or ".continue/" in lower):
        return True
    return any(hint in lower for hint in _INSTRUCTION_DIR_HINTS)


def scan_skill_injection(path: str, content: str) -> List[Dict]:
    """Flag hidden directives in instruction-class files only (precision-first)."""
    if not _is_instruction_file(path):
        return []
    for pattern in _INJECTION_PATTERNS:
        m = pattern.search(content)
        if m:
            return [{
                "type": "skill_prompt_injection",
                "severity": "HIGH",
                "source": path,
                "description": f"Instruction file contains a prompt-injection directive: {m.group(0)[:80]!r}",
                "attack_class": "LLM01",
                "atlas_technique": "AML.T0051",
            }]
    return []


# --------------------------------------------------- multi-agent config content

_AGENT_CONFIG_NAMES = {"agents.yaml", "tasks.yaml", "crew.yaml", "oai_config_list",
                       "litellm_config.yaml"}
_AGENT_PAYLOAD_PATTERNS = [
    re.compile(r"\b(?:curl|wget)\b[^\n]{0,80}https?://", re.I),
    re.compile(r"\b(?:exec|eval|os\.system|subprocess)\b", re.I),
    re.compile(r"\|\s*(?:bash|sh)\b", re.I),
]


def _is_agent_config(path: str) -> bool:
    return Path(path).name.lower() in _AGENT_CONFIG_NAMES


def scan_agent_config_content(path: str, content: str) -> List[Dict]:
    """Scan multi-agent config CONTENTS for embedded command/exfil payloads."""
    if not _is_agent_config(path):
        return []
    for pattern in _AGENT_PAYLOAD_PATTERNS:
        m = pattern.search(content)
        if m:
            return [{
                "type": "agent_config_malicious_content",
                "severity": "CRITICAL",
                "source": path,
                "description": f"Multi-agent config contains a suspicious command payload: {m.group(0)[:80]!r}",
                "attack_class": "LLM05",
                "atlas_technique": "AML.TA0015",
            }]
    return []
