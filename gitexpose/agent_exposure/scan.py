"""Top-level agent-exposure scan: capability analysis + system-prompt fingerprinting.

Returns a merged, severity-sorted list of finding-dicts (UNRESTRICTED / exfil-chain
surface first).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List

from .analyzer import analyze_configs, _SKIP_DIRS, _MAX_BYTES
from .capabilities import SEVERITY_ORDER
from .system_prompt import load_fingerprints, match_text
from . import debug_print

logger = logging.getLogger(__name__)

# Extensions worth checking for leaked-prompt text.
_TEXT_EXT = frozenset({".txt", ".md", ".mkd", ".mdx", ".json", ".yaml", ".yml",
                       ".py", ".js", ".ts", ".tsx", ".prompt"})


def _load_default_fingerprints() -> List[Dict]:
    return load_fingerprints()


def _scan_system_prompts(root: Path, fingerprints: List[Dict]) -> List[Dict]:
    if not fingerprints:
        return []
    out: List[Dict] = []
    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file() or path.suffix.lower() not in _TEXT_EXT:
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        out.extend(match_text(text, str(path.relative_to(root)), fingerprints))
    return out


def _sort_key(f: Dict) -> tuple:
    return (
        1 if f.get("exfil_chain") else 0,
        1 if f.get("capability_class") == "unrestricted" else 0,
        SEVERITY_ORDER.get((f.get("severity") or "INFO").upper(), 0),
    )


def scan(path) -> List[Dict]:
    root = Path(path)
    findings: List[Dict] = []
    findings.extend(analyze_configs(root))
    findings.extend(debug_print.scan(root))
    findings.extend(_scan_system_prompts(root, _load_default_fingerprints()))
    findings.sort(key=_sort_key, reverse=True)
    return findings
