"""Detect committed/leaked system prompts by matching against CL4R1T4S known-leak
fingerprints. Fingerprints are sets of blake2b-hashed word-shingles — we never
vendor prompt text (license/privacy clean) and tolerate light edits via overlap.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Dict, List, Set

_DEFAULT_PATH = Path(__file__).parent / "data" / "cl4r1t4s_fingerprints.json"
_WORD_RE = re.compile(r"\S+")
_ATLAS = "AML.T0056"
_OWASP = "OWASP LLM07 System Prompt Leakage"


def build_shingles(text: str, k: int = 8) -> Set[str]:
    words = _WORD_RE.findall(text.lower())
    out: Set[str] = set()
    for i in range(len(words) - k + 1):
        shingle = " ".join(words[i:i + k])
        out.add(hashlib.blake2b(shingle.encode("utf-8"), digest_size=8).hexdigest())
    return out


def load_fingerprints(path: Path = _DEFAULT_PATH) -> List[Dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("fingerprints", [])
    except (OSError, ValueError):
        return []


def match_text(text: str, source_file: str, fingerprints: List[Dict]) -> List[Dict]:
    out: List[Dict] = []
    # cache shingles per k to avoid recompute
    by_k: Dict[int, Set[str]] = {}
    for fp in fingerprints:
        k = int(fp.get("shingle_k", 8))
        text_sh = by_k.setdefault(k, build_shingles(text, k))
        leak_sh = set(fp.get("shingles", []))
        overlap = len(text_sh & leak_sh)
        if overlap >= int(fp.get("min_match", 5)):
            out.append({
                "type": "exposed_system_prompt",
                "product": fp.get("product", "unknown"),
                "severity": "HIGH",
                "source": source_file,
                "match_strength": f"{overlap}/{len(leak_sh)} shingles",
                "evidence": fp.get("source_url", ""),
                "description": (
                    f"Matches the known-leaked system prompt of {fp.get('product','unknown')} "
                    "(CL4R1T4S corpus) — exposing its guardrails and granted tool permissions."
                ),
                "recommendation": (
                    "If this is your product's prompt, treat it as leaked (rotate embedded "
                    "secrets/tools, assume guardrails are known). If a copied third-party prompt, remove it."
                ),
                "attack_class": _OWASP,
                "atlas_technique": _ATLAS,
                "mitre_attack": "T1552.001",
            })
    return out
