"""Loader for credential pattern JSON corpus."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


class PatternLoadError(ImportError):
    """Raised when the credential pattern corpus cannot be loaded."""


@dataclass(frozen=True)
class CredentialPattern:
    name: str
    regex: str
    severity: str
    attack_class: str
    atlas_technique: str
    category: str
    description: str


_DEFAULT_PATH = Path(__file__).parent / "credential_patterns_v02.json"

_REQUIRED_FIELDS = (
    "name",
    "regex",
    "severity",
    "attack_class",
    "atlas_technique",
    "category",
    "description",
)


def load_credential_patterns(path: Optional[Path] = None) -> List[CredentialPattern]:
    """Load credential patterns from JSON.

    Raises PatternLoadError if the file is missing, malformed, or fails schema
    validation. The loader is invoked at import time by SecretExtractor; a
    broken corpus must fail loudly.
    """
    target = path or _DEFAULT_PATH
    try:
        raw = target.read_text(encoding="utf-8")
    except OSError as exc:
        raise PatternLoadError(f"Cannot read credential patterns at {target}: {exc}") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PatternLoadError(f"Malformed credential patterns JSON: {exc}") from exc

    if not isinstance(data, dict) or "patterns" not in data:
        raise PatternLoadError("Credential patterns JSON missing top-level 'patterns' key")

    patterns: List[CredentialPattern] = []
    for entry in data["patterns"]:
        for field in _REQUIRED_FIELDS:
            if field not in entry:
                raise PatternLoadError(f"Pattern entry missing required field '{field}': {entry}")
        try:
            re.compile(entry["regex"])
        except re.error as exc:
            raise PatternLoadError(
                f"Pattern '{entry['name']}' has invalid regex {entry['regex']!r}: {exc}"
            ) from exc
        patterns.append(
            CredentialPattern(
                name=entry["name"],
                regex=entry["regex"],
                severity=entry["severity"],
                attack_class=entry["attack_class"],
                atlas_technique=entry["atlas_technique"],
                category=entry["category"],
                description=entry["description"],
            )
        )

    return patterns
