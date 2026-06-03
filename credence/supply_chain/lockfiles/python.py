"""Python lock-file parsers: requirements.txt, poetry.lock, Pipfile.lock.

requirements.txt: only hard pins (==) yield a versioned Dependency (a range is
not a resolved version, so it can't be queried against OSV by exact version).
poetry.lock / Pipfile.lock: fully resolved, so every entry is captured.
"""

from __future__ import annotations

import json
import re
import sys
from typing import List, Optional

from ..models import Dependency
from .base import make_purl, normalize_name, _register

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.9/3.10
    import tomli as tomllib

_ECO = "PyPI"

# requirements line: name[extras]==version  (we only keep == pins)
_REQ_PIN = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*(?P<version>[^\s;#]+)"
)


def _dep(name: str, version: str, source: str, *, direct: bool,
         integrity_hash: Optional[str] = None) -> Dependency:
    norm = normalize_name(name, _ECO)
    return Dependency(
        name=norm, version=version, ecosystem=_ECO,
        purl=make_purl(norm, version, _ECO), direct=direct,
        source_file=source, integrity_hash=integrity_hash,
    )


def parse_requirements(content: str, source: str = "requirements.txt") -> List[Dependency]:
    out: List[Dependency] = []
    for line in content.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped or stripped.startswith("-"):
            continue
        m = _REQ_PIN.match(stripped)
        if not m:
            continue
        out.append(_dep(m.group("name"), m.group("version"), source, direct=True))
    return out


def parse_poetry_lock(content: str, source: str = "poetry.lock") -> List[Dependency]:
    data = tomllib.loads(content)
    out: List[Dependency] = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if not name or not version:
            continue
        # poetry.lock does not mark direct vs transitive; treat all as non-direct
        # except we cannot know — default False (conservative for exploitability).
        out.append(_dep(name, version, source, direct=False))
    return out


def parse_pipfile_lock(content: str, source: str = "Pipfile.lock") -> List[Dependency]:
    data = json.loads(content)
    out: List[Dependency] = []
    for section, direct in (("default", True), ("develop", True)):
        for name, meta in (data.get(section) or {}).items():
            version_spec = (meta or {}).get("version", "")
            version = version_spec.lstrip("=") if version_spec else ""
            if not version:
                continue
            hashes = (meta or {}).get("hashes") or []
            integrity = hashes[0] if hashes else None
            out.append(_dep(name, version, source, direct=direct, integrity_hash=integrity))
    return out


_register("requirements.txt", parse_requirements)
_register("requirements-dev.txt", parse_requirements)
_register("poetry.lock", parse_poetry_lock)
_register("Pipfile.lock", parse_pipfile_lock)
