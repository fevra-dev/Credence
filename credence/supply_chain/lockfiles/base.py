"""Name normalization, PURL building, and the parse_all dispatcher.

normalize_name() makes lookups consistent across lock files and OSV:
  - PyPI: PEP 503 (lowercase, collapse runs of -_. to a single -)
  - npm:  lowercase (names are case-insensitive; scopes preserved)
make_purl() builds a Package URL string for the BOM and OSV cross-reference.
parse_all() walks a directory, dispatches each recognized lock file to its
parser, and returns a de-duplicated Dependency list.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Callable, Dict, List

from packageurl import PackageURL

from ..models import Dependency

logger = logging.getLogger(__name__)

_PEP503_RUN = re.compile(r"[-_.]+")

# Directories never to descend into (mirrors LocalFilesystemScanner).
_SKIP_DIRS = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv"})

# Largest lock file we will read into memory (mirrors LocalFilesystemScanner's
# 1 MB cap) — a pathologically large lock file must not exhaust memory.
_MAX_LOCKFILE_BYTES = 1 * 1024 * 1024


def normalize_name(name: str, ecosystem: str) -> str:
    name = name.strip()
    if ecosystem == "PyPI":
        return _PEP503_RUN.sub("-", name).lower()
    # npm
    return name.lower()


def make_purl(name: str, version: str, ecosystem: str) -> str:
    if ecosystem == "PyPI":
        return PackageURL(type="pypi", name=name, version=version).to_string()
    # npm — split a scoped name "@scope/pkg" into namespace + name
    namespace = None
    pkg = name
    if name.startswith("@") and "/" in name:
        namespace, pkg = name.split("/", 1)
    return PackageURL(type="npm", namespace=namespace, name=pkg, version=version).to_string()


# Filled in by Task 8 once the per-format parsers exist.
# Maps a lock-file basename -> parser callable(content: str, source: str) -> List[Dependency].
_PARSERS: Dict[str, Callable[[str, str], List[Dependency]]] = {}


def _register(basename: str, parser: Callable[[str, str], List[Dependency]]) -> None:
    _PARSERS[basename] = parser


def parse_all(root: Path) -> List[Dependency]:
    """Walk `root`, parse every recognized lock file, return deduped Dependencies.

    Dedup key is (name, version, ecosystem). When the same package appears in
    multiple files, the first occurrence wins but `direct=True` is sticky (a
    package that is direct anywhere is reported direct).
    """
    root = Path(root)
    by_key: Dict[tuple, Dependency] = {}
    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        parser = _PARSERS.get(path.name)
        if parser is None:
            continue
        try:
            if path.stat().st_size > _MAX_LOCKFILE_BYTES:
                logger.warning("Skipping oversized lock file %s (%d bytes > %d cap).",
                               path, path.stat().st_size, _MAX_LOCKFILE_BYTES)
                continue
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            logger.warning("Could not read lock file %s: %s", path, exc)
            continue
        try:
            deps = parser(content, str(path.relative_to(root)))
        except Exception as exc:  # noqa: BLE001 — never let one bad file kill the scan
            logger.warning("Failed to parse %s: %s", path, exc)
            continue
        for dep in deps:
            key = (dep.name, dep.version, dep.ecosystem)
            existing = by_key.get(key)
            if existing is None:
                by_key[key] = dep
            elif dep.direct and not existing.direct:
                by_key[key] = dep
    return list(by_key.values())
