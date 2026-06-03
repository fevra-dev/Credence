"""JavaScript lock-file parsers: package-lock.json (v2/v3) and yarn.lock (v1 + Berry).

package-lock.json v2/v3 puts resolved packages under the `packages` object keyed
by install path ("node_modules/<name>" or nested). yarn.lock v1 is a custom
text format; Berry (v2+) is YAML-ish but regular enough to parse with the same
line scanner for the fields we need (version / resolved / integrity).
"""

from __future__ import annotations

import json
import re
from typing import List, Optional

from ..models import Dependency
from .base import make_purl, normalize_name, _register

_ECO = "npm"

_NM_PREFIX = "node_modules/"


def _dep(name: str, version: str, source: str, *, direct: bool,
         integrity: Optional[str], resolved: Optional[str]) -> Dependency:
    norm = normalize_name(name, _ECO)
    return Dependency(
        name=norm, version=version, ecosystem=_ECO,
        purl=make_purl(norm, version, _ECO), direct=direct,
        source_file=source, integrity_hash=integrity, resolved_url=resolved,
    )


def parse_package_lock(content: str, source: str = "package-lock.json") -> List[Dependency]:
    data = json.loads(content)
    out: List[Dependency] = []

    # Direct deps are declared on the root package ("" key) in v2/v3.
    root = (data.get("packages") or {}).get("", {})
    direct_names = set()
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        direct_names.update((root.get(field) or {}).keys())

    packages = data.get("packages")
    if packages:  # v2/v3
        for path, meta in packages.items():
            if not path or "version" not in meta:
                continue
            # The package name is the path segment after the LAST node_modules/.
            name = path.rsplit(_NM_PREFIX, 1)[-1]
            out.append(_dep(
                name, meta["version"], source,
                direct=name in direct_names,
                integrity=meta.get("integrity"),
                resolved=meta.get("resolved"),
            ))
        return out

    # v1 fallback: flat `dependencies` map keyed by name.
    for name, meta in (data.get("dependencies") or {}).items():
        if "version" not in meta:
            continue
        out.append(_dep(
            name, meta["version"], source, direct=name in direct_names,
            integrity=meta.get("integrity"), resolved=meta.get("resolved"),
        ))
    return out


# A yarn.lock entry header is one or more comma-separated "spec" strings ending
# in ":", e.g.  lodash@^4.17.21:   or   "@angular/core@^17.0.0", "@angular/core@17":
_YARN_VERSION = re.compile(r'^\s+version[ :]+"?([^"\s]+)"?', re.MULTILINE)


def parse_yarn_lock(content: str, source: str = "yarn.lock") -> List[Dependency]:
    out: List[Dependency] = []
    # Split into blocks separated by blank lines; each block is one package entry.
    block: List[str] = []
    blocks: List[List[str]] = []
    for line in content.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            if block:
                blocks.append(block)
                block = []
            continue
        block.append(line)
    if block:
        blocks.append(block)

    for blk in blocks:
        header = blk[0]
        if header.startswith(" ") or not header.rstrip().endswith(":"):
            continue
        name = _yarn_name_from_header(header)
        if not name:
            continue
        body = "\n".join(blk[1:])
        vmatch = _YARN_VERSION.search("\n" + body)
        if not vmatch:
            continue
        version = vmatch.group(1)
        integrity = _yarn_field(body, "integrity")
        resolved = _yarn_field(body, "resolved")
        out.append(_dep(name, version, source, direct=True,
                        integrity=integrity, resolved=resolved))
    return out


def _yarn_name_from_header(header: str) -> str:
    """Extract the package name from a yarn entry header line.

    The header is a comma-separated list of "<name>@<range>" specs, optionally
    quoted, ending with ":". We take the first spec and strip the @range. Scoped
    names start with "@", so we split on the LAST "@".
    """
    first_spec = header.rstrip(":").split(",")[0].strip().strip('"')
    at = first_spec.rfind("@")
    if at <= 0:  # no range, or "@" only at index 0 (malformed)
        return first_spec
    return first_spec[:at]


def _yarn_field(body: str, field: str) -> Optional[str]:
    m = re.search(rf'^\s+{field}[ :]+"?([^"\s]+)"?', body, re.MULTILINE)
    return m.group(1) if m else None


_register("package-lock.json", parse_package_lock)
_register("yarn.lock", parse_yarn_lock)
