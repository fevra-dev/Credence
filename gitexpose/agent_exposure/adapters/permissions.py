"""Claude-Code permission-list adapter.

Parses `.claude/settings.json` / `settings.local.json` `permissions.allow`/`deny`.
Each allow entry becomes a Grant unless it is exactly covered by a deny entry
(deny neutralizes it). The grant's tool token is the raw permission string so
classify() can match it (e.g. "Bash(*)" -> SHELL_EXEC + UNRESTRICTED).
"""

from __future__ import annotations

import json
from typing import List

from ..models import Grant
from .base import _register

_PERM_BASENAMES = ("settings.json", "settings.local.json")


def parse_permissions(content: str, source_file: str) -> List[Grant]:
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        return []
    perms = (data or {}).get("permissions") or {}
    if not isinstance(perms, dict):
        return []
    allow = [a for a in (perms.get("allow") or []) if isinstance(a, str)]
    deny = {d for d in (perms.get("deny") or []) if isinstance(d, str)}

    out: List[Grant] = []
    for entry in allow:
        if entry in deny:
            continue   # deny neutralizes this allow
        out.append(Grant(
            tool=entry,
            raw=f"permissions.allow: {entry}",
            source_file=source_file,
        ))
    return out


for _bn in _PERM_BASENAMES:
    _register(_bn, parse_permissions)
