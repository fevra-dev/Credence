# credence/workflow_audit/allowlist.py
"""Host allowlists + visible suppression parsing.

Suppression is *visible only* (spec §6, v0.8.1 lesson): a `# credence:ignore
<RULE> reason=...` directive is parsed here, but high/crit exec/exfil/inj rules
ignore it (enforced in Plan 2/3) and suppressed findings are never deleted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Set

# api.github.com is platform-native, but Plan 2's WF-EXFIL-001 still treats a
# POST to a *foreign* repo/gist via api.github.com as exfil (platform-channel abuse).
_PLATFORM_HOSTS = {
    "github.com", "api.github.com", "raw.githubusercontent.com",
    "objects.githubusercontent.com", "codeload.github.com",
    "ghcr.io", "pkg-containers.githubusercontent.com", "uploads.github.com",
}

_INSTALLER_HOSTS = {
    "get.docker.com", "sh.rustup.rs", "deb.nodesource.com", "apt.llvm.org",
    "get.helm.sh", "install.python-poetry.org", "raw.githubusercontent.com",
    "bun.sh", "get.pnpm.io",
}

_SUPPRESS_RE = re.compile(
    r"#\s*credence:ignore\s+(?P<rule>[A-Z]+-[A-Z]+-\d+)"
    r"(?:\s+reason=(?P<reason>.+))?\s*$"
)


def is_platform_host(host: str) -> bool:
    return host.lower().strip() in _PLATFORM_HOSTS


def is_installer_host(host: str, extra_hosts: Optional[Set[str]] = None) -> bool:
    host = host.lower().strip()
    if host in _INSTALLER_HOSTS:
        return True
    return bool(extra_hosts) and host in {h.lower() for h in extra_hosts}


@dataclass(frozen=True)
class Suppression:
    rule_id: str
    line: int
    reason: Optional[str]


def parse_suppressions(text: str) -> List[Suppression]:
    out: List[Suppression] = []
    for i, line in enumerate(text.splitlines(), start=1):
        m = _SUPPRESS_RE.search(line)
        if m:
            reason = m.group("reason")
            out.append(Suppression(
                rule_id=m.group("rule"),
                line=i,
                reason=(reason.strip() if reason else None),
            ))
    return out
