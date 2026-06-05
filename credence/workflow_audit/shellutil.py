# credence/workflow_audit/shellutil.py
"""Shell/network parsing helpers shared by exec & exfil rules. Operate on
normalized run text (Plan 1 normalize.py already applied)."""

from __future__ import annotations

import re
from typing import Dict, List, Set

_DECODERS = (
    "base64 -d", "base64 --decode", "base32 -d", "xxd -r", "xxd -p -r",
    "openssl enc -d", "gunzip", "gzip -d", "uudecode", "gpg -d", "gpg --decrypt",
)
_INTERPRETERS = (
    "python -c", "python3 -c", "node -e", "node --eval", "perl -e", "ruby -e",
    "php -r",
)
_SHELLS = ("bash", "sh", "zsh", "dash")
_HTTP_TOOLS = ("curl", "wget")
_DNS_TOOLS = ("nslookup", "dig", "host")


def _pipes_to_shell(text: str) -> bool:
    return any(re.search(rf"\|\s*{s}\b", text) for s in _SHELLS)


def has_decode_to_shell(run: str) -> bool:
    if not run:
        return False
    low = run.lower()
    if any(d in low for d in _DECODERS):
        if _pipes_to_shell(low):
            return True
        if re.search(r"eval\s+[\"']?\$\(", low):
            return True
        if any(i in low for i in _INTERPRETERS):
            return True
    return False


def remote_pipe_to_shell(run: str):
    """If a curl/wget output is piped to a shell, return its host (or None if dynamic)."""
    low = (run or "").lower()
    if not any(re.search(rf"\b{t}\b", low) for t in _HTTP_TOOLS):
        return None
    if not _pipes_to_shell(low):
        return None
    m = re.search(r"https?://([^\s/\"'|]+)", run)
    return m.group(1) if m else None


def outbound_sinks(run: str) -> List[Dict]:
    """Return outbound network sinks: {tool, host, dynamic, dns}."""
    sinks: List[Dict] = []
    low = (run or "").lower()
    for t in _HTTP_TOOLS:
        if re.search(rf"\b{t}\b", low):
            m = re.search(r"https?://([^\s/\"'|]+)", run)
            if m:
                sinks.append({"tool": t, "host": m.group(1),
                              "dynamic": False, "dns": False})
            elif re.search(rf"\b{t}\b[^\n]*\$\{{?\w+", run):
                sinks.append({"tool": t, "host": None,
                              "dynamic": True, "dns": False})
    for t in _DNS_TOOLS:
        if re.search(rf"\b{t}\b", low):
            sinks.append({"tool": t, "host": None, "dynamic": True, "dns": True})
    if re.search(r"\bnc\b|\bncat\b", low):
        sinks.append({"tool": "nc", "host": None, "dynamic": True, "dns": False})
    return sinks


def references_vars(run: str, var_names: Set[str]) -> bool:
    for v in var_names:
        if re.search(rf"\$\{{?{re.escape(v)}\b", run or ""):
            return True
    return False
