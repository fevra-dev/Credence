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

# Tool names that IFS-substitution can split into adjacent fragments
# e.g. cu${IFS}rl → normalize → "cu rl"; compact it back to "curl".
# Derived from EVERY tool the detection cares about so IFS-deobfuscation stays in
# sync with the decoder/shell/dns/http sets (F-001: a hardcoded 7-tool list let
# dig/openssl/sh/gunzip/… evade when IFS-split). The first word of each multi-token
# entry is the binary name. `host` is deliberately excluded — too common as English
# prose ("ho st") to reassemble without false positives; `ho${IFS}st` of the rarely
# used `host` command is an accepted residual (plain `host` is still detected).
def _tool_words() -> tuple:
    words: Set[str] = set()
    for group in (_DECODERS, _INTERPRETERS):
        for entry in group:
            words.add(entry.split()[0])
    words.update(_SHELLS)
    words.update(_HTTP_TOOLS)
    words.update(("nc", "ncat", "eval", "openssl", "dig", "nslookup"))
    return tuple(sorted(words))


_IFS_SPLIT_TOOLS = _tool_words()


def _compact_ifs_tools(text: str) -> str:
    """Collapse IFS-space-split tool fragments back to their full name.

    After normalize_run(), `cu${IFS}rl` becomes `cu rl`. This function
    re-joins any pair of adjacent word-only tokens whose concatenation
    matches a known sensitive tool name, so sink-detection regexes see `curl`
    not `cu rl`.  Operates on a copy; does not mutate normalize_run output.
    """
    for tool in _IFS_SPLIT_TOOLS:
        # Match all splits: (prefix)(single-space)(suffix) where prefix+suffix == tool
        for split_at in range(1, len(tool)):
            prefix, suffix = tool[:split_at], tool[split_at:]
            # word-boundary: prefix at start of word, suffix followed by non-word-char
            pattern = rf"\b{re.escape(prefix)} {re.escape(suffix)}\b"
            text = re.sub(pattern, tool, text)
    return text


def _pipes_to_shell(text: str) -> bool:
    return any(re.search(rf"\|\s*{s}\b", text) for s in _SHELLS)


def has_decode_to_shell(run: str) -> bool:
    if not run:
        return False
    run = _compact_ifs_tools(run)
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
    run = _compact_ifs_tools(run or "")
    low = run.lower()
    if not any(re.search(rf"\b{t}\b", low) for t in _HTTP_TOOLS):
        return None
    if not _pipes_to_shell(low):
        return None
    m = re.search(r"https?://([^\s/\"'|]+)", run)
    return m.group(1) if m else None


def outbound_sinks(run: str) -> List[Dict]:
    """Return outbound network sinks: {tool, host, dynamic, dns}."""
    sinks: List[Dict] = []
    # Compact IFS-split tool names (e.g. "cu rl" → "curl") before matching.
    run = _compact_ifs_tools(run or "")
    low = run.lower()
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
