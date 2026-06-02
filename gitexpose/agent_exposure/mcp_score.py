"""MCP server security posture scoring (0-100).

Decoupled design: per-issue findings carry honest, gating severities; a separate
INFO `mcp_server_posture` summary carries the 0-100 score and its deduction
breakdown. The score informs humans; the per-issue severities gate CI. No other
scanner produces a quantified MCP posture score.
"""
from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urlparse

_OWASP = "OWASP LLM08 Excessive Agency"
_ATLAS = "AML.T0053"

# Minimal seed registry of known-legitimate MCP server origins. Grows over time.
KNOWN_MCP_SERVERS = frozenset({
    "mcp.anthropic.com",
    "mcp.stripe.com",
    "api.github.com",
    "mcp.github.com",
    "huggingface.co",
    "hf.co",
})

_SECRET_VALUE_RE = re.compile(
    r"(sk_live_|sk-|ghp_|glpat-|hf_|AKIA|xox[baprs]-)|"
    r"(_KEY|_TOKEN|_SECRET|PASSWORD|APIKEY)",
    re.IGNORECASE,
)

# Env values that are references/placeholders, not embedded secrets.
_PLACEHOLDER_RE = re.compile(
    r"^\s*(\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|\{\{[^}]+\}\}|<[^>]+>)\s*$"
)


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except (ValueError, UnicodeError):
        return ""


def _issue(ftype: str, severity: str, source: str, server_name: str,
           description: str) -> Dict:
    return {
        "type": ftype,
        "severity": severity,
        "source": source,
        "mcp_server": server_name,
        "description": description,
        "attack_class": _OWASP,
        "atlas_technique": _ATLAS,
        "mitre_attack": "T1552",
    }


def score_server(server: Dict, source: str) -> List[Dict]:
    """Score one parsed MCP server. Returns per-issue findings + INFO summary."""
    name = server.get("name") or "(unnamed)"
    url = server.get("url") or ""
    host = _host(url)
    env = server.get("env") or {}
    auth = (server.get("auth") or "").lower()
    version = server.get("version")

    score = 100
    reasons: List[str] = []
    out: List[Dict] = []

    # Static credential in env (-30, HIGH)
    has_static_cred = any(
        (_SECRET_VALUE_RE.search(str(k)) or _SECRET_VALUE_RE.search(str(v)))
        and not _PLACEHOLDER_RE.match(str(v))
        for k, v in env.items()
    ) and auth != "oauth"
    if has_static_cred:
        score -= 30
        reasons.append("-30 static credential")
        out.append(_issue(
            "mcp_static_credential", "HIGH", source, name,
            f"MCP server '{name}' embeds a static credential in its env block.",
        ))

    # Plaintext HTTP (-20, HIGH)
    if url.startswith("http://"):
        score -= 20
        reasons.append("-20 plaintext http")
        out.append(_issue(
            "mcp_plaintext_http", "HIGH", source, name,
            f"MCP server '{name}' uses plaintext http:// — credentials and traffic "
            "are exposed in transit.",
        ))

    # Unknown origin (-15, LOW)
    if host and host not in KNOWN_MCP_SERVERS:
        score -= 15
        reasons.append("-15 unknown origin")
        out.append(_issue(
            "mcp_unknown_origin", "LOW", source, name,
            f"MCP server '{name}' origin ({host}) is not in the known-good registry.",
        ))

    # No version pin (-5, LOW)
    if not version:
        score -= 5
        reasons.append("-5 no version pin")
        out.append(_issue(
            "mcp_unpinned_version", "LOW", source, name,
            f"MCP server '{name}' has no pinned version — supply-chain drift risk.",
        ))

    # Bonuses (affect score only, never gating)
    if host in KNOWN_MCP_SERVERS:
        score = min(100, score + 20)
        reasons.append("+20 known vendor")
    if auth == "oauth":
        score = min(100, score + 15)
        reasons.append("+15 oauth")

    # defensive clamp; by construction score is already within [0,100]
    score = max(0, min(100, score))
    breakdown = "; ".join(reasons) if reasons else "no deductions"
    out.append({
        "type": "mcp_server_posture",
        "severity": "INFO",
        "source": source,
        "mcp_server": name,
        "score": score,
        "description": f"MCP server '{name}' posture score {score}/100 ({breakdown}).",
        "attack_class": _OWASP,
        "atlas_technique": _ATLAS,
        "mitre_attack": "T1552",
    })
    return out


def parse_servers(data: Dict) -> List[Dict]:
    """Normalise an mcpServers object into a list of server dicts for scoring."""
    servers = (data or {}).get("mcpServers") or {}
    if not isinstance(servers, dict):
        return []
    out: List[Dict] = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        out.append({
            "name": name,
            "url": cfg.get("url") or cfg.get("serverUrl") or "",
            "version": cfg.get("version"),
            "auth": cfg.get("auth") or cfg.get("type") or "",
            "env": cfg.get("env") if isinstance(cfg.get("env"), dict) else {},
        })
    return out
