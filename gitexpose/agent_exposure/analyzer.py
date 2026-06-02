"""Walk a path for agent-config files, route each to its adapter, classify the
grants, and emit excessive_agent_capability findings — plus wildcard escalation
(handled in classify via UNRESTRICTED) and exfil-chain escalation (here).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List

from . import adapters  # noqa: F401 — registers adapters
from .adapters.base import adapter_for, content_adapters
from .capabilities import (
    ATTACK_TECHNIQUE, BASE_SEVERITY, classify, top_class,
)
from .models import CapabilityClass, Grant
from . import mcp_score

logger = logging.getLogger(__name__)

_SKIP_DIRS = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv"})
_MAX_BYTES = 1 * 1024 * 1024
_CONTENT_EXTS = frozenset({".json", ".yaml", ".yml"})
_ATLAS = "AML.T0053"
_OWASP = "OWASP LLM08 Excessive Agency"

_DESC = {
    CapabilityClass.SHELL_EXEC: "grants arbitrary shell/command execution",
    CapabilityClass.CODE_EVAL: "grants arbitrary code evaluation",
    CapabilityClass.SECRET_ACCESS: "grants access to secrets/credentials",
    CapabilityClass.NETWORK_FETCH: "grants arbitrary outbound network access",
    CapabilityClass.FILESYSTEM_WRITE: "grants filesystem write/delete",
    CapabilityClass.DATABASE: "grants database access",
    CapabilityClass.BROWSER_CONTROL: "grants browser automation control",
    CapabilityClass.UNRESTRICTED: "is an unrestricted wildcard grant",
}
_REC = "Scope this grant to the minimum needed, or add an explicit deny; remove if unused."

import json as _json

_MCP_BASENAMES = ("mcp.json", ".mcp.json", "claude_desktop_config.json")


def _maybe_score_mcp(content: str, rel: str, tail: str) -> List[Dict]:
    if tail not in _MCP_BASENAMES:
        return []
    try:
        data = _json.loads(content)
    except (ValueError, TypeError):
        return []
    out: List[Dict] = []
    for server in mcp_score.parse_servers(data, rel):
        out.extend(mcp_score.score_server(server, rel))
    return out


def _finding(grant: Grant, classes) -> Dict:
    top = top_class(classes)
    return {
        "type": "excessive_agent_capability",
        "tool": grant.tool,
        "capability_class": top.value,
        "severity": BASE_SEVERITY[top],
        "source": grant.source_file,
        "evidence": grant.raw,
        "description": f"Agent grant '{grant.tool}' {_DESC[top]}.",
        "recommendation": _REC,
        "attack_class": _OWASP,
        "atlas_technique": _ATLAS,
        "mitre_attack": ATTACK_TECHNIQUE[top],
    }


def analyze_configs(root: Path) -> List[Dict]:
    root = Path(root)
    findings: List[Dict] = []
    # source_file -> set of capability classes seen (for exfil-chain escalation)
    classes_by_source: Dict[str, set] = {}

    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        rel = str(path.relative_to(root))
        tail = path.name

        fn_adapter = adapter_for(rel)
        # permission lists only count under a .claude/ directory (filename dispatch only)
        suppress_fn = (
            fn_adapter is not None
            and tail in ("settings.json", "settings.local.json")
            and ".claude" not in path.parts
        )
        is_content = path.suffix.lower() in _CONTENT_EXTS

        if (fn_adapter is None or suppress_fn) and not is_content:
            continue  # nothing dispatches to this file

        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            content = path.read_text(encoding="utf-8", errors="ignore")
            grants: List[Grant] = []
            if fn_adapter is not None and not suppress_fn:
                grants.extend(fn_adapter(content, rel))
            if is_content:
                for ca in content_adapters():
                    grants.extend(ca(content, rel))
        except Exception as exc:  # noqa: BLE001 — one bad file never aborts the scan
            logger.warning("agent-audit: failed to parse %s (%s)", rel, type(exc).__name__)
            continue

        for grant in grants:
            classes = classify(grant)
            if not classes:
                continue
            findings.append(_finding(grant, classes))
            classes_by_source.setdefault(rel, set()).update(classes)

        # v0.8 — MCP posture scoring (per-server findings + INFO summary)
        findings.extend(_maybe_score_mcp(content, rel, tail))

    findings.extend(_exfil_chain_findings(classes_by_source))
    return findings


def _exfil_chain_findings(classes_by_source: Dict[str, set]) -> List[Dict]:
    out: List[Dict] = []
    exec_classes = {CapabilityClass.SHELL_EXEC, CapabilityClass.CODE_EVAL}
    egress_classes = {CapabilityClass.NETWORK_FETCH, CapabilityClass.SECRET_ACCESS}
    for source, classes in classes_by_source.items():
        if classes & exec_classes and classes & egress_classes:
            chain = sorted(c.value for c in (classes & (exec_classes | egress_classes)))
            out.append({
                "type": "excessive_agent_capability",
                "tool": "(combined)",
                "capability_class": "exfil_capable_agent",
                "severity": "CRITICAL",
                "source": source,
                "evidence": f"{source} grants {' + '.join(chain)}",
                "description": "Agent has both code/command execution and network/secret access — an exfiltration-capable foothold.",
                "recommendation": "Split these capabilities across agents or remove one side of the chain.",
                "attack_class": _OWASP,
                "atlas_technique": _ATLAS,
                "mitre_attack": "T1041",
                "exfil_chain": chain,
                "exfil_attack": "T1041",
            })
    return out
