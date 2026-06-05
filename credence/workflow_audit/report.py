"""Human-readable workflow-audit report."""

from __future__ import annotations

from typing import Dict, List

_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _line(f: Dict) -> str:
    fw = f.get("frameworks", {})
    tags = ", ".join(fw.get("cicd_sec", []) + fw.get("mitre", []))
    loc = f["file_path"]
    if f.get("job"):
        loc += f":{f['job']}"
    if f.get("step_index") is not None:
        loc += f"[step {f['step_index']}]"
    parts = [f"  {_ICON.get(f['severity'], '⚪')} [{f['severity']}] {f['rule_id']} "
             f"({f.get('confidence','')}) — {f['title']}",
             f"      {loc}:{f.get('line', 0)}  {tags}",
             f"      {f.get('message','')}"]
    if f.get("source") == "history":
        ident = ", ".join(f.get("identity_flags") or []) or "none"
        flag = "  [persists in history only]" if f.get("persists_in_history_only") else ""
        parts.append(f"      commit {f.get('commit_short','?')} by "
                     f"{f.get('author','?')}  identity: {ident}{flag}")
    if f.get("remediation"):
        parts.append(f"      fix: {f['remediation']}")
    return "\n".join(parts)


def render_report(findings: List[Dict]) -> str:
    if not findings:
        return "No workflow threats detected.\n"
    active = [f for f in findings if not f.get("suppressed")]
    suppressed = [f for f in findings if f.get("suppressed")]
    active.sort(key=lambda f: _ORDER.get(f["severity"], 9))
    lines = ["=" * 72, "WORKFLOW THREAT AUDIT", "=" * 72,
             f"Active findings: {len(active)}   Suppressed: {len(suppressed)}", ""]
    for f in active:
        lines.append(_line(f))
        lines.append("")
    if suppressed:
        lines += ["-" * 72, "Suppressed (visible, not gating):", ""]
        for f in suppressed:
            reason = f.get("suppression_reason") or "no reason given"
            lines.append(_line(f))
            lines.append(f"      suppressed: {reason}")
            lines.append("")
    return "\n".join(lines)
