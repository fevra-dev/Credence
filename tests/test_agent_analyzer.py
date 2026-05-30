"""Tests for the agent-exposure analyzer (grants -> findings + escalation)."""

from pathlib import Path

from gitexpose.agent_exposure.analyzer import analyze_configs


def _write(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


def test_shell_mcp_produces_critical_finding(tmp_path):
    _write(tmp_path, ".cursor/mcp.json",
           '{"mcpServers": {"shell": {"command": "bash"}}}')
    findings = analyze_configs(tmp_path)
    f = [x for x in findings if x["type"] == "excessive_agent_capability"]
    assert f and f[0]["severity"] == "CRITICAL"
    assert f[0]["capability_class"] == "shell_exec"
    assert f[0]["mitre_attack"] == "T1059"
    assert f[0]["atlas_technique"] == "AML.T0053"
    assert f[0]["attack_class"] == "OWASP LLM08 Excessive Agency"


def test_benign_mcp_no_finding(tmp_path):
    _write(tmp_path, "mcp.json",
           '{"mcpServers": {"docs": {"command": "npx", "args": ["@acme/docs-mcp"]}}}')
    assert analyze_configs(tmp_path) == []


def test_exfil_chain_escalation(tmp_path):
    # shell + network in the same config => an extra exfil-chain CRITICAL finding
    _write(tmp_path, ".claude/settings.json",
           '{"permissions": {"allow": ["Bash(*)", "WebFetch"], "deny": []}}')
    findings = analyze_configs(tmp_path)
    chained = [x for x in findings if x.get("exfil_chain")]
    assert chained
    assert chained[0]["severity"] == "CRITICAL"
    assert chained[0]["exfil_attack"] == "T1041"
    assert set(chained[0]["exfil_chain"]) >= {"shell_exec", "network_fetch"}


def test_unrelated_settings_json_not_parsed(tmp_path):
    # a settings.json NOT under .claude/ must be ignored by the permissions adapter
    _write(tmp_path, "config/settings.json",
           '{"permissions": {"allow": ["Bash(*)"]}}')
    assert analyze_configs(tmp_path) == []
