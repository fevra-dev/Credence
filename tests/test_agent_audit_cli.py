"""CLI tests for the `agent-audit` command."""

import json

from click.testing import CliRunner

from credence.cli_advanced import cli


def _repo(tmp_path):
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text(
        '{"mcpServers": {"shell": {"command": "bash"}}}')
    return tmp_path


def test_agent_audit_registered():
    # NOTE: CliRunner() with no mix_stderr kwarg (click>=8.2 removed it; the
    # command writes only stdout, so result.output is clean on every click version).
    result = CliRunner().invoke(cli, ["agent-audit", "--help"])
    assert result.exit_code == 0
    assert "agent-audit" in result.output or "Usage" in result.output


def test_agent_audit_json_flags_shell_mcp(tmp_path):
    _repo(tmp_path)
    result = CliRunner().invoke(cli, ["agent-audit", str(tmp_path), "-o", "json"])
    findings = json.loads(result.output)
    assert any(f["type"] == "excessive_agent_capability"
               and f["capability_class"] == "shell_exec" for f in findings)
    assert result.exit_code == 1   # findings => exit 1


def test_agent_audit_clean_dir(tmp_path):
    (tmp_path / "README.md").write_text("# hello")
    result = CliRunner().invoke(cli, ["agent-audit", str(tmp_path)])
    assert result.exit_code == 0
    assert "No agent-exposure" in result.output


def test_agent_audit_console_shows_mappings(tmp_path):
    _repo(tmp_path)
    result = CliRunner().invoke(cli, ["agent-audit", str(tmp_path), "-o", "console"])
    assert "excessive_agent_capability" in result.output
    assert "LLM08" in result.output and "AML.T0053" in result.output and "T1059" in result.output


def test_agent_audit_sarif_output(tmp_path):
    _repo(tmp_path)
    result = CliRunner().invoke(cli, ["agent-audit", str(tmp_path), "-o", "sarif"])
    doc = json.loads(result.output)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "GitExpose"
    assert any(r["ruleId"].startswith("excessive_agent_capability")
               for r in doc["runs"][0]["results"])
    assert result.exit_code == 1   # findings => exit 1


def test_agent_audit_sarif_clean_dir(tmp_path):
    (tmp_path / "README.md").write_text("# hello")
    result = CliRunner().invoke(cli, ["agent-audit", str(tmp_path), "-o", "sarif"])
    doc = json.loads(result.output)
    assert doc["runs"][0]["results"] == []
    assert result.exit_code == 0
