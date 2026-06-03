"""v0.7 smoke: agent-audit detects an over-permissioned function-calling tool schema."""

import json
from pathlib import Path

from click.testing import CliRunner

from credence.cli_advanced import cli

FIX = Path(__file__).parent / "fixtures" / "agent_repo_v07"


def test_smoke_v07_function_calling_json():
    result = CliRunner().invoke(cli, ["agent-audit", str(FIX), "-o", "json"])
    findings = json.loads(result.output)
    # run_shell -> shell_exec CRITICAL
    assert any(f.get("capability_class") == "shell_exec" and f["severity"] == "CRITICAL"
               for f in findings)
    # run_shell + http_get in one schema -> exfil-chain escalation
    assert any(f.get("exfil_chain") for f in findings)
    assert result.exit_code == 1


def test_smoke_v07_sarif_valid():
    result = CliRunner().invoke(cli, ["agent-audit", str(FIX), "-o", "sarif"])
    doc = json.loads(result.output)
    assert doc["version"] == "2.1.0"
    assert any(r["ruleId"].startswith("excessive_agent_capability")
               for r in doc["runs"][0]["results"])
