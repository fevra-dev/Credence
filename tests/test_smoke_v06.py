"""v0.6 smoke: agent-audit over a synthetic over-permissioned repo."""

import json
from pathlib import Path

from click.testing import CliRunner

from gitexpose.cli_advanced import cli

FIX = Path(__file__).parent / "fixtures" / "agent_repo_v06"


def test_smoke_v06_agent_audit():
    result = CliRunner().invoke(cli, ["agent-audit", str(FIX), "-o", "json"])
    findings = json.loads(result.output)
    types = {f["type"] for f in findings}
    assert "excessive_agent_capability" in types
    # the .cursor/mcp.json shell server => CRITICAL shell_exec
    assert any(f["capability_class"] == "shell_exec" and f["severity"] == "CRITICAL"
               for f in findings)
    # Bash(*) + WebFetch in settings.json => an exfil-chain escalation finding
    assert any(f.get("exfil_chain") for f in findings)
    assert result.exit_code == 1
