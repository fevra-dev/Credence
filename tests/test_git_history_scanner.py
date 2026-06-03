"""Integration tests for scan_history against a real temp git repo."""

import subprocess
from pathlib import Path

import pytest

from credence.git_history.scanner import scan_history


def _run(cmd, cwd):
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)


def _git_repo_with_removed_secret(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _run(["git", "init", "-q"], repo)
    _run(["git", "config", "user.email", "t@t.t"], repo)
    _run(["git", "config", "user.name", "Tester"], repo)
    (repo / "config.py").write_text("OPENAI_API_KEY=sk-" + "a" * 30 + "\n")
    _run(["git", "add", "."], repo)
    _run(["git", "commit", "-q", "-m", "add config"], repo)
    (repo / "config.py").write_text("# cleaned up\n")
    _run(["git", "add", "."], repo)
    _run(["git", "commit", "-q", "-m", "remove secret"], repo)
    return repo


def test_finds_secret_that_was_removed(tmp_path):
    repo = _git_repo_with_removed_secret(tmp_path)
    findings = scan_history(repo)
    types = {f["type"] for f in findings}
    assert "openai_api_key" in types
    f = next(f for f in findings if f["type"] == "openai_api_key")
    assert f["source"] == "config.py"
    assert len(f["commit"]) == 40
    assert f["commit_short"] == f["commit"][:7]
    assert f["author"] == "Tester"
    assert f["commit_date"]
    assert f["verification_status"] == "skipped"


def test_dedups_secret_surviving_multiple_commits(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _run(["git", "init", "-q"], repo)
    _run(["git", "config", "user.email", "t@t.t"], repo)
    _run(["git", "config", "user.name", "Tester"], repo)
    secret_line = "GROQ_API_KEY=gsk_" + "c" * 52 + "\n"
    (repo / "a.txt").write_text(secret_line)
    _run(["git", "add", "."], repo)
    _run(["git", "commit", "-q", "-m", "c1"], repo)
    (repo / "b.txt").write_text(secret_line)
    _run(["git", "add", "."], repo)
    _run(["git", "commit", "-q", "-m", "c2"], repo)
    findings = scan_history(repo)
    groq = [f for f in findings if f["type"] == "groq_api_key"]
    assert len(groq) == 1
    assert groq[0]["source"] == "a.txt"


def test_non_git_path_raises(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(ValueError, match="not a git repository"):
        scan_history(plain)


def test_clean_history_returns_empty(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _run(["git", "init", "-q"], repo)
    _run(["git", "config", "user.email", "t@t.t"], repo)
    _run(["git", "config", "user.name", "Tester"], repo)
    (repo / "readme.md").write_text("# nothing secret here\n")
    _run(["git", "add", "."], repo)
    _run(["git", "commit", "-q", "-m", "init"], repo)
    assert scan_history(repo) == []
