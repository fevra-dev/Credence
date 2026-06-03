"""CLI tests for the git-history subcommand."""

import json
import subprocess
from pathlib import Path

import httpx
import respx
from click.testing import CliRunner

from credence.cli_advanced import cli


def _run(cmd, cwd):
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)


def _repo_with_removed_secret(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _run(["git", "init", "-q"], repo)
    _run(["git", "config", "user.email", "t@t.t"], repo)
    _run(["git", "config", "user.name", "Tester"], repo)
    (repo / "config.py").write_text("OPENAI_API_KEY=sk-" + "a" * 30 + "\n")
    _run(["git", "add", "."], repo)
    _run(["git", "commit", "-q", "-m", "add"], repo)
    (repo / "config.py").write_text("# cleaned\n")
    _run(["git", "add", "."], repo)
    _run(["git", "commit", "-q", "-m", "rm"], repo)
    return repo


def test_help_shows_flags():
    result = CliRunner().invoke(cli, ["git-history", "--help"])
    assert result.exit_code == 0
    for flag in ("--since", "--max-commits", "--verify", "--no-verify-banner"):
        assert flag in result.output


def test_json_output_includes_commit_metadata(tmp_path):
    repo = _repo_with_removed_secret(tmp_path)
    result = CliRunner().invoke(cli, ["git-history", str(repo), "-o", "json"])
    assert result.exit_code in (0, 1)
    findings = json.loads(result.output)
    assert findings, "expected a historical finding"
    f = next(f for f in findings if f["type"] == "openai_api_key")
    assert f["commit_short"]
    assert f["author"] == "Tester"
    assert f["source"] == "config.py"
    assert f["verification_status"] == "skipped"


def test_non_git_path_errors(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    result = CliRunner().invoke(cli, ["git-history", str(plain)])
    assert result.exit_code == 2
    assert "not a git repository" in result.output.lower()


@respx.mock
def test_verify_composes(tmp_path):
    respx.route().mock(return_value=httpx.Response(401))
    repo = _repo_with_removed_secret(tmp_path)
    result = CliRunner().invoke(
        cli, ["git-history", str(repo), "-o", "json", "--verify", "--no-verify-banner", "--verify-timeout", "2"]
    )
    assert result.exit_code in (0, 1)
    findings = json.loads(result.output)
    f = next(f for f in findings if f["type"] == "openai_api_key")
    assert f["verification_status"] in ("dead", "error")


def test_json_output_has_no_internal_verify_input(tmp_path):
    repo = _repo_with_removed_secret(tmp_path)
    result = CliRunner().invoke(cli, ["git-history", str(repo), "-o", "json"])
    assert "_verify_input" not in result.output
