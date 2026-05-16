"""End-to-end tests for the `gitexpose supply-chain` CLI subcommand."""

from pathlib import Path

from click.testing import CliRunner

from gitexpose.cli_advanced import cli


def test_supply_chain_command_registered():
    runner = CliRunner()
    result = runner.invoke(cli, ["supply-chain", "--help"])
    assert result.exit_code == 0
    assert "supply-chain" in result.output.lower() or "Usage" in result.output


def test_supply_chain_runs_against_dir(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("litellm==1.82.7\n")
    runner = CliRunner()
    result = runner.invoke(cli, ["supply-chain", str(tmp_path)])
    assert result.exit_code == 1, f"expected findings (exit 1), got {result.exit_code}: {result.output}"
    assert "litellm" in result.output
    assert "known_malicious_package_version" in result.output


def test_supply_chain_clean_dir_yields_no_findings(tmp_path: Path):
    (tmp_path / "README.md").write_text("# Hello world")
    runner = CliRunner()
    result = runner.invoke(cli, ["supply-chain", str(tmp_path)])
    assert result.exit_code == 0
    assert "No supply-chain" in result.output


def test_main_cli_accepts_sarif_output_format():
    """`gitexpose --help` lists sarif as an output choice."""
    from click.testing import CliRunner

    from gitexpose.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert "sarif" in result.output
