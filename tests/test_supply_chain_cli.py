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


def test_supply_chain_handles_findings_with_no_description(tmp_path: Path):
    """Regression: SecretExtractor findings don't carry a description field.
    The console renderer was crashing with IndexError on ''.splitlines()[0]."""
    # Plant a secret that SecretExtractor will find but that has no description field
    (tmp_path / "config.py").write_text(
        "GROQ_API_KEY = 'gsk_" + "a" * 52 + "'\n"
    )
    runner = CliRunner()
    result = runner.invoke(cli, ["supply-chain", str(tmp_path)])
    # Must not crash — a real crash raises a non-SystemExit exception
    assert not result.exception or isinstance(result.exception, SystemExit), (
        f"Crashed: {result.exception}"
    )
    assert result.exit_code == 1, f"Expected findings (exit 1): {result.output}"
    assert "groq_api_key" in result.output


def test_supply_chain_handles_synthetic_repo_e2e():
    """Regression: scanning the synthetic_repo fixture must not crash.
    This is the manual-verification-equivalent test."""
    fixture = Path(__file__).parent / "fixtures" / "synthetic_repo"
    runner = CliRunner()
    result = runner.invoke(cli, ["supply-chain", str(fixture)])
    # Must not crash — a real crash raises a non-SystemExit exception
    assert not result.exception or isinstance(result.exception, SystemExit), (
        f"Crashed: {result.exception}"
    )
    assert result.exit_code == 1
    # Verify representative findings render in output
    assert "litellm" in result.output
    assert "groq_api_key" in result.output


def test_main_cli_accepts_sarif_output_format():
    """`gitexpose --help` lists sarif as an output choice."""
    from click.testing import CliRunner

    from gitexpose.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert "sarif" in result.output
