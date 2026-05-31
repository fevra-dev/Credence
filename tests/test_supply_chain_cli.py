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
    # --offline: this test exercises the curated known-bad list, not live OSV.
    result = runner.invoke(cli, ["supply-chain", str(tmp_path), "--offline"])
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
    # --offline: the synthetic_repo has pinned deps; this regression test is about
    # curated/credential rendering, not live OSV lookups.
    result = runner.invoke(cli, ["supply-chain", str(fixture), "--offline"])
    # Must not crash — a real crash raises a non-SystemExit exception
    assert not result.exception or isinstance(result.exception, SystemExit), (
        f"Crashed: {result.exception}"
    )
    assert result.exit_code == 1
    # Verify representative findings render in output
    assert "litellm" in result.output
    assert "groq_api_key" in result.output


def test_supply_chain_renders_severity_for_v01_findings(tmp_path: Path):
    """Regression: v0.1 secret-dicts have severity=None.
    Output must render 'UNKNOWN' (or similar), not the literal '[None]'."""
    # generic_api_key is a v0.1 pattern that emits with severity=None
    (tmp_path / "config.py").write_text(
        'api_key = "abcdefghijklmnopqrstuvwxyz1234567890"\n'
    )
    runner = CliRunner()
    result = runner.invoke(cli, ["supply-chain", str(tmp_path)])
    assert "[None]" not in result.output, f"Severity rendered as literal None: {result.output}"


def test_supply_chain_json_has_no_internal_verify_input(tmp_path):
    from click.testing import CliRunner
    (tmp_path / "creds.env").write_text(
        'aws_access_key_id="AKIAIOSFODNN7EXAMPLE"\n'
        'aws_secret="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
    )
    result = CliRunner().invoke(cli, ["supply-chain", str(tmp_path), "-o", "json"])
    assert "_verify_input" not in result.output


def test_main_cli_accepts_sarif_output_format():
    """`gitexpose scan --help` lists sarif as an output choice."""
    from click.testing import CliRunner

    from gitexpose.cli import scan

    runner = CliRunner()
    result = runner.invoke(scan, ["--help"])
    assert "sarif" in result.output
