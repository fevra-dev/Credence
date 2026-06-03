"""Tests for --verify CLI integration on the supply-chain command."""

import json

from click.testing import CliRunner

from credence.cli_advanced import cli


def test_supply_chain_help_shows_verify_flags():
    result = CliRunner().invoke(cli, ["supply-chain", "--help"])
    assert result.exit_code == 0
    assert "--verify" in result.output
    assert "--verify-concurrency" in result.output
    assert "--verify-timeout" in result.output
    assert "--no-verify-banner" in result.output


def test_supply_chain_without_verify_marks_findings_skipped(tmp_path):
    # Plant an OpenAI key (sk- + 30 alphanumeric chars matches openai_api_key pattern)
    target = tmp_path / "secret.env"
    target.write_text("OPENAI_API_KEY=sk-" + "a" * 30 + "\n")

    result = CliRunner().invoke(cli, ["supply-chain", str(tmp_path), "-o", "json"])
    # supply-chain exits 1 when findings exist, 0 when clean — both are fine here
    assert result.exit_code in (0, 1)
    # Output must be valid JSON
    findings = json.loads(result.output)
    # Every finding dict must carry verification_status == "skipped"
    statuses = [
        f["verification_status"]
        for f in findings
        if isinstance(f, dict) and "verification_status" in f
    ]
    assert statuses, "expected at least one finding with verification_status"
    assert all(s == "skipped" for s in statuses), (
        f"unexpected statuses: {set(statuses)}"
    )


def test_supply_chain_console_shows_verification_when_verified(tmp_path, monkeypatch):
    """With --verify, console output should surface a verification tag.
    We monkeypatch verify_secrets to mark findings verified without network."""
    import credence.verification.engine as engine_mod

    target = tmp_path / "creds.env"
    target.write_text("GROQ_API_KEY=gsk_" + "a" * 52 + "\n")

    async def fake_verify(secrets, **kwargs):
        for s in secrets:
            if s.get("type") == "groq_api_key":
                s["verification_status"] = "verified"
                s["verification_detail"] = "200"
        return secrets

    # The command does `from credence.verification import verify_secrets` inside
    # the function body, which triggers __getattr__ and returns engine.verify_secrets.
    # Patching the engine module directly ensures the fake is returned by __getattr__.
    monkeypatch.setattr(engine_mod, "verify_secrets", fake_verify)

    result = CliRunner().invoke(
        cli,
        ["supply-chain", str(tmp_path), "--verify", "--no-verify-banner"],
    )
    assert result.exit_code in (0, 1)
    assert "VERIFIED" in result.output
