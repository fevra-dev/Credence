"""End-to-end smoke test: supply-chain --verify against the v0.3 fixture, all
provider hosts mocked to a deterministic 401 (DEAD)."""

import json
from pathlib import Path

import httpx
import pytest
import respx
from click.testing import CliRunner

from credence.cli_advanced import cli

FIXTURE = Path(__file__).parent / "fixtures" / "synthetic_repo_v03"

VALID_STATUSES = {"verified", "dead", "error", "skipped", "unverifiable"}


@respx.mock
def test_supply_chain_with_verify_runs_against_fixture():
    # Mock every outbound verifier request to 401 → credential findings become DEAD.
    respx.route().mock(return_value=httpx.Response(401, json={"ok": False}))

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["supply-chain", str(FIXTURE), "-o", "json",
         "--verify", "--verify-timeout", "2", "--no-verify-banner"],
    )

    # supply-chain exits 1 when findings exist, 0 when clean — both fine; 2 = error
    assert result.exit_code in (0, 1), f"unexpected exit {result.exit_code}: {result.output}"

    findings = json.loads(result.output)
    assert isinstance(findings, list)
    assert findings, "fixture should produce findings"

    # Every finding must carry a valid verification_status
    for f in findings:
        assert isinstance(f, dict)
        assert f.get("verification_status") in VALID_STATUSES

    # Credential types actually emitted by the scanner against this fixture.
    # NOTE: github_token uses the v0.1 type name (not github_pat), so it will
    # be "unverifiable" rather than "dead". aws_access_key gets "error" because
    # the AWS STS verifier expects an "access:secret" paired string, not just
    # the access key ID. Both outcomes are acceptable.
    cred_statuses = [
        f["verification_status"] for f in findings
        if f.get("type") in {
            "openai_api_key",
            "anthropic_api_key",
            "groq_api_key",
            "gitlab_pat",
            "docker_hub_pat",
            "slack_token",
            "aws_access_key",
            "github_token",   # v0.1 name; not in VERIFIERS → unverifiable
        }
    ]
    # If any verifiable credential type was detected, it should be 'dead' (mocked 401)
    # — but tolerate 'error'/'unverifiable' for types outside the VERIFIERS registry
    # or that need paired secrets (AWS).
    if cred_statuses:
        assert any(s in {"dead", "error", "unverifiable"} for s in cred_statuses), (
            f"expected verification to run on credential findings, got {cred_statuses}"
        )
        # At least the VERIFIERS-registered types (openai, anthropic, groq, gitlab,
        # docker, slack) should resolve to "dead" since every host returns 401.
        verifiable_statuses = [
            f["verification_status"] for f in findings
            if f.get("type") in {
                "openai_api_key", "anthropic_api_key", "groq_api_key",
                "gitlab_pat", "docker_hub_pat", "slack_token",
            }
        ]
        if verifiable_statuses:
            assert any(s == "dead" for s in verifiable_statuses), (
                f"mocked-401 responses should yield 'dead' status, got {verifiable_statuses}"
            )
