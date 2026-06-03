"""CLI tests for v0.5 supply-chain SCA (lock-file + OSV + cyclonedx)."""

import json
from pathlib import Path

import httpx
import respx
from click.testing import CliRunner

from credence.cli_advanced import cli

QUERYBATCH = "https://api.osv.dev/v1/querybatch"
VULN = "https://api.osv.dev/v1/vulns/GHSA-xxxx"


def _write_repo(tmp_path: Path):
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"^4.17.20"}},'
        '"node_modules/lodash":{"version":"4.17.20",'
        '"resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",'
        '"integrity":"sha512-AAAA"}}}'
    )
    return tmp_path


def _mock_osv():
    respx.post(QUERYBATCH).mock(return_value=httpx.Response(
        200, json={"results": [{"vulns": [{"id": "GHSA-xxxx"}]}]}))
    respx.get(VULN).mock(return_value=httpx.Response(200, json={
        "id": "GHSA-xxxx", "summary": "proto pollution",
        "aliases": ["CVE-2020-8203"], "database_specific": {"severity": "HIGH"},
        "affected": [{"ranges": [{"type": "ECOSYSTEM",
                     "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
    }))


@respx.mock
def test_offline_skips_osv(tmp_path):
    _write_repo(tmp_path)
    route = respx.post(QUERYBATCH)
    runner = CliRunner()
    result = runner.invoke(cli, ["supply-chain", str(tmp_path), "--offline", "-o", "json"])
    assert not route.called   # --offline made no network call
    # exit 0/1 both fine depending on other findings; just assert it ran
    assert result.exit_code in (0, 1)


@respx.mock
def test_osv_default_on_emits_vulnerable_dependency(tmp_path):
    _write_repo(tmp_path)
    _mock_osv()
    runner = CliRunner()
    # --no-verify-banner suppresses the stderr OSV egress notice so parsed stdout
    # stays clean across click versions (click>=8.2 dropped CliRunner(mix_stderr=)).
    result = runner.invoke(cli, ["supply-chain", str(tmp_path), "-o", "json", "--no-verify-banner"])
    findings = json.loads(result.output)
    vuln = [f for f in findings if f["type"] == "vulnerable_dependency"]
    assert vuln and vuln[0]["vuln_id"] == "GHSA-xxxx"
    assert vuln[0]["severity"] == "HIGH"


@respx.mock
def test_cyclonedx_output(tmp_path):
    _write_repo(tmp_path)
    _mock_osv()
    runner = CliRunner()
    result = runner.invoke(cli, ["supply-chain", str(tmp_path), "-o", "cyclonedx", "--no-verify-banner"])
    doc = json.loads(result.output)
    assert doc["bomFormat"] == "CycloneDX"
    assert any(c["name"] == "lodash" for c in doc["components"])
    assert doc["vulnerabilities"][0]["id"] == "GHSA-xxxx"


@respx.mock
def test_console_renders_vulnerable_dependency(tmp_path):
    _write_repo(tmp_path)
    _mock_osv()
    runner = CliRunner()
    result = runner.invoke(cli, ["supply-chain", str(tmp_path), "-o", "console", "--no-verify-banner"])
    assert "vulnerable_dependency" in result.output or "GHSA-xxxx" in result.output
    assert "lodash" in result.output
    assert "4.17.21" in result.output   # fixed version surfaced
    assert "OWASP OWASP" not in result.output   # no double-prefix
