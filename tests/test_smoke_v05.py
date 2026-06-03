"""v0.5 smoke: lock-file SCA + OSV (mocked) + cyclonedx, end to end.

Uses a recorded OSV fixture so the test is deterministic and offline-safe in CI.
The live-network smoke is performed manually before release (see plan Task 14).
"""

import json
from pathlib import Path

import httpx
import respx
from click.testing import CliRunner

from credence.cli_advanced import cli

FIX = Path(__file__).parent / "fixtures" / "synthetic_repo_v05"
QUERYBATCH = "https://api.osv.dev/v1/querybatch"


@respx.mock
def test_smoke_v05_sca_and_bom():
    # requests 2.19.0 has known CVEs; mock OSV to return one deterministically.
    respx.post(QUERYBATCH).mock(return_value=httpx.Response(
        200, json={"results": [{"vulns": [{"id": "GHSA-req0"}]}, {}]}))
    respx.get("https://api.osv.dev/v1/vulns/GHSA-req0").mock(return_value=httpx.Response(
        200, json={"id": "GHSA-req0", "summary": "CRLF in requests",
                   "aliases": ["CVE-2018-18074"], "database_specific": {"severity": "HIGH"},
                   "affected": [{"ranges": [{"type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}]}))
    runner = CliRunner()

    # JSON path → vulnerable_dependency present
    res_json = runner.invoke(cli, ["supply-chain", str(FIX), "-o", "json", "--no-verify-banner"])
    findings = json.loads(res_json.output)
    assert any(f["type"] == "vulnerable_dependency" and f["package"] == "requests"
               for f in findings)

    # BOM path → valid CycloneDX with the component + VEX
    res_bom = runner.invoke(cli, ["supply-chain", str(FIX), "-o", "cyclonedx", "--no-verify-banner"])
    doc = json.loads(res_bom.output)
    assert doc["specVersion"] == "1.6"
    assert any(c["name"] == "requests" for c in doc["components"])


@respx.mock
def test_smoke_v05_offline_no_network():
    route = respx.post(QUERYBATCH)
    runner = CliRunner()
    res = runner.invoke(cli, ["supply-chain", str(FIX), "--offline", "-o", "json"])
    assert not route.called
    assert res.exit_code in (0, 1)
