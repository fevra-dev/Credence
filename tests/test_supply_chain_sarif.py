"""supply-chain --output sarif emits valid SARIF carrying orphan-signal fingerprints."""
import json

from click.testing import CliRunner

from credence.cli_advanced import cli


def test_supply_chain_sarif_output(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.py").write_text('aws_access_key = "AKIA' + "A" * 16 + '"\n')
    res = CliRunner().invoke(
        cli, ["supply-chain", str(repo), "--output", "sarif", "--offline"]
    )
    # exit code may be 0/1 depending on the severity gate; output must be valid SARIF.
    doc = json.loads(res.stdout)
    assert doc["version"] == "2.1.0"
    assert "runs" in doc


def test_supply_chain_sarif_has_runs_and_tool(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text('github_token = "ghp_' + "b" * 36 + '"\n')
    res = CliRunner().invoke(
        cli, ["supply-chain", str(repo), "--output", "sarif", "--offline", "--track",
              "--registry", str(tmp_path / "r.json")]
    )
    doc = json.loads(res.stdout)
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Credence"
    # the tracked secret should carry a partial fingerprint
    fps = [r.get("partialFingerprints", {}) for r in run["results"]]
    assert any("secretValueHash/v1" in fp for fp in fps)
