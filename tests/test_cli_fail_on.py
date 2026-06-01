"""--fail-on severity gating: findings always print; exit code is thresholded."""
from gitexpose.cli_gating import exit_code_for, SEVERITY_ORDER


def test_severity_order_is_total():
    assert SEVERITY_ORDER["CRITICAL"] > SEVERITY_ORDER["HIGH"] > SEVERITY_ORDER["MEDIUM"]
    assert SEVERITY_ORDER["MEDIUM"] > SEVERITY_ORDER["LOW"] > SEVERITY_ORDER["INFO"]


def test_no_findings_is_clean_exit():
    assert exit_code_for([], "high") == 0


def test_high_finding_trips_default_high_gate():
    findings = [{"severity": "HIGH"}]
    assert exit_code_for(findings, "high") == 1


def test_low_finding_does_not_trip_high_gate():
    findings = [{"severity": "LOW"}]
    assert exit_code_for(findings, "high") == 0


def test_low_finding_trips_info_gate():
    findings = [{"severity": "LOW"}]
    assert exit_code_for(findings, "info") == 1


def test_missing_severity_treated_as_info():
    assert exit_code_for([{"type": "x"}], "high") == 0
    assert exit_code_for([{"type": "x"}], "info") == 1


def test_critical_trips_every_gate():
    for floor in ("info", "low", "medium", "high", "critical"):
        assert exit_code_for([{"severity": "CRITICAL"}], floor) == 1


from click.testing import CliRunner
from gitexpose.cli_advanced import cli


def test_agent_audit_default_high_gate_passes_on_low(tmp_path):
    (tmp_path / "README.md").write_text("# nothing sensitive here\n")
    res = CliRunner().invoke(cli, ["agent-audit", str(tmp_path)])
    assert res.exit_code == 0


def test_agent_audit_fail_on_info_is_stricter(tmp_path):
    (tmp_path / "README.md").write_text("# nothing\n")
    res = CliRunner().invoke(cli, ["agent-audit", str(tmp_path), "--fail-on", "info"])
    assert res.exit_code == 0
