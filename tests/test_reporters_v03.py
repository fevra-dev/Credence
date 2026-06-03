"""Tests for v0.3 reporter additions: verification status surfacing."""

import json

from credence.models import Category, ScanReport, ScanResult, Severity, TargetReport
from credence.reporters import (
    ConsoleReporter,
    CSVReporter,
    HTMLReporter,
    JSONReporter,
    SARIFReporter,
)


def _make_report() -> ScanReport:
    finding = ScanResult(
        url="https://example.com/.env",
        path=".env",
        target="https://example.com",
        status_code=200,
        vulnerable=True,
        severity=Severity.CRITICAL,
        category=Category.ENV,
        description="Environment file exposed",
        evidence="Found: API_KEY=…",
        attack_class="LLM06",
        atlas_technique="AML.T0019",
        verification_status="verified",
        verification_detail="200",
    )
    return ScanReport(
        targets_scanned=1, targets_vulnerable=1, total_findings=1,
        critical_count=1, high_count=0, medium_count=0, low_count=0,
        scan_start="2026-05-27T12:00:00", scan_end="2026-05-27T12:00:01",
        scan_duration_ms=100,
        target_reports=[TargetReport(
            target="https://example.com", total_paths_checked=1, vulnerable_count=1,
            findings=[finding], errors=[], scan_duration_ms=100,
        )],
    )


def test_json_reporter_emits_verification_status():
    out = JSONReporter().generate(_make_report())
    parsed = json.loads(out)
    finding = parsed["target_reports"][0]["findings"][0]
    assert finding["verification_status"] == "verified"
    assert finding["verification_detail"] == "200"


def test_sarif_reporter_includes_verification_property_and_tag():
    out = SARIFReporter().generate(_make_report())
    parsed = json.loads(out)
    result = parsed["runs"][0]["results"][0]
    assert result["properties"]["verification_status"] == "verified"
    assert "verified-live" in result.get("properties", {}).get("tags", [])


def test_html_reporter_renders_verified_badge():
    out = HTMLReporter().generate(_make_report())
    assert "badge-verified" in out or "LIVE" in out
    assert "verified" in out.lower()


def test_html_reporter_no_badge_for_skipped():
    report = _make_report()
    report.target_reports[0].findings[0].verification_status = "skipped"
    out = HTMLReporter().generate(report)
    assert "badge-verified" not in out
    assert "badge-dead" not in out


def test_csv_reporter_has_verification_columns():
    out = CSVReporter().generate(_make_report())
    header = out.splitlines()[0]
    assert "verification_status" in header.lower()
    assert "verification_detail" in header.lower()
    assert "verified" in out


def test_console_reporter_renders_verification_tag():
    out = ConsoleReporter(no_color=True).generate(_make_report())
    assert "[VERIFIED]" in out or "VERIFIED" in out


def test_console_reporter_no_tag_for_skipped():
    report = _make_report()
    report.target_reports[0].findings[0].verification_status = "skipped"
    out = ConsoleReporter(no_color=True).generate(report)
    assert "[VERIFIED]" not in out
    assert "[DEAD]" not in out
