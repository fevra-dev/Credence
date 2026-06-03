"""Tests for v0.2 reporter additions: OWASP/ATLAS field surfacing."""

import json

from credence.models import Category, ScanReport, ScanResult, Severity, TargetReport
from credence.reporters import (
    ConsoleReporter,
    CSVReporter,
    HTMLReporter,
    JSONReporter,
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
    )
    target_report = TargetReport(
        target="https://example.com",
        total_paths_checked=1,
        vulnerable_count=1,
        findings=[finding],
        errors=[],
        scan_duration_ms=100,
    )
    return ScanReport(
        targets_scanned=1,
        targets_vulnerable=1,
        total_findings=1,
        critical_count=1,
        high_count=0,
        medium_count=0,
        low_count=0,
        scan_start="2026-05-08T12:00:00",
        scan_end="2026-05-08T12:00:01",
        scan_duration_ms=100,
        target_reports=[target_report],
    )


def test_json_reporter_includes_attack_class_and_atlas_technique():
    out = JSONReporter().generate(_make_report())
    parsed = json.loads(out)
    finding = parsed["target_reports"][0]["findings"][0]
    assert finding["attack_class"] == "LLM06"
    assert finding["atlas_technique"] == "AML.T0019"


def test_csv_reporter_includes_owasp_atlas_columns():
    out = CSVReporter().generate(_make_report())
    header = out.splitlines()[0]
    assert "attack_class" in header.lower() or "OWASP" in header
    assert "atlas_technique" in header.lower() or "ATLAS" in header
    assert "LLM06" in out
    assert "AML.T0019" in out


def test_console_reporter_renders_owasp_atlas_when_present():
    out = ConsoleReporter(no_color=True).generate(_make_report())
    assert "LLM06" in out
    assert "AML.T0019" in out


def test_html_reporter_renders_owasp_atlas_badges():
    out = HTMLReporter().generate(_make_report())
    assert "LLM06" in out
    assert "AML.T0019" in out
