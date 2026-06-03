"""Tests for SARIF 2.1.0 reporter."""

import json
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

from credence.models import Category, ScanReport, ScanResult, Severity, TargetReport
from credence.reporters.sarif_reporter import SARIFReporter

SCHEMA_PATH = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"


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
        evidence="Found: API_KEY=...",
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


def test_sarif_reporter_validates_against_schema():
    out = SARIFReporter().generate(_make_report())
    parsed = json.loads(out)
    schema = json.loads(SCHEMA_PATH.read_text())
    jsonschema.validate(parsed, schema)


def test_sarif_top_level_version_and_runs():
    out = SARIFReporter().generate(_make_report())
    parsed = json.loads(out)
    assert parsed["version"] == "2.1.0"
    assert "runs" in parsed
    assert len(parsed["runs"]) >= 1


def test_sarif_includes_atlas_taxonomy():
    out = SARIFReporter().generate(_make_report())
    parsed = json.loads(out)
    run = parsed["runs"][0]
    taxonomies = run.get("taxonomies", [])
    names = [t.get("name") for t in taxonomies]
    assert any("ATLAS" in n.upper() for n in names if n)


def test_sarif_result_references_atlas_technique():
    out = SARIFReporter().generate(_make_report())
    parsed = json.loads(out)
    run = parsed["runs"][0]
    assert run["results"]
    result = run["results"][0]
    taxa = result.get("taxa", [])
    assert any("AML.T0019" in str(t) for t in taxa)


def test_sarif_result_includes_severity_level():
    out = SARIFReporter().generate(_make_report())
    parsed = json.loads(out)
    result = parsed["runs"][0]["results"][0]
    assert result["level"] in {"error", "warning", "note", "none"}


def test_sarif_empty_report_still_validates():
    empty = ScanReport(
        targets_scanned=0,
        targets_vulnerable=0,
        total_findings=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        scan_start="2026-05-08T12:00:00",
        scan_end="2026-05-08T12:00:01",
        scan_duration_ms=0,
        target_reports=[],
    )
    out = SARIFReporter().generate(empty)
    parsed = json.loads(out)
    schema = json.loads(SCHEMA_PATH.read_text())
    jsonschema.validate(parsed, schema)
