"""Tests for the CycloneDX 1.6 AI-BOM reporter."""

import json

from credence.supply_chain import Dependency
from credence.reporters.cyclonedx_reporter import build_bom


def _dep(name="lodash", version="4.17.20"):
    return Dependency(name=name, version=version, ecosystem="npm",
                      purl=f"pkg:npm/{name}@{version}", direct=True,
                      source_file="package-lock.json", integrity_hash="sha512-AAAA")


def test_build_bom_is_valid_cyclonedx_json():
    deps = [_dep()]
    findings = [{
        "type": "vulnerable_dependency", "package": "lodash", "version": "4.17.20",
        "purl": "pkg:npm/lodash@4.17.20", "vuln_id": "GHSA-xxxx", "severity": "HIGH",
        "cvss_score": 7.5, "summary": "proto pollution",
        "advisory_url": "https://osv.dev/vulnerability/GHSA-xxxx",
        "cred_co_present": False, "direct": True, "pinned": False,
    }]
    out = build_bom(deps, findings)
    doc = json.loads(out)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    # NTIA minimum elements
    assert doc["metadata"]["timestamp"]
    assert doc["metadata"]["tools"]
    names = {c["name"] for c in doc["components"]}
    assert "lodash" in names
    # VEX entry present, honestly scoped to in_triage by default
    vex = doc["vulnerabilities"][0]
    assert vex["id"] == "GHSA-xxxx"
    assert vex["analysis"]["state"] == "in_triage"


def test_vex_state_exploitable_only_on_verified_cred_copresence():
    deps = [_dep()]
    # cred_verified_co_present is the CLI's post-verify signal: a live credential
    # shares this dependency's source file. That is the only thing (besides a KEV
    # flag) that lets VEX claim "exploitable".
    findings = [{
        "type": "vulnerable_dependency", "package": "lodash", "version": "4.17.20",
        "purl": "pkg:npm/lodash@4.17.20", "vuln_id": "GHSA-xxxx", "severity": "HIGH",
        "summary": "x", "advisory_url": "https://osv.dev/vulnerability/GHSA-xxxx",
        "cred_co_present": True, "direct": True, "pinned": False, "known_exploited": False,
        "cred_verified_co_present": True,
    }]
    doc = json.loads(build_bom(deps, findings))
    assert doc["vulnerabilities"][0]["analysis"]["state"] == "exploitable"


def test_vex_state_in_triage_without_verified_cred():
    deps = [_dep()]
    # cred co-present but NOT verified live → still only a hypothesis → in_triage.
    findings = [{
        "type": "vulnerable_dependency", "package": "lodash", "version": "4.17.20",
        "purl": "pkg:npm/lodash@4.17.20", "vuln_id": "GHSA-xxxx", "severity": "HIGH",
        "summary": "x", "advisory_url": "https://osv.dev/vulnerability/GHSA-xxxx",
        "cred_co_present": True, "direct": True, "pinned": False, "known_exploited": False,
    }]
    doc = json.loads(build_bom(deps, findings))
    assert doc["vulnerabilities"][0]["analysis"]["state"] == "in_triage"
