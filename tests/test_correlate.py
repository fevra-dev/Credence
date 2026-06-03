"""Tests for correlating OSV results into vulnerable_dependency findings."""

from credence.supply_chain import Dependency, Vulnerability
from credence.supply_chain.correlate import build_vuln_findings, exploitability_sort_key


def _dep(name="lodash", version="4.17.20", direct=True):
    return Dependency(name=name, version=version, ecosystem="npm",
                      purl=f"pkg:npm/{name}@{version}", direct=direct, source_file="package-lock.json")


def _vuln(severity="HIGH", fixed="4.17.21", known_exploited=False):
    return Vulnerability(vuln_id="GHSA-xxxx", severity=severity, summary="proto pollution",
                         advisory_url="https://osv.dev/vulnerability/GHSA-xxxx",
                         cvss_score=7.5, fixed_version=fixed, aliases=["CVE-2020-8203"],
                         known_exploited=known_exploited)


def test_build_vuln_findings_shape():
    dep = _dep()
    findings = build_vuln_findings({dep.purl: [_vuln()]}, [dep],
                                   unpinned_packages=set(), cred_sources=set())
    f = findings[0]
    assert f["type"] == "vulnerable_dependency"
    assert f["package"] == "lodash"
    assert f["vuln_id"] == "GHSA-xxxx"
    assert f["severity"] == "HIGH"
    assert f["fixed_version"] == "4.17.21"
    assert f["fix_available"] is True
    assert f["direct"] is True
    assert f["attack_class"] == "OWASP A06:2021 Vulnerable & Outdated Components"
    assert f["verification_status"] == "skipped"


def test_cred_co_presence_marks_exploitable_signal():
    dep = _dep()
    findings = build_vuln_findings({dep.purl: [_vuln()]}, [dep],
                                   unpinned_packages=set(),
                                   cred_sources={"package-lock.json"})
    assert findings[0]["cred_co_present"] is True


def test_exploitability_sort_prioritizes_direct_unpinned_over_higher_cvss():
    # transitive CRITICAL (cvss 9.8) vs direct+unpinned+fix HIGH (cvss 7.5)
    high_direct = {"severity": "HIGH", "cvss_score": 7.5, "direct": True,
                   "pinned": False, "fix_available": True, "cred_co_present": False}
    crit_transitive = {"severity": "CRITICAL", "cvss_score": 9.8, "direct": False,
                       "pinned": True, "fix_available": False, "cred_co_present": False}
    ordered = sorted([crit_transitive, high_direct], key=exploitability_sort_key, reverse=True)
    assert ordered[0] is high_direct   # exploitability context beats raw CVSS
