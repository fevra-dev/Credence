"""Tests for Python lock-file parsers."""

from gitexpose.supply_chain import Dependency, Vulnerability


def test_models_importable():
    d = Dependency(name="requests", version="2.31.0", ecosystem="PyPI",
                   purl="pkg:pypi/requests@2.31.0", direct=True, source_file="requirements.txt")
    assert d.name == "requests"
    v = Vulnerability(vuln_id="CVE-0000-0000", severity="HIGH", summary="x",
                      advisory_url="https://osv.dev/vulnerability/CVE-0000-0000")
    assert v.severity == "HIGH"
