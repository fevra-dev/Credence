"""Tests for Python lock-file parsers."""

from pathlib import Path

from credence.supply_chain import Dependency, Vulnerability
from credence.supply_chain.lockfiles.python import (
    parse_requirements, parse_poetry_lock, parse_pipfile_lock,
)

FIX = Path(__file__).parent / "fixtures" / "lockfiles"


def test_models_importable():
    d = Dependency(name="requests", version="2.31.0", ecosystem="PyPI",
                   purl="pkg:pypi/requests@2.31.0", direct=True, source_file="requirements.txt")
    assert d.name == "requests"
    v = Vulnerability(vuln_id="CVE-0000-0000", severity="HIGH", summary="x",
                      advisory_url="https://osv.dev/vulnerability/CVE-0000-0000")
    assert v.severity == "HIGH"


def test_parse_requirements_pins_only():
    content = "requests==2.31.0\nflask>=2.0  # unpinned, ignored for SCA\nurllib3==2.0.7\n"
    deps = parse_requirements(content, "requirements.txt")
    by_name = {d.name: d for d in deps}
    assert by_name["requests"].version == "2.31.0"
    assert by_name["requests"].ecosystem == "PyPI"
    assert by_name["requests"].direct is True
    assert by_name["requests"].purl == "pkg:pypi/requests@2.31.0"
    # only hard pins (==) produce a versioned Dependency for OSV lookup
    assert "flask" not in by_name


def test_parse_poetry_lock_normalizes_names():
    deps = parse_poetry_lock((FIX / "poetry.lock").read_text(), "poetry.lock")
    by_name = {d.name: d for d in deps}
    assert by_name["requests"].version == "2.31.0"
    assert by_name["flask-sqlalchemy"].version == "3.0.5"   # PEP 503 normalized
    assert all(d.ecosystem == "PyPI" for d in deps)


def test_parse_pipfile_lock_default_and_develop():
    deps = parse_pipfile_lock((FIX / "Pipfile.lock").read_text(), "Pipfile.lock")
    by_name = {d.name: d for d in deps}
    assert by_name["requests"].version == "2.31.0"
    assert by_name["pytest"].version == "7.4.0"     # develop deps included
    assert by_name["requests"].integrity_hash == "sha256:aaa"
