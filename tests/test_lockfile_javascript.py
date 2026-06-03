"""Tests for JavaScript lock-file parsers."""

from pathlib import Path

from credence.supply_chain.lockfiles.javascript import (
    parse_package_lock, parse_yarn_lock,
)

FIX = Path(__file__).parent / "fixtures" / "lockfiles"


def test_parse_package_lock_v3():
    deps = parse_package_lock((FIX / "package-lock.json").read_text(), "package-lock.json")
    by_name = {d.name: d for d in deps}
    assert by_name["lodash"].version == "4.17.21"
    assert by_name["lodash"].ecosystem == "npm"
    assert by_name["lodash"].integrity_hash == "sha512-AAAA"
    assert by_name["lodash"].resolved_url.endswith("lodash-4.17.21.tgz")
    assert by_name["@angular/core"].version == "17.0.0"
    assert by_name["@angular/core"].purl == "pkg:npm/%40angular/core@17.0.0"


def test_parse_yarn_lock_v1():
    deps = parse_yarn_lock((FIX / "yarn.lock").read_text(), "yarn.lock")
    by_name = {d.name: d for d in deps}
    assert by_name["lodash"].version == "4.17.21"
    assert by_name["lodash"].integrity_hash == "sha512-CCCC"
    assert by_name["@angular/core"].version == "17.0.0"
