"""Tests for lock-file name normalization, PURL building, and the parse_all dispatcher."""

from credence.supply_chain.lockfiles.base import normalize_name, make_purl


def test_normalize_pypi_pep503():
    assert normalize_name("Flask_SQLAlchemy", "PyPI") == "flask-sqlalchemy"
    assert normalize_name("ZopE.Interface", "PyPI") == "zope-interface"


def test_normalize_npm_lowercases():
    assert normalize_name("Lodash", "npm") == "lodash"
    assert normalize_name("@Angular/Core", "npm") == "@angular/core"


def test_make_purl_pypi():
    assert make_purl("requests", "2.31.0", "PyPI") == "pkg:pypi/requests@2.31.0"


def test_make_purl_npm_scoped():
    # scoped npm names encode the scope as a PURL namespace
    purl = make_purl("@angular/core", "17.0.0", "npm")
    assert purl == "pkg:npm/%40angular/core@17.0.0"


from pathlib import Path

from credence.supply_chain.lockfiles import parse_all


def test_parse_all_walks_mixed_repo(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"":{},'
        '"node_modules/lodash":{"version":"4.17.21"}}}'
    )
    # ignored: inside a skip-dir
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "requirements.txt").write_text("evil==6.6.6\n")

    deps = parse_all(tmp_path)
    names = {d.name for d in deps}
    assert "requests" in names
    assert "lodash" in names
    assert "evil" not in names   # node_modules is skipped


def test_parse_all_skips_oversized_lockfile(tmp_path: Path):
    # /attack F-004: a pathologically large lock file must be skipped (1 MB cap),
    # mirroring LocalFilesystemScanner — not read into memory.
    body = '{"lockfileVersion":3,"packages":{"":{},"node_modules/x":{"version":"1.0.0"}}}'
    (tmp_path / "package-lock.json").write_text(body + " " * (1024 * 1024 + 16))
    assert parse_all(tmp_path) == []   # oversized → skipped, no parse
