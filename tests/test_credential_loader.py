"""Tests for credential pattern loader."""

import re

import pytest

from credence.data.loader import (
    CredentialPattern,
    PatternLoadError,
    load_credential_patterns,
)


def test_loads_at_least_sixteen_patterns():
    patterns = load_credential_patterns()
    assert len(patterns) >= 16


def test_each_pattern_has_required_fields():
    patterns = load_credential_patterns()
    for p in patterns:
        assert isinstance(p, CredentialPattern)
        assert p.name
        assert p.regex
        assert p.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert p.attack_class.startswith("LLM")
        assert p.atlas_technique.startswith("AML.")


def test_each_regex_compiles():
    patterns = load_credential_patterns()
    for p in patterns:
        re.compile(p.regex)


def test_known_pattern_present():
    patterns = load_credential_patterns()
    names = {p.name for p in patterns}
    assert "groq_api_key" in names
    assert "anthropic_api_key" in names
    assert "huggingface_token" in names


def test_groq_regex_matches_realistic_key():
    patterns = {p.name: p for p in load_credential_patterns()}
    groq = patterns["groq_api_key"]
    realistic = "gsk_" + "a" * 52
    assert re.search(groq.regex, realistic)
    assert not re.search(groq.regex, "gsk_was_a_thing")


def test_loader_raises_on_missing_file(monkeypatch, tmp_path):
    """If the JSON file is missing, loader raises PatternLoadError."""
    bogus = tmp_path / "nonexistent.json"
    with pytest.raises(PatternLoadError):
        load_credential_patterns(path=bogus)


def test_loader_raises_on_malformed_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(PatternLoadError, match="Malformed"):
        load_credential_patterns(path=bad)


def test_loader_raises_on_missing_patterns_key(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema_version": "1.0"}', encoding="utf-8")
    with pytest.raises(PatternLoadError, match="patterns"):
        load_credential_patterns(path=bad)


def test_loader_raises_on_missing_required_field(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"patterns": [{"name": "x", "regex": "y"}]}', encoding="utf-8")
    with pytest.raises(PatternLoadError, match="missing required field"):
        load_credential_patterns(path=bad)


def test_loader_raises_on_invalid_regex(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(
        '{"patterns": [{"name": "broken", "regex": "sk-[a-zA-Z0-9{20,}", '
        '"severity": "HIGH", "attack_class": "LLM06", "atlas_technique": "AML.T0019", '
        '"category": "test", "description": "broken regex"}]}',
        encoding="utf-8",
    )
    with pytest.raises(PatternLoadError, match="invalid regex"):
        load_credential_patterns(path=bad)
