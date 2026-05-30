"""Tests for the Claude-Code permission-list adapter."""

from gitexpose.agent_exposure.adapters.permissions import parse_permissions


def test_allow_entries_become_grants():
    content = '{"permissions": {"allow": ["Bash(*)", "WebFetch", "Read(./src/**)"], "deny": []}}'
    grants = parse_permissions(content, ".claude/settings.json")
    tools = {g.tool for g in grants}
    assert "Bash(*)" in tools
    assert "WebFetch" in tools


def test_deny_covered_allow_is_dropped():
    # an allow entry exactly matched by a deny entry must NOT produce a grant
    content = '{"permissions": {"allow": ["WebFetch", "Bash(*)"], "deny": ["WebFetch"]}}'
    grants = parse_permissions(content, ".claude/settings.json")
    tools = {g.tool for g in grants}
    assert "WebFetch" not in tools
    assert "Bash(*)" in tools


def test_malformed_returns_empty():
    assert parse_permissions("nope", ".claude/settings.json") == []
