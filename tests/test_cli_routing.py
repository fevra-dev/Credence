"""Routing + command-resolution tests for the unified `gitexpose` CLI (v0.6.1)."""

import gitexpose
from click.testing import CliRunner

from gitexpose.cli_advanced import cli


def test_full_audit_command_registered():
    # the advanced multi-module aggregator now lives under `full-audit`
    assert "full-audit" in cli.commands


def test_version_option_matches_package():
    # the group's --version must reflect the real package version, not a stale literal
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert gitexpose.__version__ in result.output


from gitexpose.cli import _route_argv  # noqa: E402


def _known():
    return set(cli.commands)


def test_bare_target_routes_to_scan():
    assert _route_argv(["example.com"], _known()) == ["scan", "example.com"]


def test_bare_target_with_options_routes_to_scan():
    assert _route_argv(["example.com", "-o", "sarif"], _known()) == \
        ["scan", "example.com", "-o", "sarif"]


def test_leading_option_routes_to_scan():
    # the tricky case: a leading flag still means "web scan"
    assert _route_argv(["-f", "targets.txt"], _known()) == ["scan", "-f", "targets.txt"]


def test_explicit_scan_unchanged():
    assert _route_argv(["scan", "example.com"], _known()) == ["scan", "example.com"]


def test_subcommands_unchanged():
    for cmd in ("supply-chain", "git-history", "agent-audit", "full-audit"):
        assert _route_argv([cmd, "."], _known()) == [cmd, "."]


def test_version_and_help_passthrough():
    assert _route_argv(["--version"], _known()) == ["--version"]
    assert _route_argv(["--help"], _known()) == ["--help"]
    assert _route_argv(["-h"], _known()) == ["-h"]


def test_no_args_unchanged():
    assert _route_argv([], _known()) == []


def test_group_exposes_scan_and_subcommands():
    names = set(cli.commands)
    assert {"scan", "full-audit", "supply-chain", "git-history", "agent-audit"} <= names


def test_scan_subcommand_is_web_scanner_with_sarif():
    # SARIF is unique to the mature web scanner (cli.py) — proves `scan` is the right one
    result = CliRunner().invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "sarif" in result.output
