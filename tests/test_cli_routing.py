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
