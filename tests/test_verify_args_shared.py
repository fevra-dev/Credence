"""The --verify* options must be a reusable decorator, applied to supply-chain
(and, in Task 5, git-history)."""

from click.testing import CliRunner

from gitexpose.cli_advanced import cli, add_verify_args


def test_add_verify_args_is_callable_decorator():
    assert callable(add_verify_args)


def test_supply_chain_still_has_all_verify_flags():
    result = CliRunner().invoke(cli, ["supply-chain", "--help"])
    assert result.exit_code == 0
    for flag in ("--verify", "--verify-concurrency", "--verify-timeout",
                 "--verify-only-severity", "--no-verify-banner"):
        assert flag in result.output
