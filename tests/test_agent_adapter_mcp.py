"""Tests for the MCP config adapter + adapter registry."""

from gitexpose.agent_exposure.adapters.base import adapter_for, ADAPTERS, _register
from gitexpose.agent_exposure.models import Grant


def test_register_and_lookup_by_basename():
    _register("zzz-test.json", lambda c, s: [Grant("t", "r", s)])
    assert adapter_for("nested/dir/zzz-test.json") is not None
    assert adapter_for("unknown.txt") is None
    del ADAPTERS["zzz-test.json"]


from gitexpose.agent_exposure.adapters.mcp import parse_mcp  # noqa: E402


def test_mcp_shell_command_grant():
    content = (
        '{"mcpServers": {"shell": {"command": "bash", "args": ["-c"]},'
        ' "docs": {"command": "npx", "args": ["@acme/docs-mcp"]}}}'
    )
    grants = parse_mcp(content, ".cursor/mcp.json")
    tools = {g.tool for g in grants}
    assert "bash" in tools                 # the shell server's command
    # the docs server's command (npx) is emitted but classify() finds it benign
    assert any("npx" in g.tool for g in grants)


def test_mcp_env_secret_passthrough():
    content = '{"mcpServers": {"x": {"command": "node", "env": {"OPENAI_API_KEY": "sk-x"}}}}'
    grants = parse_mcp(content, "mcp.json")
    assert any("OPENAI_API_KEY" in g.raw for g in grants)


def test_mcp_command_args_captured_for_eval_detection():
    # `python -c` / `node -e` wired via args must reach classify() as CODE_EVAL —
    # the adapter folds args into the Grant.raw so _EVAL_RE can see them.
    content = '{"mcpServers": {"py": {"command": "python", "args": ["-c", "import os"]}}}'
    grants = parse_mcp(content, "mcp.json")
    assert any("-c" in g.raw for g in grants)
    from gitexpose.agent_exposure.capabilities import classify
    from gitexpose.agent_exposure.models import CapabilityClass
    assert any(CapabilityClass.CODE_EVAL in classify(g) for g in grants)


def test_mcp_malformed_json_returns_empty():
    assert parse_mcp("{not json", "mcp.json") == []


def test_registry_has_both_families():
    import gitexpose.agent_exposure.adapters  # noqa: F401
    from gitexpose.agent_exposure.adapters.base import ADAPTERS
    assert "mcp.json" in ADAPTERS
    assert "settings.json" in ADAPTERS
