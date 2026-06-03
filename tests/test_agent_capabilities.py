"""Tests for the agent-exposure capability taxonomy."""

from credence.agent_exposure import CapabilityClass, Grant


def test_models_importable():
    g = Grant(tool="bash", raw='command="bash"', source_file="mcp.json")
    assert g.tool == "bash"
    assert CapabilityClass.SHELL_EXEC.value == "shell_exec"


from credence.agent_exposure.capabilities import (  # noqa: E402
    classify, BASE_SEVERITY, ATTACK_TECHNIQUE,
)


def _g(tool, raw=""):
    return Grant(tool=tool, raw=raw or tool, source_file="x")


def test_classify_shell():
    assert CapabilityClass.SHELL_EXEC in classify(_g("bash", 'command="bash"'))


def test_classify_wildcard_is_unrestricted():
    cl = classify(_g("Bash(*)", "permissions.allow: Bash(*)"))
    assert CapabilityClass.UNRESTRICTED in cl
    assert CapabilityClass.SHELL_EXEC in cl


def test_classify_network_and_fs():
    assert CapabilityClass.NETWORK_FETCH in classify(_g("WebFetch"))
    assert CapabilityClass.FILESYSTEM_WRITE in classify(_g("Write"))


def test_classify_secret_from_env_passthrough():
    assert CapabilityClass.SECRET_ACCESS in classify(
        _g("env:OPENAI_API_KEY", "mcpServers.x.env.OPENAI_API_KEY")
    )


def test_classify_benign_returns_empty():
    assert classify(_g("docs-server", "npx @acme/docs-mcp")) == set()


def test_mappings_present_for_every_class():
    for c in CapabilityClass:
        assert c in BASE_SEVERITY
        assert c in ATTACK_TECHNIQUE


def test_attack_technique_values():
    assert ATTACK_TECHNIQUE[CapabilityClass.SHELL_EXEC] == "T1059"
    assert ATTACK_TECHNIQUE[CapabilityClass.SECRET_ACCESS] == "T1552"
    assert ATTACK_TECHNIQUE[CapabilityClass.NETWORK_FETCH] == "T1071.001"


def test_classify_function_tool_names():
    # function-calling tool names map to the taxonomy by NAME
    assert CapabilityClass.SHELL_EXEC in classify(_g("run_shell", 'tools[].name="run_shell"'))
    assert CapabilityClass.CODE_EVAL not in classify(_g("run_shell", 'tools[].name="run_shell"'))
    assert CapabilityClass.NETWORK_FETCH in classify(_g("http_get", 'tools[].name="http_get"'))
    assert CapabilityClass.DATABASE in classify(_g("query_db", 'tools[].name="query_db"'))
    assert CapabilityClass.SECRET_ACCESS in classify(_g("read_secret", 'tools[].name="read_secret"'))


def test_classify_exec_code_tool_is_shell_exec():
    assert CapabilityClass.SHELL_EXEC in classify(_g("exec_code", 'tools[].name="exec_code"'))


def test_classify_benign_function_tool_empty():
    assert classify(_g("get_weather", 'tools[].name="get_weather"')) == set()
    assert classify(_g("calculator", 'tools[].name="calculator"')) == set()
