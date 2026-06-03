"""Tests for the function-calling content adapter + content-adapter registry."""

from credence.agent_exposure.adapters.base import (
    CONTENT_ADAPTERS, _register_content, content_adapters,
)
from credence.agent_exposure.models import Grant


def test_content_adapter_registry_register_and_list():
    marker = lambda c, s: [Grant("t", "r", s)]  # noqa: E731
    _register_content(marker)
    assert marker in content_adapters()
    CONTENT_ADAPTERS.remove(marker)


from credence.agent_exposure.adapters.function_calling import parse_function_calling  # noqa: E402
from credence.agent_exposure.capabilities import classify  # noqa: E402
from credence.agent_exposure.models import CapabilityClass  # noqa: E402


def test_openai_nested_shape():
    content = (
        '{"tools": [{"type": "function", "function": {"name": "run_shell",'
        ' "description": "run a shell command"}}]}'
    )
    grants = parse_function_calling(content, "agent.json")
    assert [g.tool for g in grants] == ["run_shell"]
    assert CapabilityClass.SHELL_EXEC in classify(grants[0])


def test_openai_flattened_shape():
    content = '[{"type": "function", "name": "http_get"}]'
    grants = parse_function_calling(content, "tools.json")
    assert [g.tool for g in grants] == ["http_get"]


def test_anthropic_shape():
    content = '{"tools": [{"name": "query_db", "input_schema": {"type": "object"}}]}'
    grants = parse_function_calling(content, "claude_tools.json")
    assert [g.tool for g in grants] == ["query_db"]


def test_benign_tools_no_dangerous_name():
    content = '{"tools": [{"type": "function", "function": {"name": "get_weather"}}]}'
    grants = parse_function_calling(content, "agent.json")
    assert [g.tool for g in grants] == ["get_weather"]      # emitted...
    assert classify(grants[0]) == set()                      # ...but benign -> no finding


def test_non_tool_json_no_match():
    # package.json-style JSON has no tool-schema shape
    content = '{"name": "my-pkg", "version": "1.0.0", "scripts": {"test": "jest"}}'
    assert parse_function_calling(content, "package.json") == []


def test_description_with_secret_does_not_trigger_secret_access():
    # FP guard: the free-form description is NOT placed in raw, so _SECRET_RE can't fire
    content = (
        '{"tools": [{"type": "function", "function": {"name": "get_weather",'
        ' "description": "needs OPENAI_API_KEY to call the weather API"}}]}'
    )
    grants = parse_function_calling(content, "agent.json")
    assert "API_KEY" not in grants[0].raw
    assert CapabilityClass.SECRET_ACCESS not in classify(grants[0])


def test_yaml_tools_shape():
    content = (
        "tools:\n"
        "  - type: function\n"
        "    function:\n"
        "      name: run_shell\n"
    )
    grants = parse_function_calling(content, "agent.yaml")
    assert [g.tool for g in grants] == ["run_shell"]


def test_malformed_returns_empty():
    assert parse_function_calling("{not json", "x.json") == []
    assert parse_function_calling(": : : not yaml : :", "x.yaml") == []
