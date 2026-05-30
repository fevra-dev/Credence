"""Tests for the agent-exposure capability taxonomy."""

from gitexpose.agent_exposure import CapabilityClass, Grant


def test_models_importable():
    g = Grant(tool="bash", raw='command="bash"', source_file="mcp.json")
    assert g.tool == "bash"
    assert CapabilityClass.SHELL_EXEC.value == "shell_exec"
