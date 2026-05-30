"""Tests for the MCP config adapter + adapter registry."""

from gitexpose.agent_exposure.adapters.base import adapter_for, ADAPTERS, _register
from gitexpose.agent_exposure.models import Grant


def test_register_and_lookup_by_basename():
    _register("zzz-test.json", lambda c, s: [Grant("t", "r", s)])
    assert adapter_for("nested/dir/zzz-test.json") is not None
    assert adapter_for("unknown.txt") is None
    del ADAPTERS["zzz-test.json"]
