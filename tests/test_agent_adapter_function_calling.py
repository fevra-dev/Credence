"""Tests for the function-calling content adapter + content-adapter registry."""

from gitexpose.agent_exposure.adapters.base import (
    CONTENT_ADAPTERS, _register_content, content_adapters,
)
from gitexpose.agent_exposure.models import Grant


def test_content_adapter_registry_register_and_list():
    marker = lambda c, s: [Grant("t", "r", s)]  # noqa: E731
    _register_content(marker)
    assert marker in content_adapters()
    CONTENT_ADAPTERS.remove(marker)
