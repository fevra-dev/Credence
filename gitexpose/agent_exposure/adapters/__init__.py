"""Agent-config adapters. Importing the package registers every adapter."""

from . import base  # noqa: F401
from . import mcp  # noqa: F401  (registers mcp.json family)

from .base import ADAPTERS, adapter_for

__all__ = ["ADAPTERS", "adapter_for"]
