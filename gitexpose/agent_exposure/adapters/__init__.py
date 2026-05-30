"""Agent-config adapters. Importing the package registers every adapter."""

from . import base  # noqa: F401

from .base import ADAPTERS, adapter_for

__all__ = ["ADAPTERS", "adapter_for"]
