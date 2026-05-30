"""Data models for the AI-agent-exposure subsystem.

A Grant is one normalized tool/capability grant extracted from an agent config by
an adapter. CapabilityClass is the dangerous-capability taxonomy the engine maps
grants onto.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CapabilityClass(str, Enum):
    SHELL_EXEC = "shell_exec"
    CODE_EVAL = "code_eval"
    SECRET_ACCESS = "secret_access"
    NETWORK_FETCH = "network_fetch"
    FILESYSTEM_WRITE = "filesystem_write"
    DATABASE = "database"
    BROWSER_CONTROL = "browser_control"
    UNRESTRICTED = "unrestricted"


@dataclass(frozen=True)
class Grant:
    tool: str          # normalized tool/capability token, e.g. "bash", "WebFetch"
    raw: str           # literal config evidence, e.g. 'mcpServers.shell.command="bash"'
    source_file: str   # path relative to scan root
