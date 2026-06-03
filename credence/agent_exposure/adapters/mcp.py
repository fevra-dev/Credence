"""MCP server config adapter.

Parses the `mcpServers` object (mcp.json / .cursor/mcp.json / .vscode/mcp.json /
claude_desktop_config.json / .mcp.json). For each server, emits Grants for: the
launch `command` plus its `args` folded into the evidence (reveals arbitrary-exec
wiring + eval flags like `python -c` / `node -e`), and each `env` passthrough key
(reveals secret access). Malformed JSON yields no grants (never crashes).
"""

from __future__ import annotations

import json
from typing import List

from ..models import Grant
from .base import _register

_MCP_BASENAMES = (
    "mcp.json", ".mcp.json", "claude_desktop_config.json",
)


def parse_mcp(content: str, source_file: str) -> List[Grant]:
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        return []
    servers = (data or {}).get("mcpServers") or {}
    if not isinstance(servers, dict):
        return []

    out: List[Grant] = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        command = cfg.get("command")
        if isinstance(command, str) and command:
            # Fold args into the evidence so the engine can see eval flags
            # (`python -c`, `node -e`) — args carry the CODE_EVAL signal.
            args = cfg.get("args")
            arg_str = ""
            if isinstance(args, list):
                arg_str = " " + " ".join(str(a) for a in args)
            out.append(Grant(
                tool=command,
                raw=f'mcpServers.{name}.command="{command}"{arg_str}',
                source_file=source_file,
            ))
        env = cfg.get("env")
        if isinstance(env, dict):
            for key in env:
                out.append(Grant(
                    tool=f"env:{key}",
                    raw=f"mcpServers.{name}.env.{key}",
                    source_file=source_file,
                ))
    return out


for _bn in _MCP_BASENAMES:
    _register(_bn, parse_mcp)
# nested-path basenames the registry resolves by tail (mcp.json) cover
# .cursor/mcp.json and .vscode/mcp.json automatically.
