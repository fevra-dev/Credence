"""Config-adapter protocol + registry.

Each adapter parses ONE agent-config format into a list of Grant objects. The
registry maps a recognizable basename (or basename suffix) to its adapter so the
analyzer can dispatch by filename. Adding a v0.7 format = a new module that calls
_register(); the capability engine is untouched.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

from ..models import Grant

# parser signature: (content: str, source_file: str) -> List[Grant]
Adapter = Callable[[str, str], List[Grant]]

ADAPTERS: Dict[str, Adapter] = {}


def _register(basename: str, adapter: Adapter) -> None:
    ADAPTERS[basename] = adapter


def adapter_for(filename: str) -> Optional[Adapter]:
    """Return the adapter whose registered basename matches the filename's tail."""
    if filename in ADAPTERS:
        return ADAPTERS[filename]
    # match by basename (handles e.g. ".cursor/mcp.json" -> "mcp.json")
    tail = filename.rsplit("/", 1)[-1]
    return ADAPTERS.get(tail)


# --- Content adapters (shape dispatch) -------------------------------------
# Unlike ADAPTERS (filename dispatch), a content adapter is offered the parsed
# text of every .json/.yaml/.yml file and decides for itself whether the content
# matches its shape (returns [] on non-match). Adding a v0.8 framework adapter =
# one new module that calls _register_content().

CONTENT_ADAPTERS: List[Adapter] = []


def _register_content(adapter: Adapter) -> None:
    CONTENT_ADAPTERS.append(adapter)


def content_adapters() -> List[Adapter]:
    return list(CONTENT_ADAPTERS)
