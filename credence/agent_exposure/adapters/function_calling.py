"""Function-calling tool-schema content adapter.

Shape-sniffs OpenAI/Anthropic `tools[]` arrays in JSON/YAML and emits one Grant per
tool, keyed on the tool NAME (never the free-form description — so classify()'s
secret/eval regexes cannot fire on prose). A content adapter: offered every
.json/.yaml/.yml file by the analyzer; returns [] when the file is not a tool
schema (the precise-shape gate keeps false positives low).
"""

from __future__ import annotations

import json
from typing import List, Optional

from ..models import Grant
from .base import _register_content

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a declared dep; degrade if absent
    yaml = None


def _load(content: str):
    """Parse as JSON (stdlib) then YAML (if available). Return obj or None."""
    try:
        return json.loads(content)
    except ValueError:
        pass
    if yaml is not None:
        try:
            return yaml.safe_load(content)
        except Exception:  # noqa: BLE001 — any YAML parse error -> not a tool schema
            return None
    return None


def _candidate_arrays(obj):
    """Yield lists that might be tool arrays: a top-level list, or lists under the
    'tools'/'functions' keys (one level deep)."""
    if isinstance(obj, list):
        yield obj
    if isinstance(obj, dict):
        for key in ("tools", "functions"):
            val = obj.get(key)
            if isinstance(val, list):
                yield val


def _tool_name(item) -> Optional[str]:
    """Return the tool name iff the item matches an exact OpenAI/Anthropic shape."""
    if not isinstance(item, dict):
        return None
    # OpenAI nested: {"type":"function","function":{"name":N}}
    if item.get("type") == "function" and isinstance(item.get("function"), dict):
        name = item["function"].get("name")
        if isinstance(name, str) and name:
            return name
    # OpenAI flattened: {"type":"function","name":N}
    if item.get("type") == "function" and isinstance(item.get("name"), str) and item["name"]:
        return item["name"]
    # Anthropic: {"name":N,"input_schema":{...}}
    if isinstance(item.get("name"), str) and item["name"] and isinstance(item.get("input_schema"), dict):
        return item["name"]
    return None


def parse_function_calling(content: str, source_file: str) -> List[Grant]:
    obj = _load(content)
    if obj is None:
        return []
    out: List[Grant] = []
    for arr in _candidate_arrays(obj):
        names = [n for n in (_tool_name(it) for it in arr) if n]
        if not names:
            continue  # not a tool schema -> skip (FP guard)
        for name in names:
            out.append(Grant(
                tool=name,
                raw=f'tools[].name="{name}"',  # structured evidence ONLY (no description)
                source_file=source_file,
            ))
    return out


_register_content(parse_function_calling)
