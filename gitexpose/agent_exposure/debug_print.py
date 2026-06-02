"""AST detector for credential-bearing debug prints in agent/skill/tool Python.

Walks Python files, finds print()/logging.<level>() calls whose arguments
reference a variable whose NAME looks like a credential (api_key, token,
secret, bearer, password, client_secret, access_key, ...). String literals that
merely mention those words do NOT fire — only NAME/ATTRIBUTE references and the
embedded expressions of f-strings count. One bad file never aborts the scan.

Backed by arXiv:2604.03070 (73.5% of agent-skill credential leaks are stdout
broadcasts). Finding type: agent_skill_credential_print (HIGH, OWASP LLM06 /
ATLAS AML.T0019).
"""
from __future__ import annotations

import ast
import logging
import re
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)

_SKIP_DIRS = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv"})
_MAX_BYTES = 1 * 1024 * 1024

_CRED_NAME_RE = re.compile(
    r"(api[_-]?key|apikey|access[_-]?key|secret|client[_-]?secret|"
    r"token|bearer|password|passwd|credential|private[_-]?key)",
    re.IGNORECASE,
)

_LOGGING_LEVELS = frozenset({"debug", "info", "warning", "warn", "error",
                             "critical", "exception", "log"})


def _is_print_or_logging(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Name) and func.id == "print":
        return True
    if isinstance(func, ast.Attribute) and func.attr in _LOGGING_LEVELS:
        return True
    return False


def _names_in(node: ast.AST):
    """Yield identifier strings for Name/Attribute references inside an arg,
    including the embedded expressions of an f-string (JoinedStr)."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            yield sub.id
        elif isinstance(sub, ast.Attribute):
            yield sub.attr


def _credential_ref_in_call(call: ast.Call) -> bool:
    for arg in call.args:
        for ident in _names_in(arg):
            if _CRED_NAME_RE.search(ident):
                return True
    return False


def _scan_source(text: str, source: str) -> List[Dict]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    out: List[Dict] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_print_or_logging(node) \
                and _credential_ref_in_call(node):
            out.append({
                "type": "agent_skill_credential_print",
                "severity": "HIGH",
                "source": source,
                "line": getattr(node, "lineno", 1),
                "description": (
                    "Debug print/log broadcasts a credential-named variable to "
                    "stdout/logs — leaks the secret into the agent's context window "
                    "and log sinks on every invocation."
                ),
                "attack_class": "LLM06",
                "atlas_technique": "AML.T0019",
            })
    return out


def scan(root) -> List[Dict]:
    root = Path(root)
    out: List[Dict] = []
    for path in root.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        try:
            out.extend(_scan_source(text, str(path.relative_to(root))))
        except Exception as exc:  # noqa: BLE001 — one bad file never aborts
            logger.debug("debug_print: failed on %s: %s", path, exc)
    return out
