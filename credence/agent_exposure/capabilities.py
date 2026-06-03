"""Dangerous-capability taxonomy: classify a Grant into CapabilityClass(es),
plus the severity and MITRE ATT&CK mappings (verified triple: OWASP LLM08 +
ATLAS AML.T0053 + per-class ATT&CK technique). See spec §4-5.
"""

from __future__ import annotations

import re
from typing import Set

from .models import CapabilityClass, Grant

# capability_class -> GitExpose severity bucket
BASE_SEVERITY = {
    CapabilityClass.SHELL_EXEC: "CRITICAL",
    CapabilityClass.CODE_EVAL: "HIGH",
    CapabilityClass.SECRET_ACCESS: "HIGH",
    CapabilityClass.NETWORK_FETCH: "HIGH",
    CapabilityClass.FILESYSTEM_WRITE: "MEDIUM",
    CapabilityClass.DATABASE: "MEDIUM",
    CapabilityClass.BROWSER_CONTROL: "MEDIUM",
    CapabilityClass.UNRESTRICTED: "CRITICAL",
}

# capability_class -> MITRE ATT&CK technique (spec §4 table)
ATTACK_TECHNIQUE = {
    CapabilityClass.SHELL_EXEC: "T1059",
    CapabilityClass.CODE_EVAL: "T1059.006",
    CapabilityClass.SECRET_ACCESS: "T1552",
    CapabilityClass.NETWORK_FETCH: "T1071.001",
    CapabilityClass.FILESYSTEM_WRITE: "T1105",
    CapabilityClass.DATABASE: "T1213",
    CapabilityClass.BROWSER_CONTROL: "T1185",
    CapabilityClass.UNRESTRICTED: "T1059",   # posture; defaults to exec
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

_SHELL = {"bash", "sh", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh",
          "shell", "terminal", "run_command", "execute_command", "run_shell_command",
          "run_shell", "execute", "exec_code", "run_code", "code_interpreter", "python_exec"}
_NETWORK = {"webfetch", "fetch", "curl", "wget", "http", "https",
            "fetch_url", "browser_fetch", "web_request",
            "http_get", "http_post", "web_search", "browse", "search_web", "url_fetch"}
_FS_WRITE = {"write", "edit", "multiedit", "write_file", "create_file",
             "delete_file", "fs_write", "filesystem", "save_file", "put_file"}
_DB = {"postgres", "postgresql", "mysql", "sqlite", "mongodb", "redis", "database", "sql",
       "query_db", "run_query", "execute_sql"}
_BROWSER = {"playwright", "puppeteer", "browser", "selenium", "chromium"}
_SECRET_NAMES = {"read_secret", "get_secret", "read_env", "get_env",
                 "fetch_secret", "secrets_manager", "vault_read"}

_SECRET_RE = re.compile(r"(_KEY|_TOKEN|_SECRET|PASSWORD|CREDENTIAL|APIKEY|API_KEY)", re.I)
_ENV_FILE_RE = re.compile(r"\.env\b", re.I)
_EVAL_RE = re.compile(r"(?:^|\s)-c\b|(?:^|\s)-e\b|\beval\b|\bexec\(", re.I)
_WILDCARD_RE = re.compile(r"\(\s*\*\s*\)|(?:^|[:=\s])\*(?:$|[\s\"'])")


def classify(grant: Grant) -> Set[CapabilityClass]:
    classes: Set[CapabilityClass] = set()
    tool = grant.tool.strip().lower()
    raw = grant.raw
    base = tool.split("(")[0].strip()   # "bash(*)" -> "bash"

    # Explicit wildcard grant => UNRESTRICTED (low-FP: only literal * / (*))
    if base == "*" or _WILDCARD_RE.search(grant.tool) or _WILDCARD_RE.search(raw):
        classes.add(CapabilityClass.UNRESTRICTED)

    if base in _SHELL:
        classes.add(CapabilityClass.SHELL_EXEC)
    if _EVAL_RE.search(raw):
        classes.add(CapabilityClass.CODE_EVAL)
    if base in _NETWORK:
        classes.add(CapabilityClass.NETWORK_FETCH)
    if base in _FS_WRITE:
        classes.add(CapabilityClass.FILESYSTEM_WRITE)
    if base in _DB:
        classes.add(CapabilityClass.DATABASE)
    if base in _BROWSER:
        classes.add(CapabilityClass.BROWSER_CONTROL)
    if base in _SECRET_NAMES or _SECRET_RE.search(raw) or (_ENV_FILE_RE.search(raw) and "read" in tool):
        classes.add(CapabilityClass.SECRET_ACCESS)

    return classes


def top_class(classes: Set[CapabilityClass]) -> CapabilityClass:
    """The most severe class in the set (ties broken by enum order)."""
    return max(classes, key=lambda c: (SEVERITY_ORDER[BASE_SEVERITY[c]], c.value))
