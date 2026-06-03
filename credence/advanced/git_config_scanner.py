# credence/advanced/git_config_scanner.py
"""Structural git-metadata credential scanner.

Parses .git/config and .gitmodules with configparser ONLY — never invokes git
(CVE-2025-41390: a malicious core.fsmonitor in .git/config yields RCE when any
tool runs a git subprocess in the directory). Emits finding-dicts in the shared
shape so reporters and the cluster post-processor handle them uniformly.

Finding types:
  - git_config_credential_url         token in [remote] url=          (CRITICAL)
  - git_config_extraheader_credential Azure DevOps Basic header        (HIGH)
  - gitmodules_credential_url         token in [submodule] url=        (CRITICAL)
  - git_config_generic_token_url      user:pass@host, no known prefix  (LOW)

Known limitations:
  - http.extraHeader specified multiple times: configparser keeps only the last
    value, so a non-final AUTHORIZATION header can be missed (rare in practice).
  - [include] / include.path directives are not followed.
"""
from __future__ import annotations

import base64
import binascii
import configparser
import re
from pathlib import Path
from typing import Dict, List, Optional

_OWASP = "LLM06"
_ATLAS = "AML.T0012"

# Provider token prefixes with high discriminability (low FP). Covers GitHub PAT
# (ghp_), fine-grained PAT (github_pat_), server-to-server (ghs_), OAuth (gho_),
# user-to-server (ghu_), refresh (ghr_); GitLab PAT (glpat-) and deploy (gldt-);
# Bitbucket (ATBB); Hugging Face (hf_).
_PREFIX_RE = re.compile(
    r"(ghp_|github_pat_|ghs_|gho_|ghu_|ghr_|glpat-|gldt-|ATBB|hf_)[A-Za-z0-9_\-]{8,}"
)
# user:password@host — credential-bearing URL with no recognised prefix.
_USERPASS_RE = re.compile(r"https?://[^/\s:@]+:[^/\s@]+@[^/\s]+")
# Colon-less userinfo: a long token used AS the username (https://TOKEN@host) — a
# valid git form that escapes both prefix and user:pass matching. Lower confidence.
_USERINFO_RE = re.compile(r"https?://[^/\s:@]{20,}@[^/\s]+")


def _mask(token: str) -> str:
    """Mask a credential token — never expose prefix patterns like 'ghp_'."""
    if len(token) <= 8:
        return "*" * len(token)
    return "*" * (len(token) - 4) + token[-4:]


def _read(path: Path) -> Optional[configparser.ConfigParser]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    parser = configparser.ConfigParser(strict=False, interpolation=None, allow_no_value=True)
    try:
        parser.read_string(text)
    except configparser.Error:
        return None
    return parser


def _classify_url(url: str) -> Optional[Dict]:
    """Return (partial) finding fields for a credential-bearing URL, or None."""
    m = _PREFIX_RE.search(url)
    if m:
        return {"severity": "CRITICAL", "_token": m.group(0), "_generic": False}
    m = _USERPASS_RE.search(url)
    if m:
        return {
            "severity": "LOW",
            "_token": m.group(0).split("@")[0].split("//")[-1],
            "_generic": True,
        }
    # Colon-less token-as-username (https://TOKEN@host) — flag LOW for manual review.
    m = _USERINFO_RE.search(url)
    if m:
        return {
            "severity": "LOW",
            "_token": m.group(0).split("@")[0].split("//")[-1],
            "_generic": True,
        }
    return None


def _finding(ftype: str, severity: str, source: str, description: str,
             committed: bool = False) -> Dict:
    f = {
        "type": ftype,
        "severity": severity,
        "source": source,
        "description": description,
        "attack_class": _OWASP,
        "atlas_technique": _ATLAS,
    }
    if committed:
        f["committed_to_history"] = True
    return f


# Option keys whose VALUE can carry a credential-bearing URL. Beyond `url`, git
# rewrites via `insteadof`/`pushinsteadof` and pushes via `pushurl` — all of which
# git actively substitutes, so a token in any of them is live.
_URL_OPTION_KEYS = ("url", "pushurl", "insteadof", "pushinsteadof")


def _emit_url_finding(cls: Dict, section: str, source: str, where: str,
                      *, submodule: bool) -> Dict:
    masked = _mask(cls["_token"])
    if submodule:
        # severity from _classify_url: CRITICAL for prefix tokens, LOW for generic
        return _finding(
            "gitmodules_credential_url", cls["severity"], source,
            f"Submodule {section} embeds a credential-bearing URL ({masked}@...).",
            committed=True,
        )
    if cls["_generic"]:
        return _finding(
            "git_config_generic_token_url", "LOW", source,
            f"{where} in {section} contains user:password credentials "
            f"({masked}@...). Generic form — verify manually.",
        )
    return _finding(
        "git_config_credential_url", "CRITICAL", source,
        f"{where} in {section} embeds an access token ({masked}). "
        "Token persists in git metadata across clone/package operations.",
    )


def _scan_remote_like(parser, source: str, *, submodule: bool) -> List[Dict]:
    out: List[Dict] = []
    for section in parser.sections():
        if section == configparser.DEFAULTSECT:
            continue
        # The section HEADER itself can carry a token: [url "https://TOKEN@host/"].
        header_cls = _classify_url(section)
        if header_cls is not None:
            out.append(_emit_url_finding(header_cls, section, source,
                                         "Rewrite-rule URL", submodule=submodule))
        # Any URL-bearing option value (url / pushurl / insteadOf / pushInsteadOf).
        for key in _URL_OPTION_KEYS:
            if not parser.has_option(section, key):
                continue
            cls = _classify_url(parser.get(section, key))
            if cls is None:
                continue
            label = "URL" if key == "url" else f"{key} value"
            out.append(_emit_url_finding(cls, section, source, label,
                                         submodule=submodule))
    return out


def _scan_extraheader(parser, source: str) -> List[Dict]:
    out: List[Dict] = []
    for section in parser.sections():
        if section == configparser.DEFAULTSECT:
            continue
        if not parser.has_option(section, "extraheader"):
            continue
        value = parser.get(section, "extraheader")
        # Basic <base64(:PAT)> — decode then take the secret after the colon.
        m = re.search(r"Basic\s+([A-Za-z0-9+/=]+)", value, re.IGNORECASE)
        if m:
            try:
                decoded = base64.b64decode(m.group(1), validate=True).decode("utf-8", "ignore")
            except (binascii.Error, ValueError):
                decoded = ""
            secret = decoded.split(":", 1)[-1].strip()
            if len(secret) >= 8:
                out.append(_finding(
                    "git_config_extraheader_credential", "HIGH", source,
                    f"{section} stores a Basic-auth credential in http.extraHeader "
                    f"({_mask(secret)}). Common Azure DevOps PAT vector.",
                ))
                continue
        # Bearer <token> / token <token> — the trailing value IS the credential.
        m = re.search(r"\b(?:Bearer|token)\s+(\S+)", value, re.IGNORECASE)
        if m:
            secret = m.group(1).strip()
            if len(secret) >= 8:
                out.append(_finding(
                    "git_config_extraheader_credential", "HIGH", source,
                    f"{section} stores a bearer/token credential in http.extraHeader "
                    f"({_mask(secret)}).",
                ))
    return out


def scan(root) -> List[Dict]:
    root = Path(root)
    out: List[Dict] = []

    git_config = root / ".git" / "config"
    if git_config.is_file():
        parser = _read(git_config)
        if parser is not None:
            out.extend(_scan_remote_like(parser, ".git/config", submodule=False))
            out.extend(_scan_extraheader(parser, ".git/config"))

    gitmodules = root / ".gitmodules"
    if gitmodules.is_file():
        parser = _read(gitmodules)
        if parser is not None:
            out.extend(_scan_remote_like(parser, ".gitmodules", submodule=True))
    return out
