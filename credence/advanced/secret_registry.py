"""Cross-source secret frequency registry + orphan-signal enrichment.

A secret seen in exactly one source is statistically more likely a private
accidental leak; a secret seen across many sources is likely a scraped public
example. We tag each secret finding with a `source_frequency` band and a
`secret_value_hash` (SHA256 of the normalised value).

The registry persists secret-value HASHES (never the raw secret values) plus,
per hash, the list of distinct source labels (relative file paths) it was seen
in. Those source labels are needed to count distinct sources; be aware they are
written to the registry file, so treat that file as repo-structure-revealing if
you share it for cross-team dedup. Frequency is a triage hint, not a verdict.

The hash also feeds SARIF `partialFingerprints["secretValueHash/v1"]`, enabling
cross-tool deduplication (e.g. running alongside TruffleHog).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import unquote

logger = logging.getLogger(__name__)

# Well-known placeholder/example credentials → downgrade to INFO.
KNOWN_EXAMPLE_KEYS = frozenset({
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "AIzaSyDUMMYKEYDUMMYKEYDUMMYKEYDUMMYKEY1",
})


def normalize(value: str) -> str:
    """Normalise a secret for hashing: strip + URL-decode, preserve case.

    URL-decoding makes Credence and TruffleHog (which URL-decodes extracted
    values) land on the same hash for the same logical secret, so cross-tool
    dedup via partialFingerprints works. This is intentionally lossy: two
    different raw encodings of the same secret hash identically.
    """
    return unquote((value or "").strip())


def secret_hash(value: str) -> str:
    return hashlib.sha256(normalize(value).encode("utf-8")).hexdigest()


def frequency_band(count: int) -> str:
    if count <= 1:
        return "orphan_candidate"
    if count <= 5:
        return "low"
    if count <= 15:
        return "moderate"
    if count <= 50:
        return "high"
    return "replicated"


# Token substrings that mark a finding-dict as a credential. Narrower than the
# cluster module's set on purpose: the registry PERSISTS a hash for every match,
# so we avoid the over-broad `_url` token (which matches non-credential findings
# like redirect_url). DB connection-string findings (postgres_url, mongodb_url,
# ...) still qualify via their raw `value_full`, handled by the first branch below.
_SECRET_TYPE_TOKENS = (
    "_api_key", "_token", "_pat", "_webhook", "_key", "_sid", "_password",
    "private_key", "jwt_token",
)


def _is_secret_finding(f: Dict) -> bool:
    # A raw secret value present (value_full/secret) is the strongest signal and
    # covers DB connection URLs, context-bound keys, etc. without a token match.
    if f.get("value_full") or f.get("secret"):
        return True
    t = f.get("type", "") or ""
    return any(tok in t for tok in _SECRET_TYPE_TOKENS)


def _raw_value(f: Dict) -> Optional[str]:
    return f.get("value_full") or f.get("secret")


class SecretRegistry:
    """Persistent SHA256 -> sorted list of distinct source labels. Hashes only."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._data: Dict[str, List[str]] = {}
        if self.path.is_file():
            try:
                self._data = json.loads(self.path.read_text())
            except (OSError, ValueError):
                self._data = {}

    def observe(self, value: str, source: str) -> int:
        """Record (hash, source); return the distinct-source count for this secret."""
        h = secret_hash(value)
        sources = self._data.setdefault(h, [])
        if source not in sources:
            sources.append(source)
            sources.sort()
        return len(sources)

    def save(self) -> None:
        # The registry holds secret HASHES + source file PATHS — both sensitive on a
        # shared host. Create the dir 0700 and the file 0600, umask-proof: pass mode to
        # mkdir AND chmod after (mkdir mode is masked by umask), and open the file with
        # an explicit 0o600 opener so it is never momentarily world-readable.
        try:
            parent = self.path.parent
            parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(parent, 0o700)
            except OSError:
                pass  # best-effort (e.g. parent not owned by us); file mode still 0600
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, json.dumps(self._data, indent=0).encode("utf-8"))
            finally:
                os.close(fd)
            # If the file pre-existed with looser perms, O_CREAT won't tighten it.
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        except OSError as exc:
            logger.warning("secret_registry: could not save %s: %s", self.path, exc)


def enrich(findings: List[Dict], registry: Optional[SecretRegistry]) -> None:
    """Mutate secret findings in-place: add secret_value_hash + source_frequency.

    With a registry, source_frequency reflects cross-source observation count.
    Without one, only the hash is added (still feeds SARIF fingerprints).
    Known example keys are downgraded to INFO regardless of registry.
    """
    for f in findings:
        if not _is_secret_finding(f):
            continue
        raw = _raw_value(f)
        if raw is None:
            continue
        f["secret_value_hash"] = secret_hash(raw)
        if normalize(raw) in KNOWN_EXAMPLE_KEYS:
            f["severity"] = "INFO"
            f["source_frequency"] = "known_example"
            continue
        if registry is not None:
            count = registry.observe(raw, f.get("source") or "unknown")
            f["source_frequency"] = frequency_band(count)
    if registry is not None:
        registry.save()
