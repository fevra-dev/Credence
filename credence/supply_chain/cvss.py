"""CVSS v3.1 base-score computation and severity bucketing.

OSV's `severity` field carries a CVSS *vector string* (not a number), while
GHSA-sourced advisories carry a qualitative `database_specific.severity`. We
prefer the qualitative string when present and otherwise compute the v3.1 base
score from the vector with the official formula (FIRST CVSS v3.1 spec §7.1).
No external CVSS library — the formula is small and deterministic.
"""

from __future__ import annotations

import math
from typing import Optional, Tuple

# Metric weights (CVSS v3.1 spec, Table on §7.4)
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}


def _roundup(value: float) -> float:
    """Official CVSS v3.1 Roundup (spec Appendix A)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def base_score_from_vector(vector: str) -> Optional[float]:
    try:
        parts = dict(
            kv.split(":", 1) for kv in vector.split("/") if ":" in kv and not kv.startswith("CVSS")
        )
        av = _AV[parts["AV"]]
        ac = _AC[parts["AC"]]
        ui = _UI[parts["UI"]]
        scope_changed = parts["S"] == "C"
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[parts["PR"]]
        c, i, a = _CIA[parts["C"]], _CIA[parts["I"]], _CIA[parts["A"]]
    except (KeyError, ValueError):
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    raw = (1.08 * (impact + exploitability)) if scope_changed else (impact + exploitability)
    return _roundup(min(raw, 10.0))


def bucket(score: Optional[float]) -> str:
    if score is None:
        return "MEDIUM"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


_QUALITATIVE = {
    "CRITICAL": "CRITICAL", "HIGH": "HIGH",
    "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW",
}


def severity_from_osv(osv_vuln: dict) -> Tuple[str, Optional[float]]:
    """Return (severity_bucket, cvss_score|None) for an OSV vulnerability object."""
    # 1. Qualitative severity (GHSA) wins — no score to report.
    qual = ((osv_vuln.get("database_specific") or {}).get("severity") or "").upper()
    if qual in _QUALITATIVE:
        return _QUALITATIVE[qual], None
    # 2. CVSS vector → compute base score.
    for sev in osv_vuln.get("severity") or []:
        if str(sev.get("type", "")).startswith("CVSS") and sev.get("score"):
            score = base_score_from_vector(sev["score"])
            if score is not None:
                return bucket(score), score
    # 3. Default.
    return "MEDIUM", None
