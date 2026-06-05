"""Parse GitHub Actions workflow / composite-action YAML into typed models.

PyYAML safe_load only. On any parse error we return a Workflow with
parse_ok=False and the raw text preserved (Approach C: callers degrade to
line-scan and emit a fail-loud finding rather than silently skipping).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import yaml

from .models import Job, Step, Workflow

# Sentinel used in _build_job / parse_workflow to distinguish an absent
# `permissions:` key from an explicit `permissions: null`.
_ABSENT = object()

# ---------------------------------------------------------------------------
# Line-tracking YAML loader
# ---------------------------------------------------------------------------
_LINE_KEY = "__line__"


class _LineLoader(yaml.SafeLoader):
    pass


_KEY_LINES_KEY = "__key_lines__"


def _construct_mapping(loader, node, deep=False):
    mapping = yaml.SafeLoader.construct_mapping(loader, node, deep=deep)
    mapping[_LINE_KEY] = node.start_mark.line + 1
    # Also record per-key line numbers so callers can retrieve the line of a
    # named key (e.g. the "build:" job key) rather than the mapping-value line.
    key_lines = {}
    for key_node, _val_node in node.value:
        if key_node.tag == "tag:yaml.org,2002:str":
            key_lines[key_node.value] = key_node.start_mark.line + 1
    mapping[_KEY_LINES_KEY] = key_lines
    return mapping


_LineLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


def _line_load(text: str):
    return yaml.load(text, Loader=_LineLoader)  # noqa: S506 (custom SafeLoader subclass)


_INJECTED_KEYS = (_LINE_KEY, _KEY_LINES_KEY)


# ---------------------------------------------------------------------------


def _clean_perms(perms):
    if isinstance(perms, dict):
        return {k: v for k, v in perms.items() if k not in _INJECTED_KEYS}
    return perms


def _norm_events(on_value: Any) -> List[str]:
    if on_value is None:
        return []
    if isinstance(on_value, str):
        return [on_value]
    if isinstance(on_value, list):
        return [str(e) for e in on_value]
    if isinstance(on_value, dict):
        return [str(k) for k in on_value.keys() if k not in _INJECTED_KEYS]
    return []


def _env_to_str_map(env: Any) -> Dict[str, str]:
    if isinstance(env, dict):
        return {str(k): "" if v is None else str(v)
                for k, v in env.items() if k not in _INJECTED_KEYS}
    return {}


def _build_step(idx: int, raw: Any) -> Step:
    if not isinstance(raw, dict):
        return Step(index=idx, name=None, uses=None, run=None)
    return Step(
        index=idx,
        name=(str(raw["name"]) if raw.get("name") is not None else None),
        uses=(str(raw["uses"]) if raw.get("uses") is not None else None),
        run=(str(raw["run"]) if raw.get("run") is not None else None),
        env=_env_to_str_map(raw.get("env")),
        with_={k: v for k, v in (raw.get("with") or {}).items() if k not in _INJECTED_KEYS}
              if isinstance(raw.get("with"), dict) else {},
        shell=(str(raw["shell"]) if raw.get("shell") is not None else None),
        line=int(raw.get(_LINE_KEY, 0)),
    )


def _build_job(job_id: str, raw: Any, key_line: int = 0) -> Job:
    if not isinstance(raw, dict):
        return Job(job_id=job_id)
    perms = raw.get("permissions", _ABSENT)
    # Prefer the key line (e.g. line of "build:" in the jobs dict) over the
    # mapping-value line (first key inside the job dict).
    line = key_line or int(raw.get(_LINE_KEY, 0))
    job = Job(
        job_id=job_id,
        runs_on=raw.get("runs-on"),
        permissions=(None if perms is _ABSENT else _clean_perms(perms)),
        permissions_absent=(perms is _ABSENT),
        env=_env_to_str_map(raw.get("env")),
        uses=(str(raw["uses"]) if raw.get("uses") is not None else None),
        secrets_inherit=(raw.get("secrets") == "inherit"),
        line=line,
    )
    steps = raw.get("steps")
    if isinstance(steps, list):
        job.steps = [_build_step(i, s) for i, s in enumerate(steps)]
    return job


def parse_workflow(text: str, path: str) -> Workflow:
    wf = Workflow(path=path, raw_text=text)
    try:
        data = _line_load(text)
    except yaml.YAMLError:
        wf.parse_ok = False
        return wf
    if not isinstance(data, dict):
        wf.parse_ok = False
        return wf

    wf.name = (str(data["name"]) if data.get("name") is not None else None)
    # NB: PyYAML parses the bare key `on` as boolean True (YAML 1.1). Accept both.
    on_value = data.get("on", data.get(True))
    wf.on_events = _norm_events(on_value)

    perms = data.get("permissions", _ABSENT)
    wf.permissions = (None if perms is _ABSENT else _clean_perms(perms))
    wf.permissions_absent = (perms is _ABSENT)
    wf.env = _env_to_str_map(data.get("env"))

    jobs = data.get("jobs")
    if isinstance(jobs, dict):
        jobs_key_lines = jobs.get(_KEY_LINES_KEY, {}) if isinstance(jobs, dict) else {}
        wf.jobs = [
            _build_job(str(jid), jraw, key_line=jobs_key_lines.get(str(jid), 0))
            for jid, jraw in jobs.items()
            if jid not in (_LINE_KEY, _KEY_LINES_KEY)
        ]
    return wf


_LOCAL_SCRIPT_RE = re.compile(
    # The interpreter-prefix group uses \.(?!/) so a bare dot is only consumed as
    # a `source`-alias when it is NOT followed by `/`.  Without the lookahead the
    # optional `\.` would eat the leading `.` of `./script.sh` after a chained
    # operator (&&, ||, ;), producing a spurious `/script.sh` capture.
    r"(?:^|\s|;|&&|\|\|)\s*(?:bash|sh|source|\.(?!/))?\s*(\./[\w./-]+|[\w./-]+\.sh)\b"
)


def parse_action(text: str, path: str) -> Workflow:
    """Parse a composite action.yml; surface runs.steps as a synthetic 'runs' job."""
    wf = Workflow(path=path, raw_text=text, is_composite_action=True)
    try:
        data = _line_load(text)
    except yaml.YAMLError:
        wf.parse_ok = False
        return wf
    if not isinstance(data, dict):
        wf.parse_ok = False
        return wf
    wf.name = (str(data["name"]) if data.get("name") is not None else None)
    runs = data.get("runs")
    if isinstance(runs, dict) and isinstance(runs.get("steps"), list):
        job = Job(job_id="runs")
        job.steps = [_build_step(i, s) for i, s in enumerate(runs["steps"])]
        wf.jobs = [job]
    return wf


def run_script_refs(run_text: str) -> List[str]:
    """Return repo-local script paths invoked from a run block (not remote URLs)."""
    if not run_text:
        return []
    refs: List[str] = []
    for m in _LOCAL_SCRIPT_RE.finditer(run_text):
        ref = m.group(1)
        if "://" in ref:
            continue
        if ref.startswith("/"):
            continue  # absolute paths are never repo-local refs
        if ref.endswith(".sh") or ref.startswith("./"):
            refs.append(ref)
    return refs
