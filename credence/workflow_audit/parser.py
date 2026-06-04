"""Parse GitHub Actions workflow / composite-action YAML into typed models.

PyYAML safe_load only. On any parse error we return a Workflow with
parse_ok=False and the raw text preserved (Approach C: callers degrade to
line-scan and emit a fail-loud finding rather than silently skipping).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import yaml

from .models import Job, Step, Workflow


def _norm_events(on_value: Any) -> List[str]:
    if on_value is None:
        return []
    if isinstance(on_value, str):
        return [on_value]
    if isinstance(on_value, list):
        return [str(e) for e in on_value]
    if isinstance(on_value, dict):
        return [str(k) for k in on_value.keys()]
    return []


def _env_to_str_map(env: Any) -> Dict[str, str]:
    if isinstance(env, dict):
        return {str(k): "" if v is None else str(v) for k, v in env.items()}
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
        with_=raw.get("with") if isinstance(raw.get("with"), dict) else {},
        shell=(str(raw["shell"]) if raw.get("shell") is not None else None),
    )


def _build_job(job_id: str, raw: Any) -> Job:
    if not isinstance(raw, dict):
        return Job(job_id=job_id)
    perms = raw.get("permissions", _ABSENT)
    job = Job(
        job_id=job_id,
        runs_on=raw.get("runs-on"),
        permissions=(None if perms is _ABSENT else perms),
        permissions_absent=(perms is _ABSENT),
        env=_env_to_str_map(raw.get("env")),
        uses=(str(raw["uses"]) if raw.get("uses") is not None else None),
        secrets_inherit=(raw.get("secrets") == "inherit"),
    )
    steps = raw.get("steps")
    if isinstance(steps, list):
        job.steps = [_build_step(i, s) for i, s in enumerate(steps)]
    return job


_ABSENT = object()


def parse_workflow(text: str, path: str) -> Workflow:
    wf = Workflow(path=path, raw_text=text)
    try:
        data = yaml.safe_load(text)
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
    wf.permissions = (None if perms is _ABSENT else perms)
    wf.permissions_absent = (perms is _ABSENT)
    wf.env = _env_to_str_map(data.get("env"))

    jobs = data.get("jobs")
    if isinstance(jobs, dict):
        wf.jobs = [_build_job(str(jid), jraw) for jid, jraw in jobs.items()]
    return wf
