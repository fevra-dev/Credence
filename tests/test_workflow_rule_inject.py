# tests/test_workflow_rule_inject.py
from credence.workflow_audit.parser import parse_workflow
from credence.workflow_audit.taint import resolve_job
from credence.workflow_audit.rules import RuleContext
import credence.workflow_audit.rules.inject_rules as inj


def _run001(text):
    wf = parse_workflow(text, path="x")
    resolved = {j.job_id: resolve_job(wf, j) for j in wf.jobs}
    return list(inj.wf_inj_001(wf, resolved, RuleContext()))


VULN = """
on: pull_request_target
jobs:
  b:
    runs-on: x
    steps:
      - run: echo "PR is ${{ github.event.pull_request.title }}"
"""
SAFE_ENV = """
on: pull_request_target
jobs:
  b:
    runs-on: x
    steps:
      - env:
          TITLE: ${{ github.event.pull_request.title }}
        run: echo "PR is $TITLE"
"""
SUFFIX = """
on: issues
jobs:
  b:
    runs-on: x
    steps:
      - run: echo "${{ github.event.issue.body }}"
"""


def test_untrusted_context_in_run_fires_high():
    out = _run001(VULN)
    assert any(f.rule_id == "WF-INJ-001" and f.severity.value == "HIGH" for f in out)


def test_env_bound_untrusted_context_is_safe():
    # the untrusted value is bound via env: and referenced as $TITLE -> not a finding
    assert _run001(SAFE_ENV) == []


def test_suffix_heuristic_event_field_fires():
    assert any(f.rule_id == "WF-INJ-001" for f in _run001(SUFFIX))
