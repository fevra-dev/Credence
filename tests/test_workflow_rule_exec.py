# tests/test_workflow_rule_exec.py
from credence.workflow_audit.parser import parse_workflow
from credence.workflow_audit.taint import resolve_job
from credence.workflow_audit.rules import RuleContext
import credence.workflow_audit.rules.exec_rules as exec_rules


def _run(text):
    wf = parse_workflow(text, path=".github/workflows/ci.yml")
    resolved = {j.job_id: resolve_job(wf, j) for j in wf.jobs}
    out = []
    out += exec_rules.wf_exec_001(wf, resolved, RuleContext())
    return out


SAME_STEP = """
on: push
jobs:
  b:
    runs-on: x
    steps:
      - run: echo aGk= | base64 -d | bash
"""
CROSS_STEP = """
on: push
jobs:
  b:
    runs-on: x
    steps:
      - run: echo aGk= | base64 -d > /tmp/p.sh
      - run: bash /tmp/p.sh
"""
BENIGN = """
on: push
jobs:
  b:
    runs-on: x
    steps:
      - run: |
          base64 -d secret.b64 > secret.bin
          echo "decoded a data file, not executing"
"""


def test_same_step_decode_to_shell_fires_high():
    out = _run(SAME_STEP)
    assert any(f.rule_id == "WF-EXEC-001" and f.severity.value == "HIGH" for f in out)


def test_cross_step_decode_then_run_fires_via_taint():
    out = _run(CROSS_STEP)
    assert any(f.rule_id == "WF-EXEC-001" for f in out)


def test_benign_decode_to_file_no_execution_does_not_fire():
    assert _run(BENIGN) == []
