# tests/test_workflow_rule_config.py
from credence.workflow_audit.parser import parse_workflow
from credence.workflow_audit.taint import resolve_job
from credence.workflow_audit.rules import RuleContext
import credence.workflow_audit.rules.config_rules as cfg


def _run(fn, text):
    wf = parse_workflow(text, path="x")
    resolved = {j.job_id: resolve_job(wf, j) for j in wf.jobs}
    return list(fn(wf, resolved, RuleContext()))


PWN = """
on: pull_request_target
jobs:
  b:
    runs-on: x
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
SAFE_CHECKOUT = """
on: pull_request_target
jobs:
  b:
    runs-on: x
    steps:
      - uses: actions/checkout@v4
"""


def test_cfg_001_pwn_request_fires_high():
    out = _run(cfg.wf_cfg_001, PWN)
    assert any(f.rule_id == "WF-CFG-001" and f.severity.value == "HIGH" for f in out)


def test_cfg_001_base_checkout_safe():
    assert _run(cfg.wf_cfg_001, SAFE_CHECKOUT) == []


def test_cfg_002_write_all_fires():
    out = _run(cfg.wf_cfg_002,
               "on: push\njobs:\n  b:\n    runs-on: x\n    permissions: write-all\n    steps: []")
    assert any(f.rule_id == "WF-CFG-002" for f in out)


def test_cfg_002_absent_permissions_fires():
    out = _run(cfg.wf_cfg_002,
               "on: push\njobs:\n  b:\n    runs-on: x\n    steps: []")
    assert any(f.rule_id == "WF-CFG-002" for f in out)


def test_cfg_002_explicit_read_is_clean():
    out = _run(cfg.wf_cfg_002,
               "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: x\n    steps: []")
    assert out == []


def test_cfg_003_branch_pin_medium_sha_clean():
    branch = _run(cfg.wf_cfg_003, "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
                  "      - uses: some/action@main")
    assert any(f.rule_id == "WF-CFG-003" and f.severity.value == "MEDIUM" for f in branch)
    sha = _run(cfg.wf_cfg_003, "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
               "      - uses: some/action@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0")
    assert [f for f in sha if f.rule_id == "WF-CFG-003"] == []


def test_cfg_003_first_party_action_clean():
    out = _run(cfg.wf_cfg_003, "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
               "      - uses: actions/checkout@v4")
    # actions/* and github/* are first-party; @tag is Low, not flagged at default
    assert all(f.severity.value != "MEDIUM" for f in out)


def test_cfg_004_self_hosted_on_pr_target():
    out = _run(cfg.wf_cfg_004,
               "on: pull_request_target\njobs:\n  b:\n    runs-on: self-hosted\n    steps: []")
    assert any(f.rule_id == "WF-CFG-004" for f in out)


def test_cfg_004_self_hosted_on_push_clean():
    out = _run(cfg.wf_cfg_004,
               "on: push\njobs:\n  b:\n    runs-on: self-hosted\n    steps: []")
    assert out == []


def test_cfg_005_artipacked_checkout_then_upload():
    text = ("on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - uses: actions/upload-artifact@v4\n"
            "        with:\n          path: .\n")
    out = _run(cfg.wf_cfg_005, text)
    assert any(f.rule_id == "WF-CFG-005" for f in out)


def test_cfg_005_checkout_with_persist_false_clean():
    text = ("on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n          persist-credentials: false\n"
            "      - uses: actions/upload-artifact@v4\n        with:\n          path: .\n")
    assert _run(cfg.wf_cfg_005, text) == []


def test_cfg_006_secrets_inherit():
    text = ("on: push\njobs:\n  b:\n    uses: ./.github/workflows/reusable.yml\n"
            "    secrets: inherit\n")
    out = _run(cfg.wf_cfg_006, text)
    assert any(f.rule_id == "WF-CFG-006" for f in out)
