# tests/test_workflow_platforms.py
from credence.workflow_audit.platforms import (
    WORKFLOW_GLOBS, ACTION_GLOBS, untrusted_contexts, PRIVILEGED_TRIGGERS,
    CANONICAL_PRIVILEGED_TRIGGERS, is_pr_controlled_ref,
)


def test_globs_cover_workflows_and_actions():
    assert ".github/workflows/*.yml" in WORKFLOW_GLOBS
    assert ".github/workflows/*.yaml" in WORKFLOW_GLOBS
    assert ".github/actions/**/action.yml" in ACTION_GLOBS


def test_untrusted_explicit_field():
    found = untrusted_contexts(
        'echo "${{ github.event.pull_request.title }}"')
    assert "github.event.pull_request.title" in found


def test_untrusted_suffix_heuristic_on_event_paths():
    # not in the explicit 18 but ends in a known untrusted suffix -> flagged
    found = untrusted_contexts("${{ github.event.discussion.title }}")
    assert "github.event.discussion.title" in found


def test_untrusted_head_ref_non_event():
    assert "github.head_ref" in untrusted_contexts("${{ github.head_ref }}")


def test_trusted_context_not_flagged():
    # github.repository / github.sha are not attacker-controlled text sinks
    assert untrusted_contexts("${{ github.repository }} ${{ github.sha }}") == []


def test_canonical_vs_extended_triggers():
    assert "pull_request_target" in CANONICAL_PRIVILEGED_TRIGGERS
    assert "workflow_run" in CANONICAL_PRIVILEGED_TRIGGERS
    assert "issue_comment" in PRIVILEGED_TRIGGERS
    assert "issue_comment" not in CANONICAL_PRIVILEGED_TRIGGERS


def test_pr_controlled_ref_detection():
    assert is_pr_controlled_ref("${{ github.event.pull_request.head.sha }}")
    assert is_pr_controlled_ref("${{ github.head_ref }}")
    assert not is_pr_controlled_ref("${{ github.sha }}")
    assert not is_pr_controlled_ref("main")
