# credence/workflow_audit/platforms.py
"""GitHub Actions platform adapter: discovery globs, untrusted-context grammar
(research-verified 18-field list + suffix heuristic), privileged-trigger sets,
and PR-controlled-ref detection. Other platforms are recognized by path only in
v1 (no GH-specific checks)."""

from __future__ import annotations

import re
from typing import List

WORKFLOW_GLOBS = [".github/workflows/*.yml", ".github/workflows/*.yaml"]
ACTION_GLOBS = [".github/actions/**/action.yml", ".github/actions/**/action.yaml",
                "action.yml", "action.yaml"]

# Research-verified explicit untrusted-input fields (GitHub Security Lab).
UNTRUSTED_FIELDS = {
    "github.event.issue.title", "github.event.issue.body",
    "github.event.pull_request.title", "github.event.pull_request.body",
    "github.event.comment.body", "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.pages.*.page_name",
    "github.event.commits.*.message",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.commits.*.author.email",
    "github.event.commits.*.author.name",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.head_ref",
}
# GitHub Docs suffix heuristic (applied to github.event.* paths for recall).
UNTRUSTED_SUFFIXES = ("body", "default_branch", "email", "head_ref", "label",
                      "message", "name", "page_name", "ref", "title")

CANONICAL_PRIVILEGED_TRIGGERS = {"pull_request_target", "workflow_run"}
PRIVILEGED_TRIGGERS = CANONICAL_PRIVILEGED_TRIGGERS | {
    "issue_comment", "issues", "discussion", "discussion_comment",
    "schedule", "workflow_call",
}

_EXPR_RE = re.compile(r"\$\{\{\s*(github\.[A-Za-z0-9_.*\[\]'\"-]+?)\s*\}\}")
_PR_REF_RE = re.compile(
    r"github\.event\.pull_request\.head\.|github\.head_ref")


def _last_segment(expr: str) -> str:
    return expr.rstrip("]'\"").split(".")[-1]


def _is_untrusted(expr: str) -> bool:
    if expr in UNTRUSTED_FIELDS:
        return True
    if expr == "github.head_ref":
        return True
    if expr.startswith("github.event."):
        return _last_segment(expr) in UNTRUSTED_SUFFIXES
    return False


def untrusted_contexts(text: str) -> List[str]:
    """Return github.* expressions in `text` that are attacker-controllable."""
    out: List[str] = []
    for m in _EXPR_RE.finditer(text or ""):
        expr = m.group(1)
        if _is_untrusted(expr) and expr not in out:
            out.append(expr)
    return out


def is_pr_controlled_ref(value: str) -> bool:
    return bool(value) and bool(_PR_REF_RE.search(value))
