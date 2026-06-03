"""Orchestrator: spawn `git log -p`, stream it through the diff parser, run
SecretExtractor over added lines, dedup to earliest commit, attach metadata."""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from ..secrets.secret_extractor import SecretExtractor
from .diff_parser import parse_history

_PRETTY = "format:%x01%H%x00%an%x00%aI"


def _is_git_repo(repo_path: Path) -> bool:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        raise ValueError("git executable not found on PATH")
    return result.returncode == 0 and result.stdout.strip() == "true"


def scan_history(
    repo_path,
    *,
    since: Optional[str] = None,
    max_commits: Optional[int] = None,
) -> List[Dict]:
    """Scan all reachable git history for secrets.

    Returns a flat list of finding-dicts (SecretExtractor shape) each augmented
    with commit / commit_short / author / commit_date / source. Each distinct
    secret value is reported once, at its earliest-introducing commit.

    Raises ValueError if repo_path is not a git repository.
    """
    repo_path = Path(repo_path)
    if not _is_git_repo(repo_path):
        raise ValueError(f"not a git repository: {repo_path}")

    args = [
        "git", "-C", str(repo_path), "log", "-p", "--all", "--reverse",
        "-U0", "--no-color", f"--pretty={_PRETTY}",
    ]
    if since:
        args += ["--since", since]
    if max_commits:
        args += [f"--max-count={int(max_commits)}"]

    proc = subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, errors="replace", bufsize=1,
    )

    extractor = SecretExtractor()
    seen: set = set()
    findings: List[Dict] = []

    loop = asyncio.new_event_loop()
    try:
        assert proc.stdout is not None
        for commit, path, added_text in parse_history(proc.stdout):
            secrets = loop.run_until_complete(
                extractor.extract(added_text, source=path)
            )
            for s in secrets:
                value = s.get("value_full") or ""
                if not value or value in seen:
                    continue
                seen.add(value)
                s["commit"] = commit.sha
                s["commit_short"] = commit.sha[:7]
                s["author"] = commit.author
                s["commit_date"] = commit.date
                s["source"] = path
                findings.append(s)
    finally:
        loop.close()
        proc.wait()

    return findings
