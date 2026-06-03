"""Streaming state-machine parser for `git log -p --pretty=format:'\\x01%H\\x00%an\\x00%aI'`.

Pure function over already-decoded lines — no git is spawned here, so it is fully
unit-testable on canned input. Yields (CommitMeta, file_path, added_text) for each
file that has at least one added line in each commit.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Iterator, List, Optional, Tuple

_SENTINEL = "\x01"


@dataclass(frozen=True)
class CommitMeta:
    sha: str
    author: str
    date: str  # ISO 8601


def parse_history(lines: Iterable[str]) -> Iterator[Tuple[CommitMeta, str, str]]:
    """Yield (commit, file_path, added_text) blocks.

    `lines` is an iterable of decoded lines (trailing newlines are stripped).
    """
    commit: Optional[CommitMeta] = None
    current_file: Optional[str] = None
    buffer: List[str] = []

    def _flush(c, f, buf) -> Iterator[Tuple[CommitMeta, str, str]]:
        if c is not None and f is not None and buf:
            yield c, f, "\n".join(buf)

    for raw in lines:
        line = raw.rstrip("\n")

        if line.startswith(_SENTINEL):
            yield from _flush(commit, current_file, buffer)
            buffer = []
            current_file = None
            payload = line[len(_SENTINEL):]
            parts = payload.split("\x00")
            sha = parts[0] if len(parts) > 0 else ""
            author = parts[1] if len(parts) > 1 else ""
            date = parts[2] if len(parts) > 2 else ""
            commit = CommitMeta(sha=sha, author=author, date=date)
            continue

        if line.startswith("diff --git "):
            yield from _flush(commit, current_file, buffer)
            buffer = []
            current_file = None
            continue

        if line.startswith("+++ b/") or line == "+++ /dev/null":
            yield from _flush(commit, current_file, buffer)
            buffer = []
            dest = line[4:].strip()
            if dest == "/dev/null":
                current_file = None
            else:
                current_file = dest[2:] if dest.startswith("b/") else dest
            continue

        if line.startswith("+") and current_file is not None:
            buffer.append(line[1:])
            continue

    yield from _flush(commit, current_file, buffer)
