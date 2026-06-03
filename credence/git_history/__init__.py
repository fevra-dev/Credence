"""git-history secret scanning for GitExpose v0.4.

Streams `git log -p` over all reachable commits, runs SecretExtractor over added
lines, and reports each secret once (at its earliest-introducing commit) with
commit metadata. Composes with the verification engine via the CLI.
"""

from .scanner import scan_history

__all__ = ["scan_history"]
