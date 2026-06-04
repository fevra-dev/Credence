# credence/workflow_audit/normalize.py
"""Canonicalize run-block text before rule matching so shell-level obfuscation
(F-010) does not defeat detection: strip invisible unicode, collapse backslash
line-continuations and ${IFS}/$IFS word-splitting tricks.
"""

from __future__ import annotations

import re
import unicodedata

# ${IFS}, $IFS, ${IFS:0:1} style splitters → a single space
_IFS_RE = re.compile(r"\$\{IFS[^}]*\}|\$IFS")
_LINE_CONT_RE = re.compile(r"\\\r?\n")
# zero-width / bidi / invisible separators
_INVISIBLE = "".join(chr(c) for c in (
    0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD,
    0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
))
_INVISIBLE_RE = re.compile("[" + re.escape(_INVISIBLE) + "]")


def normalize_run(run_text: str) -> str:
    if not run_text:
        return ""
    text = unicodedata.normalize("NFKC", run_text)
    text = _INVISIBLE_RE.sub("", text)
    text = _LINE_CONT_RE.sub("", text)        # join `cu\<newline>rl` -> `curl`
    text = _IFS_RE.sub(" ", text)             # `cu${IFS}rl` -> `cu rl`
    return text
