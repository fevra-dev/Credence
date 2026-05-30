#!/usr/bin/env python3
"""Offline generator: build cl4r1t4s_fingerprints.json from a local CL4R1T4S checkout.

NOT shipped in the wheel. Usage:
    python scripts/build_cl4r1t4s_fingerprints.py /path/to/CL4R1T4S_checkout

Walks *.md/*.mkd/*.txt files, treats each as one leaked prompt, and emits shingle
fingerprints (hashes only — no prompt text is written out).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from gitexpose.agent_exposure.system_prompt import build_shingles, _DEFAULT_PATH

K = 8
MIN_MATCH = 5


def main(checkout: str) -> None:
    root = Path(checkout)
    fps = []
    for p in root.rglob("*"):
        if p.suffix.lower() not in (".md", ".mkd", ".txt") or not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="ignore")
        shingles = sorted(build_shingles(text, K))
        if len(shingles) < MIN_MATCH:
            continue
        fps.append({
            "product": p.stem,
            "source_url": f"CL4R1T4S/{p.relative_to(root)}",
            "shingle_k": K,
            "min_match": MIN_MATCH,
            "shingles": shingles,
        })
    _DEFAULT_PATH.write_text(
        json.dumps({"version": 1, "fingerprints": fps}, indent=2), encoding="utf-8"
    )
    print(f"wrote {len(fps)} fingerprints to {_DEFAULT_PATH}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: build_cl4r1t4s_fingerprints.py <CL4R1T4S_checkout>")
    main(sys.argv[1])
