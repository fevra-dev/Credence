"""Unit tests for the git-history diff parser. The parser is a pure function over
already-decoded lines (no git spawned), so we feed it canned `git log -p` output."""

from credence.git_history.diff_parser import CommitMeta, parse_history

SENT = "\x01"  # sentinel prefix used in --pretty=format

CANNED = [
    f"{SENT}aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x00Jane Dev\x002025-11-04T12:30:00-05:00",
    "diff --git a/config.py b/config.py",
    "new file mode 100644",
    "index 0000000..1111111",
    "--- /dev/null",
    "+++ b/config.py",
    "@@ -0,0 +1 @@",
    "+OPENAI_API_KEY=sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    f"{SENT}bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\x00Bob\x002025-12-01T09:00:00-05:00",
    "diff --git a/.env b/.env",
    "--- /dev/null",
    "+++ b/.env",
    "@@ -0,0 +1 @@",
    "+GROQ_API_KEY=gsk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
]


def test_parses_two_commits_with_files():
    blocks = list(parse_history(iter(CANNED)))
    assert len(blocks) == 2
    c0, path0, added0 = blocks[0]
    assert isinstance(c0, CommitMeta)
    assert c0.sha == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert c0.author == "Jane Dev"
    assert c0.date == "2025-11-04T12:30:00-05:00"
    assert path0 == "config.py"
    assert "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in added0
    c1, path1, added1 = blocks[1]
    assert c1.sha.startswith("bbbb")
    assert path1 == ".env"
    assert "gsk_" in added1


def test_added_text_excludes_the_plus_header_and_minus_lines():
    canned = [
        f"{SENT}cccccccccccccccccccccccccccccccccccccccc\x00A\x002025-01-01T00:00:00Z",
        "diff --git a/x.txt b/x.txt",
        "--- a/x.txt",
        "+++ b/x.txt",
        "@@ -1 +1 @@",
        "-old line",
        "+new SECRET=sk-cccccccccccccccccccccccccccc",
    ]
    blocks = list(parse_history(iter(canned)))
    assert len(blocks) == 1
    _, path, added = blocks[0]
    assert path == "x.txt"
    assert "new SECRET=sk-cccccccccccccccccccccccccccc" in added
    assert "old line" not in added
    assert "+++ b/x.txt" not in added


def test_binary_hunk_yields_no_added_text():
    canned = [
        f"{SENT}dddddddddddddddddddddddddddddddddddddddd\x00A\x002025-01-01T00:00:00Z",
        "diff --git a/logo.png b/logo.png",
        "Binary files /dev/null and b/logo.png differ",
    ]
    blocks = list(parse_history(iter(canned)))
    assert blocks == []


def test_content_line_starting_with_plus_plus_is_not_a_header():
    canned = [
        f"{SENT}ffffffffffffffffffffffffffffffffffffffff\x00A\x002025-01-01T00:00:00Z",
        "diff --git a/notes.txt b/notes.txt",
        "--- /dev/null",
        "+++ b/notes.txt",
        "@@ -0,0 +2 @@",
        "++ this is content that starts with plus-plus",
        "+OPENAI_API_KEY=sk-ffffffffffffffffffffffffffffff",
    ]
    blocks = list(parse_history(iter(canned)))
    assert len(blocks) == 1
    _, path, added = blocks[0]
    assert path == "notes.txt"
    assert "sk-ffffffffffffffffffffffffffffff" in added


def test_dev_null_destination_is_skipped():
    canned = [
        f"{SENT}eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\x00A\x002025-01-01T00:00:00Z",
        "diff --git a/gone.txt b/gone.txt",
        "--- a/gone.txt",
        "+++ /dev/null",
        "@@ -1 +0,0 @@",
        "-was here",
    ]
    blocks = list(parse_history(iter(canned)))
    assert blocks == []
