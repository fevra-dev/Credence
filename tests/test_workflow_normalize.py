# tests/test_workflow_normalize.py
from credence.workflow_audit.normalize import normalize_run


def test_collapses_backslash_line_continuations():
    assert "curl" in normalize_run("cu\\\nrl -d x")
    assert normalize_run("cu\\\nrl").replace(" ", "").find("curl") != -1


def test_collapses_ifs_brace_obfuscation():
    out = normalize_run("cu${IFS}rl${IFS}-d")
    assert "curl" in out.replace(" ", "") or "cu rl" in out


def test_strips_invisible_unicode():
    # zero-width space embedded in "curl"
    obf = "cu​rl -d x"
    assert "curl" in normalize_run(obf)


def test_plain_text_passthrough():
    assert "base64 -d | bash" in normalize_run("base64 -d | bash")
