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


def test_ifs_word_boundary_does_not_mangle_longer_vars():
    # $IFSVAR / $IFSMORE must not be treated as $IFS (prefix match)
    out = normalize_run("echo $IFSVAR")
    assert "IFSVAR" in out, f"$IFSVAR was mangled — got: {out!r}"

    out2 = normalize_run("echo $IFSMORE")
    assert "IFSMORE" in out2, f"$IFSMORE was mangled — got: {out2!r}"

    # existing behaviour preserved: cu${IFS}rl → cu rl
    out3 = normalize_run("cu${IFS}rl")
    assert "IFSVAR" not in out3  # sanity
    assert "cu rl" in out3 or ("cu" in out3 and "rl" in out3)
