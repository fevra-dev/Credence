"""Agent debug-print AST detector: flags print/logging of credential-named vars."""
from pathlib import Path

from gitexpose.agent_exposure.debug_print import scan


def _py(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body)
    return p


def test_print_of_api_key_var_is_flagged(tmp_path):
    _py(tmp_path, "skill.py", "api_key = get_key()\nprint(api_key)\n")
    out = scan(tmp_path)
    assert any(f["type"] == "agent_skill_credential_print" for f in out)
    assert out[0]["severity"] == "HIGH"


def test_fstring_with_credential_var_is_flagged(tmp_path):
    _py(tmp_path, "tool.py", 'token = "x"\nprint(f"using {token}")\n')
    out = scan(tmp_path)
    assert any(f["type"] == "agent_skill_credential_print" for f in out)


def test_logging_info_of_secret_is_flagged(tmp_path):
    _py(tmp_path, "agent.py", "import logging\nclient_secret = s()\nlogging.info(client_secret)\n")
    out = scan(tmp_path)
    assert any(f["type"] == "agent_skill_credential_print" for f in out)


def test_string_literal_mentioning_api_key_is_not_flagged(tmp_path):
    _py(tmp_path, "skill.py", 'print("api_key is configured")\n')
    assert scan(tmp_path) == []


def test_print_of_unrelated_var_is_not_flagged(tmp_path):
    _py(tmp_path, "skill.py", "count = 3\nprint(count)\n")
    assert scan(tmp_path) == []


def test_malformed_python_does_not_crash(tmp_path):
    _py(tmp_path, "broken.py", "def (:\n  print(api_key\n")
    assert scan(tmp_path) == []


def test_non_python_files_ignored(tmp_path):
    (tmp_path / "notes.md").write_text("print(api_key)\n")
    assert scan(tmp_path) == []


from gitexpose.agent_exposure import scan as agent_scan


def test_agent_scan_includes_debug_print(tmp_path):
    (tmp_path / "skill.py").write_text("api_key = k()\nprint(api_key)\n")
    findings = agent_scan(tmp_path)
    assert any(f["type"] == "agent_skill_credential_print" for f in findings)
