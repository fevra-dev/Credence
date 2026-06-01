"""Git-metadata credential scanner: structural configparser, never shells out to git."""
import base64
from pathlib import Path

from gitexpose.advanced.git_config_scanner import scan


def _write_git_config(root: Path, body: str) -> None:
    (root / ".git").mkdir(parents=True, exist_ok=True)
    (root / ".git" / "config").write_text(body)


def test_remote_url_with_ghp_token(tmp_path):
    _write_git_config(tmp_path, (
        '[remote "origin"]\n'
        '\turl = https://ghp_AbCdEf0123456789AbCdEf0123456789AbCd@github.com/o/r.git\n'
    ))
    out = scan(tmp_path)
    types = {f["type"] for f in out}
    assert "git_config_credential_url" in types
    f = next(f for f in out if f["type"] == "git_config_credential_url")
    assert f["severity"] == "CRITICAL"
    assert "ghp_" not in f["description"]  # token value must be masked in description
    assert f["attack_class"] and f["atlas_technique"]


def test_remote_url_clean_has_no_finding(tmp_path):
    _write_git_config(tmp_path, '[remote "origin"]\n\turl = https://github.com/o/r.git\n')
    assert scan(tmp_path) == []


def test_extraheader_basic_auth_base64(tmp_path):
    pat = "x:" + "g" * 52  # ":" + Azure DevOps PAT shape
    b64 = base64.b64encode(pat.encode()).decode()
    _write_git_config(tmp_path, (
        '[http "https://dev.azure.com/org"]\n'
        f'\textraHeader = AUTHORIZATION: Basic {b64}\n'
    ))
    out = scan(tmp_path)
    assert any(f["type"] == "git_config_extraheader_credential" for f in out)


def test_extraheader_garbage_base64_does_not_crash(tmp_path):
    _write_git_config(tmp_path, (
        '[http "https://dev.azure.com/org"]\n'
        '\textraHeader = AUTHORIZATION: Basic !!!not-base64!!!\n'
    ))
    scan(tmp_path)  # must not raise


def test_gitmodules_token_url_flagged_as_committed(tmp_path):
    (tmp_path / ".gitmodules").write_text(
        '[submodule "lib"]\n'
        '\tpath = lib\n'
        '\turl = https://glpat-AbCdEf0123456789AbCd@gitlab.com/o/lib.git\n'
    )
    out = scan(tmp_path)
    f = next(f for f in out if f["type"] == "gitmodules_credential_url")
    assert f["committed_to_history"] is True


def test_generic_userpass_url_is_low_confidence(tmp_path):
    _write_git_config(tmp_path, (
        '[remote "origin"]\n'
        '\turl = https://alice:s3cr3tpassword@gitea.example.com/o/r.git\n'
    ))
    out = scan(tmp_path)
    f = next(f for f in out if f["type"] == "git_config_generic_token_url")
    assert f["severity"] in ("LOW", "INFO")


def test_no_git_subprocess_on_malicious_fsmonitor(tmp_path, monkeypatch):
    # CVE-2025-41390: a malicious core.fsmonitor must never be executed.
    import subprocess
    def _boom(*a, **k):
        raise AssertionError("scan() invoked a subprocess — CVE-2025-41390 risk")
    monkeypatch.setattr(subprocess, "run", _boom)
    monkeypatch.setattr(subprocess, "Popen", _boom)
    monkeypatch.setattr(subprocess, "check_output", _boom)
    _write_git_config(tmp_path, (
        "[core]\n\tfsmonitor = \"touch /tmp/pwned\"\n"
        '[remote "origin"]\n'
        '\turl = https://ghp_AbCdEf0123456789AbCdEf0123456789AbCd@github.com/o/r.git\n'
    ))
    out = scan(tmp_path)
    assert any(f["type"] == "git_config_credential_url" for f in out)


def test_missing_git_dir_returns_empty(tmp_path):
    assert scan(tmp_path) == []


from gitexpose.advanced.local_fs_scanner import LocalFilesystemScanner


def test_local_fs_scanner_surfaces_git_metadata(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text(
        '[remote "origin"]\n'
        '\turl = https://ghp_AbCdEf0123456789AbCdEf0123456789AbCd@github.com/o/r.git\n'
    )
    findings = LocalFilesystemScanner().scan(tmp_path)
    assert any(f["type"] == "git_config_credential_url" for f in findings)
