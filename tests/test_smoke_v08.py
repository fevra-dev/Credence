"""v0.8 end-to-end smoke: all four features fire on a constructed repo.

The repo is built in tmp_path (not a committed fixture) because git refuses to
track files inside a nested .git/ directory, so a static .git/config fixture
cannot be version-controlled.
"""
import json
from pathlib import Path

from gitexpose.advanced.local_fs_scanner import LocalFilesystemScanner
from gitexpose.agent_exposure import scan as agent_scan


def _build_repo(root: Path) -> None:
    # git-metadata: credential-bearing remote URL in .git/config
    (root / ".git").mkdir(parents=True, exist_ok=True)
    (root / ".git" / "config").write_text(
        '[core]\n\trepositoryformatversion = 0\n'
        '[remote "origin"]\n'
        '\turl = https://ghp_AbCdEf0123456789AbCdEf0123456789AbCd@github.com/acme/agent.git\n'
    )
    # debug-print: a skill that prints a credential variable
    (root / "skills").mkdir(parents=True, exist_ok=True)
    (root / "skills" / "leaky_skill.py").write_text(
        "def run(api_key):\n    print(api_key)\n    return True\n"
    )
    # MCP posture: a shady server (plaintext http + static cred + unknown origin)
    (root / "mcp.json").write_text(json.dumps({
        "mcpServers": {
            "shady": {
                "url": "http://mcp.unknown.example",
                "env": {"API_KEY": "sk_live_smoke_value_not_a_placeholder"},
            }
        }
    }))


def test_supply_chain_finds_git_metadata_and_orphan(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _build_repo(repo)
    findings = LocalFilesystemScanner().scan(
        repo, track=True, registry_path=str(tmp_path / "r.json")
    )
    types = {f["type"] for f in findings}
    assert "git_config_credential_url" in types
    # The git-metadata finding carries only a MASKED token (no raw value), so it is
    # intentionally NOT fingerprinted — confirm it has no secret_value_hash.
    gitcfg = next(f for f in findings if f["type"] == "git_config_credential_url")
    assert "secret_value_hash" not in gitcfg
    # The orphan signal still fires end-to-end: the mcp.json sk_live_ value is a
    # raw-valued secret finding, so it gets a hash + an orphan_candidate band.
    hashed = [f for f in findings if f.get("secret_value_hash")]
    assert hashed, "expected at least one raw-valued secret finding to be fingerprinted"
    assert any(f.get("source_frequency") == "orphan_candidate" for f in hashed)


def test_agent_audit_finds_debug_print_and_mcp_posture(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _build_repo(repo)
    findings = agent_scan(repo)
    types = {f["type"] for f in findings}
    assert "agent_skill_credential_print" in types
    assert "mcp_server_posture" in types
    assert "mcp_static_credential" in types
    assert "mcp_plaintext_http" in types
