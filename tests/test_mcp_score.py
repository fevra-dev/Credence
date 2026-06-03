"""MCP security score: per-issue findings + INFO posture summary; score != severity."""
from credence.agent_exposure.mcp_score import score_server


def test_clean_known_https_oauth_server_scores_high():
    server = {
        "name": "stripe",
        "url": "https://mcp.stripe.com",
        "version": "1.2.3",
        "auth": "oauth",
        "env": {},
    }
    findings = score_server(server, "mcp.json")
    summary = next(f for f in findings if f["type"] == "mcp_server_posture")
    assert summary["severity"] == "INFO"
    assert summary["score"] >= 90
    assert all(f["severity"] != "HIGH" for f in findings if f["type"] != "mcp_server_posture")


def test_static_credential_is_high_and_deducts_30():
    server = {
        "name": "custom",
        "url": "https://mcp.example.com",
        "version": "1.0.0",
        "env": {"API_KEY": "sk_live_abc"},
    }
    findings = score_server(server, "mcp.json")
    issue = next(f for f in findings if f["type"] == "mcp_static_credential")
    assert issue["severity"] == "HIGH"
    summary = next(f for f in findings if f["type"] == "mcp_server_posture")
    assert summary["score"] <= 70


def test_plaintext_http_is_high():
    server = {"name": "x", "url": "http://mcp.example.com", "version": "1.0.0"}
    findings = score_server(server, "mcp.json")
    assert any(f["type"] == "mcp_plaintext_http" and f["severity"] == "HIGH" for f in findings)


def test_unknown_origin_is_low():
    server = {"name": "x", "url": "https://totally-unknown.example", "version": "1.0.0"}
    findings = score_server(server, "mcp.json")
    issue = next(f for f in findings if f["type"] == "mcp_unknown_origin")
    assert issue["severity"] == "LOW"


def test_unpinned_version_is_low():
    server = {"name": "stripe", "url": "https://mcp.stripe.com"}  # no version
    findings = score_server(server, "mcp.json")
    assert any(f["type"] == "mcp_unpinned_version" and f["severity"] == "LOW" for f in findings)


def test_posture_summary_lists_deductions_in_description():
    server = {"name": "x", "url": "https://unknown.example"}  # unknown + no pin
    findings = score_server(server, "mcp.json")
    summary = next(f for f in findings if f["type"] == "mcp_server_posture")
    assert "unknown origin" in summary["description"].lower()
    assert str(summary["score"]) in summary["description"]
    assert 0 <= summary["score"] <= 100


def test_env_var_passthrough_is_not_a_static_credential():
    # ${VAR} / $VAR passthrough is the correct secure pattern, not a leak.
    for val in ("${OPENAI_API_KEY}", "$OPENAI_API_KEY", "{{OPENAI_API_KEY}}", "<your-key-here>"):
        server = {"name": "x", "url": "https://mcp.example.com", "version": "1.0.0",
                  "env": {"OPENAI_API_KEY": val}}
        findings = score_server(server, "mcp.json")
        assert not any(f["type"] == "mcp_static_credential" for f in findings), val


def test_real_embedded_secret_value_still_fires():
    server = {"name": "x", "url": "https://mcp.example.com", "version": "1.0.0",
              "env": {"OPENAI_API_KEY": "sk_live_realembeddedsecret123"}}
    findings = score_server(server, "mcp.json")
    assert any(f["type"] == "mcp_static_credential" for f in findings)


def test_oauth_suppresses_static_credential():
    server = {"name": "x", "url": "https://mcp.stripe.com", "version": "1.0",
              "auth": "oauth", "env": {"API_KEY": "sk_live_x"}}
    findings = score_server(server, "mcp.json")
    assert not any(f["type"] == "mcp_static_credential" for f in findings)


def test_score_and_severity_are_decoupled():
    # Two LOW issues → score at most 80 (-15 unknown origin, -5 no version pin),
    # but NO high-severity finding (gate stays clean).
    server = {"name": "x", "url": "https://unknown.example"}  # unknown origin + no version pin
    findings = score_server(server, "mcp.json")
    summary = next(f for f in findings if f["type"] == "mcp_server_posture")
    assert summary["severity"] == "INFO"
    assert summary["score"] <= 80
    assert not any(f["severity"] in ("HIGH", "CRITICAL") for f in findings)


import json
from credence.agent_exposure.analyzer import analyze_configs


def test_analyze_configs_emits_mcp_posture(tmp_path):
    (tmp_path / "mcp.json").write_text(json.dumps({
        "mcpServers": {
            "weird": {"url": "http://unknown.example", "env": {"API_KEY": "sk_live_x"}}
        }
    }))
    findings = analyze_configs(tmp_path)
    types = {f["type"] for f in findings}
    assert "mcp_server_posture" in types
    assert "mcp_static_credential" in types
    assert "mcp_plaintext_http" in types


# --- v0.8.1 audit regression (F-001) ---

def test_real_credential_wrapped_in_angle_brackets_still_fires():
    # F-001: <sk_live_...> matched the placeholder regex and was suppressed, hiding a
    # live secret (angle brackets are not runtime-expanded). Must now fire.
    server = {"name": "x", "url": "https://mcp.example.com", "version": "1.0.0",
              "env": {"API_KEY": "<sk_live_51RealKeyMaterialABCDEF>"}}
    findings = score_server(server, "mcp.json")
    assert any(f["type"] == "mcp_static_credential" for f in findings)


def test_real_credential_in_curly_placeholder_still_fires():
    server = {"name": "x", "url": "https://mcp.example.com", "version": "1.0.0",
              "env": {"API_KEY": "{{ghp_RealTokenMaterial1234567890}}"}}
    findings = score_server(server, "mcp.json")
    assert any(f["type"] == "mcp_static_credential" for f in findings)


def test_named_placeholder_without_secret_is_still_suppressed():
    # Must NOT regress the original FP fix: <API_KEY> / ${OPENAI_API_KEY} stay benign.
    for val in ("<API_KEY>", "${OPENAI_API_KEY}", "$OPENAI_API_KEY", "{{ENV_VAR}}"):
        server = {"name": "x", "url": "https://mcp.example.com", "version": "1.0.0",
                  "env": {"OPENAI_API_KEY": val}}
        findings = score_server(server, "mcp.json")
        assert not any(f["type"] == "mcp_static_credential" for f in findings), val
