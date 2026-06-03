"""Tests for v0.2 empirical AI-tool config path additions."""

from credence.paths_extended import get_extended_paths


def _all_path_strings():
    return {p.path for p in get_extended_paths()}


def test_continue_dev_paths_present():
    paths = _all_path_strings()
    assert ".continue/agents/new-config.yaml" in paths or any(
        p.startswith(".continue/agents/") for p in paths
    )
    assert any(p.startswith(".continue/config") for p in paths)


def test_claude_credentials_path_present():
    assert "claude/.credentials.json" in _all_path_strings()


def test_litellm_paths_present():
    assert any("litellm" in p.lower() for p in _all_path_strings())


def test_mcp_config_paths_present():
    assert "mcp.json" in _all_path_strings() or ".cursor/mcp.json" in _all_path_strings()


def test_dotnet_build_output_paths_present():
    assert any("bin/Debug" in p or "bin/Release" in p for p in _all_path_strings())


def test_drizzle_config_present():
    assert "drizzle.config.ts" in _all_path_strings()


def test_crewai_paths_present():
    paths = _all_path_strings()
    assert "agents.yaml" in paths
    assert "tasks.yaml" in paths


def test_autogen_oai_config_list_present():
    assert "OAI_CONFIG_LIST" in _all_path_strings()


def test_env_backup_variants_present():
    paths = _all_path_strings()
    assert ".env.bak" in paths
    assert ".env.local.bak" in paths


def test_get_all_paths_combined_imports_cleanly():
    """Regression: get_all_paths_combined() must not raise ImportError on call."""
    from credence.paths_extended import get_all_paths_combined
    paths = get_all_paths_combined()
    assert len(paths) > 0


def test_llm_exposure_scanner_categories_extended():
    """v0.2 expands AI_TOOL_CONFIGS with new categories."""
    from credence.advanced.llm_exposure_scanner import AI_TOOL_CONFIGS

    expected_categories = {
        "continue_dev",
        "claude_credentials",
        "litellm_proxy",
        "mcp_configs",
        "net_build_output",
        "drizzle_orm",
        "crewai_configs",
        "autogen_configs",
    }
    assert expected_categories.issubset(set(AI_TOOL_CONFIGS.keys()))


def test_llm_exposure_scanner_categories_have_owasp_atlas():
    from credence.advanced.llm_exposure_scanner import AI_TOOL_CONFIGS

    for name, cfg in AI_TOOL_CONFIGS.items():
        assert "attack_class" in cfg, f"{name} missing attack_class"
        assert "atlas_technique" in cfg, f"{name} missing atlas_technique"


def test_llm_exposure_scanner_categories_use_severity_enum():
    """AI_TOOL_CONFIGS severities are Severity enum members, not strings."""
    from credence.advanced.llm_exposure_scanner import AI_TOOL_CONFIGS, Severity

    for name, cfg in AI_TOOL_CONFIGS.items():
        assert isinstance(cfg["severity"], Severity), (
            f"{name}: severity must be Severity enum member, got "
            f"{type(cfg['severity']).__name__} ({cfg['severity']!r})"
        )
