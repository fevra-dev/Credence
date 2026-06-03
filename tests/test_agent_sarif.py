"""Tests for the agent-exposure SARIF 2.1.0 emitter."""

import json

from credence.agent_exposure.sarif import to_sarif


_FINDINGS = [
    {
        "type": "excessive_agent_capability", "capability_class": "shell_exec",
        "severity": "CRITICAL", "source": ".cursor/mcp.json",
        "description": "Agent grant 'bash' grants arbitrary shell/command execution.",
        "attack_class": "OWASP LLM08 Excessive Agency",
        "atlas_technique": "AML.T0053", "mitre_attack": "T1059",
    },
    {
        "type": "exposed_system_prompt", "severity": "HIGH", "source": "p.txt",
        "description": "Matches a known-leaked system prompt.",
        "attack_class": "OWASP LLM07 System Prompt Leakage",
        "atlas_technique": "AML.T0056", "mitre_attack": "T1552.001",
    },
]


def test_to_sarif_is_valid_sarif_210():
    doc = json.loads(to_sarif(_FINDINGS, "0.7.0"))
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert doc["runs"][0]["tool"]["driver"]["name"] == "Credence"
    assert doc["runs"][0]["tool"]["driver"]["version"] == "0.7.0"


def test_severity_maps_to_level():
    doc = json.loads(to_sarif(_FINDINGS, "0.7.0"))
    levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    assert levels["excessive_agent_capability/shell_exec"] == "error"   # CRITICAL -> error
    assert levels["exposed_system_prompt"] == "error"                    # HIGH -> error


def test_rules_carry_compliance_ids():
    doc = json.loads(to_sarif(_FINDINGS, "0.7.0"))
    rules = {r["id"]: r for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    props = rules["excessive_agent_capability/shell_exec"]["properties"]
    assert props["mitre_attack"] == "T1059"
    assert props["atlas_technique"] == "AML.T0053"


def test_results_have_file_locations():
    doc = json.loads(to_sarif(_FINDINGS, "0.7.0"))
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in doc["runs"][0]["results"]}
    assert ".cursor/mcp.json" in uris


def test_clean_scan_emits_valid_empty_sarif():
    doc = json.loads(to_sarif([], "0.7.0"))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []


def test_missing_optional_keys_do_not_crash():
    doc = json.loads(to_sarif([{"type": "x", "severity": "LOW"}], "0.7.0"))
    assert doc["runs"][0]["results"][0]["level"] == "note"
