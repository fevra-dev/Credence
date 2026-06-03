"""Tests for the OSV.dev async client."""

import httpx
import pytest
import respx

from credence.supply_chain import Dependency
from credence.supply_chain.osv import query_osv

QUERYBATCH = "https://api.osv.dev/v1/querybatch"
VULN = "https://api.osv.dev/v1/vulns/GHSA-xxxx"


def _dep(name="lodash", version="4.17.20", eco="npm"):
    return Dependency(name=name, version=version, ecosystem=eco,
                      purl=f"pkg:npm/{name}@{version}", direct=True, source_file="package-lock.json")


@pytest.mark.asyncio
@respx.mock
async def test_query_osv_maps_vuln_to_dependency():
    respx.post(QUERYBATCH).mock(return_value=httpx.Response(
        200, json={"results": [{"vulns": [{"id": "GHSA-xxxx", "modified": "2026-01-01"}]}]}))
    respx.get(VULN).mock(return_value=httpx.Response(200, json={
        "id": "GHSA-xxxx",
        "summary": "Prototype pollution in lodash",
        "aliases": ["CVE-2020-8203"],
        "database_specific": {"severity": "HIGH"},
        "affected": [{"ranges": [{"type": "ECOSYSTEM",
                     "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
    }))
    dep = _dep()
    result = await query_osv([dep])
    vulns = result[dep.purl]
    assert vulns[0].vuln_id == "GHSA-xxxx"
    assert vulns[0].severity == "HIGH"
    assert vulns[0].fixed_version == "4.17.21"
    assert "CVE-2020-8203" in vulns[0].aliases


@pytest.mark.asyncio
@respx.mock
async def test_query_osv_no_vulns_returns_empty():
    respx.post(QUERYBATCH).mock(return_value=httpx.Response(200, json={"results": [{}]}))
    dep = _dep()
    result = await query_osv([dep])
    assert result.get(dep.purl, []) == []


@pytest.mark.asyncio
@respx.mock
async def test_query_osv_network_error_degrades_to_empty():
    respx.post(QUERYBATCH).mock(side_effect=httpx.ConnectError("down"))
    dep = _dep()
    result = await query_osv([dep])
    assert result == {}   # degrade gracefully; caller falls back to curated list


@pytest.mark.asyncio
@respx.mock
async def test_query_osv_respects_max_deps():
    route = respx.post(QUERYBATCH).mock(return_value=httpx.Response(200, json={"results": [{}]}))
    deps = [_dep(name=f"p{i}", version="1.0.0") for i in range(10)]
    await query_osv(deps, max_deps=3)
    # Only one batch request was sent (3 ≤ 1000 per batch), proving truncation happened.
    sent = route.calls.last.request
    import json as _json
    body = _json.loads(sent.content)
    assert len(body["queries"]) == 3


# --- /attack hardening (F-001 robustness, F-003 fan-out cap) ---

@pytest.mark.asyncio
@respx.mock
async def test_query_osv_malformed_querybatch_body_degrades():
    # 200 with a non-JSON body must NOT crash the scan (spec §9) — degrade.
    respx.post(QUERYBATCH).mock(return_value=httpx.Response(200, text="<html>nope</html>"))
    dep = _dep()
    result = await query_osv([dep])   # must not raise
    assert result.get(dep.purl, []) == []


@pytest.mark.asyncio
@respx.mock
async def test_query_osv_malformed_vuln_object_skips():
    # querybatch fine, but a hydration body has an unexpected shape (a JSON list,
    # so _to_vulnerability's .get() would raise) — skip that vuln, don't crash.
    respx.post(QUERYBATCH).mock(return_value=httpx.Response(
        200, json={"results": [{"vulns": [{"id": "GHSA-bad"}]}]}))
    respx.get("https://api.osv.dev/v1/vulns/GHSA-bad").mock(
        return_value=httpx.Response(200, text="[1, 2, 3]"))
    dep = _dep()
    result = await query_osv([dep])   # must not raise
    assert result.get(dep.purl, []) == []


@pytest.mark.asyncio
@respx.mock
async def test_query_osv_caps_hydration_fanout():
    # A single dep with many advisories must not amplify into unbounded GETs.
    ids = [f"GHSA-{i}" for i in range(6)]
    respx.post(QUERYBATCH).mock(return_value=httpx.Response(
        200, json={"results": [{"vulns": [{"id": i} for i in ids]}]}))
    calls = {"n": 0}

    def _vuln(request):
        calls["n"] += 1
        return httpx.Response(200, json={"id": "x", "summary": "s",
                                         "database_specific": {"severity": "LOW"}})

    respx.route(method="GET", host="api.osv.dev").mock(side_effect=_vuln)
    await query_osv([_dep()], max_deps=2)
    assert calls["n"] <= 2, f"hydration fan-out not capped: {calls['n']}"
