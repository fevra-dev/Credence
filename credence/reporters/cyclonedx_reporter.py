"""CycloneDX 1.6 AI-BOM builder for the supply-chain command.

Takes the parsed Dependency inventory + vulnerable_dependency findings and emits
a CycloneDX 1.6 JSON document with components, dependency-vulnerability VEX, and
NTIA minimum elements. VEX analysis state is honestly scoped (spec §6): default
`in_triage`; `exploitable` only when a co-present credential was verified live or
OSV flags the vuln known-exploited. We never assert `not_affected`.

Verified against cyclonedx-python-lib 11.7.0. An explicit bom_ref (= purl) is set
on each component so the VEX affects-ref reliably links to its component
(Component.bom_ref.value is None until serialization auto-assigns a UUID).
"""

from __future__ import annotations

from typing import Dict, List

from cyclonedx.model import Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.vulnerability import (
    BomTarget, Vulnerability as CdxVulnerability, VulnerabilityAdvisory,
    VulnerabilityAnalysis, VulnerabilitySource, ImpactAnalysisState,
)
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion
from packageurl import PackageURL

from ..supply_chain.models import Dependency

_TOOL_NAME = "Credence"
_TOOL_VERSION = "0.5.1"


def _vex_state(finding: Dict) -> ImpactAnalysisState:
    """Honest VEX state (spec §6): exploitable only when proven, else in_triage.

    `cred_verified_co_present` is set by the CLI after `--verify` runs: it means a
    credential in the SAME source file as this vulnerable dependency was confirmed
    live. `known_exploited` is OSV's CISA-KEV-style flag. We never assert
    not_affected (that needs reachability analysis we do not perform).
    """
    if finding.get("cred_verified_co_present") or finding.get("known_exploited"):
        return ImpactAnalysisState.EXPLOITABLE
    return ImpactAnalysisState.IN_TRIAGE


def build_bom(deps: List[Dependency], findings: List[Dict]) -> str:
    bom = Bom()
    bom.metadata.tools.components.add(
        Component(name=_TOOL_NAME, version=_TOOL_VERSION, type=ComponentType.APPLICATION)
    )

    # Components — every parsed dependency (NTIA: name, version, PURL, hash).
    # Set an EXPLICIT bom_ref (= purl) so the VEX affects-ref is stable and
    # matches the component (Component.bom_ref.value is None until serialization).
    known_purls = set()
    for dep in deps:
        comp = Component(
            name=dep.name,
            version=dep.version,
            type=ComponentType.LIBRARY,
            bom_ref=dep.purl,
            purl=PackageURL.from_string(dep.purl),
            properties=[
                Property(name="credence:direct", value=str(dep.direct).lower()),
                Property(name="credence:source", value=dep.source_file),
            ],
        )
        bom.components.add(comp)
        known_purls.add(dep.purl)

    # Vulnerabilities (VEX) from vulnerable_dependency findings.
    for f in findings:
        if f.get("type") != "vulnerable_dependency":
            continue
        purl = f.get("purl")
        advisories = []
        if f.get("advisory_url"):
            advisories.append(VulnerabilityAdvisory(url=f["advisory_url"]))
        affects = [BomTarget(ref=purl)] if purl in known_purls else []
        vuln = CdxVulnerability(
            id=f["vuln_id"],
            source=VulnerabilitySource(name="OSV", url=f.get("advisory_url")),
            description=f.get("summary"),
            advisories=advisories,
            analysis=VulnerabilityAnalysis(state=_vex_state(f)),
            affects=affects,
        )
        bom.vulnerabilities.add(vuln)

    outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_6)
    return outputter.output_as_string(indent=2)
