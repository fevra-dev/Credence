#!/usr/bin/env python3
"""
React2Shell Detector - CVE-2025-55182 Detection Module

Detects exposed React Server Components (RSC) endpoints and Flight protocol
configurations that may be vulnerable to the React2Shell RCE vulnerability.

The React2Shell vulnerability exploits insecure deserialization in the React
Flight protocol's reviveModel function, allowing unauthenticated RCE through
a single crafted HTTP request.

Author: Credence Security Research
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import aiohttp


class VulnerabilityStatus(Enum):
    """Vulnerability assessment status"""
    VULNERABLE = "vulnerable"
    POTENTIALLY_VULNERABLE = "potentially_vulnerable"
    LIKELY_SAFE = "likely_safe"
    UNKNOWN = "unknown"


class FrameworkType(Enum):
    """Detected framework type"""
    NEXTJS = "nextjs"
    REMIX = "remix"
    GATSBY = "gatsby"
    REACT_NATIVE_WEB = "react_native_web"
    CUSTOM_RSC = "custom_rsc"
    UNKNOWN = "unknown"


@dataclass
class RSCEndpoint:
    """Represents a discovered RSC endpoint"""
    url: str
    endpoint_type: str
    framework: FrameworkType
    version: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    response_indicators: List[str] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class React2ShellFinding:
    """Represents a React2Shell vulnerability finding"""
    target: str
    status: VulnerabilityStatus
    framework: FrameworkType
    framework_version: Optional[str]
    endpoints: List[RSCEndpoint]
    evidence: List[str]
    risk_score: float
    recommendations: List[str]
    cve_id: str = "CVE-2025-55182"
    cvss_score: float = 10.0


class React2ShellDetector:
    """
    Detects React Server Components vulnerabilities including React2Shell (CVE-2025-55182).
    
    The detector performs multi-stage analysis:
    1. Framework fingerprinting (Next.js, Remix, etc.)
    2. RSC endpoint discovery
    3. Flight protocol exposure detection
    4. Version extraction for CVE correlation
    5. Risk scoring based on configuration exposure
    """

    # RSC/Flight protocol indicators
    FLIGHT_INDICATORS = [
        b'0:',  # Flight chunk prefix
        b'"$@',  # Flight reference marker
        b'"$L',  # Flight lazy reference
        b'"$F',  # Flight function reference
        b'"$undefined',
        b'$ACTION_',
    ]

    # Next.js specific paths
    NEXTJS_PATHS = [
        "/_next/static/chunks/",
        "/_next/static/css/",
        "/_next/data/",
        "/.next/server/",
        "/.next/static/",
        "/.next/build-manifest.json",
        "/.next/react-loadable-manifest.json",
        "/.next/server/pages-manifest.json",
        "/.next/server/middleware-manifest.json",
        "/.next/server/app-paths-manifest.json",
        "/.next/prerender-manifest.json",
        "/.next/routes-manifest.json",
        "/.next/required-server-files.json",
        "/next.config.js",
        "/next.config.mjs",
    ]

    # RSC-specific endpoints
    RSC_ENDPOINTS = [
        "/?_rsc=",  # RSC query parameter
        "/__rsc",
        "/api/__nextauth/",
        "/api/auth/",
        "/_next/image",
        "/_next/static/chunks/app/",
        "/_next/static/chunks/pages/",
    ]

    # Vulnerable version patterns
    VULNERABLE_VERSIONS = {
        "nextjs": [
            (13, 0, 0), (13, 5, 7),   # Next.js 13.x vulnerable range
            (14, 0, 0), (14, 2, 15),  # Next.js 14.x vulnerable range
            (15, 0, 0), (15, 0, 3),   # Next.js 15.x vulnerable range
        ],
        "react": [
            (18, 3, 0), (18, 3, 1),   # React 18.3.x with RSC
            (19, 0, 0), (19, 0, 0),   # React 19 canary builds
        ]
    }

    # Headers that indicate RSC/Flight usage
    RSC_HEADERS = {
        "rsc": ["1", "true"],
        "next-router-state-tree": None,  # Any value
        "next-router-prefetch": None,
        "next-url": None,
        "x-nextjs-data": None,
    }

    def __init__(
        self,
        timeout: int = 15,
        max_concurrent: int = 20,
        deep_scan: bool = True,
        verify_ssl: bool = False
    ):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_concurrent = max_concurrent
        self.deep_scan = deep_scan
        self.verify_ssl = verify_ssl
        self.semaphore = asyncio.Semaphore(max_concurrent)

        # Detection cache
        self._cache: Dict[str, Any] = {}

    async def scan(
        self,
        target: str,
        session: Optional[aiohttp.ClientSession] = None
    ) -> React2ShellFinding:
        """
        Perform comprehensive React2Shell vulnerability scan.
        
        Args:
            target: Base URL to scan
            session: Optional aiohttp session
            
        Returns:
            React2ShellFinding with vulnerability assessment
        """
        own_session = session is None
        if own_session:
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl, limit=self.max_concurrent)
            session = aiohttp.ClientSession(connector=connector, timeout=self.timeout)

        try:
            # Normalize target URL
            target = self._normalize_url(target)

            # Stage 1: Framework fingerprinting
            framework, version = await self._fingerprint_framework(target, session)

            # Stage 2: Discover RSC endpoints
            endpoints = await self._discover_rsc_endpoints(target, session, framework)

            # Stage 3: Check Flight protocol exposure
            flight_exposed = await self._check_flight_exposure(target, session, endpoints)

            # Stage 4: Analyze server configuration exposure
            config_exposure = await self._analyze_config_exposure(target, session)

            # Stage 5: Calculate risk and generate finding
            finding = self._generate_finding(
                target=target,
                framework=framework,
                version=version,
                endpoints=endpoints,
                flight_exposed=flight_exposed,
                config_exposure=config_exposure
            )

            return finding

        finally:
            if own_session:
                await session.close()

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for consistent scanning"""
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        return url.rstrip('/')

    async def _fingerprint_framework(
        self,
        target: str,
        session: aiohttp.ClientSession
    ) -> Tuple[FrameworkType, Optional[str]]:
        """
        Identify the React framework and version in use.
        
        Fingerprints:
        - Next.js: /_next/ paths, __NEXT_DATA__, specific headers
        - Remix: __remixContext, remix manifest
        - Gatsby: __GATSBY global, gatsby-* paths
        """
        framework = FrameworkType.UNKNOWN
        version = None

        try:
            async with self.semaphore:
                async with session.get(target) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        headers = dict(resp.headers)

                        # Check for Next.js
                        if self._is_nextjs(body, headers):
                            framework = FrameworkType.NEXTJS
                            version = self._extract_nextjs_version(body, headers)

                        # Check for Remix
                        elif '__remixContext' in body or 'remix' in body.lower():
                            framework = FrameworkType.REMIX
                            version = self._extract_remix_version(body)

                        # Check for Gatsby
                        elif '__GATSBY' in body or 'gatsby' in str(headers):
                            framework = FrameworkType.GATSBY

                        # Check for generic RSC usage
                        elif any(indicator.decode() in body for indicator in self.FLIGHT_INDICATORS if isinstance(indicator, bytes)):
                            framework = FrameworkType.CUSTOM_RSC

            # Deep scan for build manifests
            if self.deep_scan and framework == FrameworkType.NEXTJS:
                version = await self._deep_version_extraction(target, session) or version

        except Exception:
            pass

        return framework, version

    def _is_nextjs(self, body: str, headers: Dict) -> bool:
        """Check if the target is using Next.js"""
        indicators = [
            '__NEXT_DATA__' in body,
            '_next/static' in body,
            'next/dist' in body,
            headers.get('x-powered-by', '').lower() == 'next.js',
            'x-nextjs-cache' in headers,
            '_buildManifest.js' in body,
        ]
        return any(indicators)

    def _extract_nextjs_version(self, body: str, headers: Dict) -> Optional[str]:
        """Extract Next.js version from response"""
        patterns = [
            r'next@([\d.]+)',
            r'next/([\d.]+)',
            r'"version":\s*"([\d.]+)"',
            r'_next/static/chunks/webpack-([\w]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, body)
            if match:
                return match.group(1)

        # Check headers
        if 'x-nextjs-cache' in headers:
            # Version might be in other headers
            pass

        return None

    def _extract_remix_version(self, body: str) -> Optional[str]:
        """Extract Remix version from response"""
        pattern = r'remix@([\d.]+)'
        match = re.search(pattern, body)
        return match.group(1) if match else None

    async def _deep_version_extraction(
        self,
        target: str,
        session: aiohttp.ClientSession
    ) -> Optional[str]:
        """Deep extraction of version from build manifests"""
        manifest_paths = [
            "/.next/build-manifest.json",
            "/_next/static/chunks/webpack.js",
            "/.next/required-server-files.json",
        ]

        for path in manifest_paths:
            try:
                url = urljoin(target, path)
                async with self.semaphore:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            content = await resp.text()

                            # Parse JSON manifests
                            if path.endswith('.json'):
                                try:
                                    data = json.loads(content)
                                    if 'version' in data:
                                        return data['version']
                                    if 'config' in data and 'version' in data['config']:
                                        return data['config']['version']
                                except json.JSONDecodeError:
                                    pass

                            # Extract from JS bundles
                            version_match = re.search(r'version["\']?\s*[:=]\s*["\']?([\d.]+)', content)
                            if version_match:
                                return version_match.group(1)

            except Exception:
                continue

        return None

    async def _discover_rsc_endpoints(
        self,
        target: str,
        session: aiohttp.ClientSession,
        framework: FrameworkType
    ) -> List[RSCEndpoint]:
        """
        Discover exposed RSC endpoints.
        
        Scans for:
        - Direct RSC API endpoints
        - Server action endpoints
        - Flight protocol endpoints
        - Build artifacts with server code
        """
        endpoints: List[RSCEndpoint] = []

        # Combine framework-specific and generic paths
        paths_to_check = list(self.RSC_ENDPOINTS)

        if framework == FrameworkType.NEXTJS:
            paths_to_check.extend(self.NEXTJS_PATHS)

        # Scan paths concurrently
        tasks = []
        for path in paths_to_check:
            tasks.append(self._check_endpoint(target, path, session, framework))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, RSCEndpoint):
                endpoints.append(result)

        # Check for RSC with special headers
        rsc_header_endpoints = await self._probe_rsc_headers(target, session, framework)
        endpoints.extend(rsc_header_endpoints)

        return endpoints

    async def _check_endpoint(
        self,
        target: str,
        path: str,
        session: aiohttp.ClientSession,
        framework: FrameworkType
    ) -> Optional[RSCEndpoint]:
        """Check if a specific endpoint exists and analyze it"""
        url = urljoin(target, path)

        try:
            async with self.semaphore:
                async with session.get(url) as resp:
                    if resp.status in [200, 304]:
                        content = await resp.read()
                        headers = dict(resp.headers)

                        # Analyze response for RSC indicators
                        indicators = self._analyze_response_indicators(content, headers)

                        if indicators or self._is_sensitive_path(path):
                            risk_score = self._calculate_endpoint_risk(path, indicators, headers)

                            return RSCEndpoint(
                                url=url,
                                endpoint_type=self._classify_endpoint(path),
                                framework=framework,
                                headers=headers,
                                response_indicators=indicators,
                                risk_score=risk_score
                            )
        except Exception:
            pass

        return None

    def _analyze_response_indicators(
        self,
        content: bytes,
        headers: Dict[str, str]
    ) -> List[str]:
        """Analyze response for RSC/Flight protocol indicators"""
        indicators = []

        # Check for Flight protocol chunks
        for indicator in self.FLIGHT_INDICATORS:
            if indicator in content:
                indicators.append(f"flight_chunk:{indicator.decode('utf-8', errors='ignore')}")

        # Check content type
        content_type = headers.get('content-type', '')
        if 'text/x-component' in content_type:
            indicators.append("rsc_content_type")
        if 'application/rsc' in content_type:
            indicators.append("rsc_mime_type")

        # Check for server action exports
        if b'$ACTION_' in content or b'$$ACTION_' in content:
            indicators.append("server_actions_exposed")

        # Check for serialized references
        if b'"$Sreact.' in content:
            indicators.append("react_server_reference")

        # Check for module references that could be exploited
        if b'__webpack_require__' in content and b'server' in content.lower():
            indicators.append("server_module_exposure")

        return indicators

    def _is_sensitive_path(self, path: str) -> bool:
        """Check if path is inherently sensitive"""
        sensitive_patterns = [
            '.next/server/',
            'server-reference-manifest',
            'app-paths-manifest',
            'middleware-manifest',
            'required-server-files',
        ]
        return any(pattern in path for pattern in sensitive_patterns)

    def _classify_endpoint(self, path: str) -> str:
        """Classify the type of endpoint"""
        if 'manifest' in path:
            return "build_manifest"
        elif 'server' in path:
            return "server_artifact"
        elif '_rsc' in path or 'rsc' in path:
            return "rsc_endpoint"
        elif 'action' in path.lower():
            return "server_action"
        elif 'static' in path:
            return "static_asset"
        else:
            return "unknown"

    def _calculate_endpoint_risk(
        self,
        path: str,
        indicators: List[str],
        headers: Dict[str, str]
    ) -> float:
        """Calculate risk score for an endpoint (0.0 - 10.0)"""
        score = 0.0

        # Base scores for path types
        if '.next/server/' in path:
            score += 4.0
        elif 'manifest' in path:
            score += 2.5
        elif '_rsc' in path:
            score += 3.0

        # Indicator-based scoring
        indicator_scores = {
            "server_actions_exposed": 3.0,
            "react_server_reference": 2.5,
            "flight_chunk": 2.0,
            "rsc_content_type": 1.5,
            "server_module_exposure": 2.0,
        }

        for indicator in indicators:
            for key, value in indicator_scores.items():
                if key in indicator:
                    score += value

        # Cap at 10.0
        return min(score, 10.0)

    async def _probe_rsc_headers(
        self,
        target: str,
        session: aiohttp.ClientSession,
        framework: FrameworkType
    ) -> List[RSCEndpoint]:
        """Probe for RSC endpoints using special headers"""
        endpoints = []

        # RSC request headers that trigger server component rendering
        rsc_headers = {
            "RSC": "1",
            "Next-Router-State-Tree": "%5B%22%22%5D",
            "Next-Router-Prefetch": "1",
            "Accept": "text/x-component",
        }

        try:
            async with self.semaphore:
                async with session.get(target, headers=rsc_headers) as resp:
                    content = await resp.read()
                    response_headers = dict(resp.headers)

                    # Check if response differs with RSC headers
                    indicators = self._analyze_response_indicators(content, response_headers)

                    if indicators:
                        endpoints.append(RSCEndpoint(
                            url=target,
                            endpoint_type="rsc_triggered",
                            framework=framework,
                            headers=response_headers,
                            response_indicators=indicators,
                            risk_score=self._calculate_endpoint_risk("/_rsc", indicators, response_headers)
                        ))
        except Exception:
            pass

        return endpoints

    async def _check_flight_exposure(
        self,
        target: str,
        session: aiohttp.ClientSession,
        endpoints: List[RSCEndpoint]
    ) -> bool:
        """
        Check for direct Flight protocol exposure.
        
        The Flight protocol serialization format can be exploited
        if the reviveModel function doesn't properly validate types.
        """
        flight_exposed = False

        # Check if any endpoint returns Flight protocol data
        for endpoint in endpoints:
            if any('flight' in ind.lower() for ind in endpoint.response_indicators):
                flight_exposed = True
                break
            if 'text/x-component' in str(endpoint.headers.get('content-type', '')):
                flight_exposed = True
                break

        # Additional probing with malformed Flight data
        if self.deep_scan:
            test_payloads = [
                '0:["$","div",null,{}]',  # Basic Flight chunk
                '1:{"id":"test","chunks":[],"name":""}',  # Module reference
            ]

            for payload in test_payloads:
                try:
                    headers = {
                        "Content-Type": "text/x-component",
                        "RSC": "1",
                    }
                    async with self.semaphore:
                        async with session.post(
                            target,
                            data=payload.encode(),
                            headers=headers
                        ) as resp:
                            if resp.status != 400:
                                # Server accepted Flight-like data
                                flight_exposed = True
                                break
                except Exception:
                    pass

        return flight_exposed

    async def _analyze_config_exposure(
        self,
        target: str,
        session: aiohttp.ClientSession
    ) -> Dict[str, Any]:
        """Analyze exposed configuration files for security issues"""
        exposure = {
            "server_files_exposed": False,
            "env_variables_leaked": False,
            "internal_paths_revealed": False,
            "exposed_files": [],
        }

        config_paths = [
            ("/.next/required-server-files.json", "server_config"),
            ("/.next/prerender-manifest.json", "prerender_config"),
            ("/next.config.js", "next_config"),
            ("/.env", "environment"),
            ("/.env.local", "environment"),
            ("/.env.production", "environment"),
        ]

        for path, config_type in config_paths:
            try:
                url = urljoin(target, path)
                async with self.semaphore:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            exposure["exposed_files"].append({
                                "path": path,
                                "type": config_type,
                                "size": len(content),
                            })

                            if config_type == "server_config":
                                exposure["server_files_exposed"] = True
                            elif config_type == "environment":
                                exposure["env_variables_leaked"] = True

                            # Check for internal path disclosure
                            if re.search(r'(/home/|/var/|/app/|/src/)', content):
                                exposure["internal_paths_revealed"] = True
            except Exception:
                continue

        return exposure

    def _generate_finding(
        self,
        target: str,
        framework: FrameworkType,
        version: Optional[str],
        endpoints: List[RSCEndpoint],
        flight_exposed: bool,
        config_exposure: Dict[str, Any]
    ) -> React2ShellFinding:
        """Generate comprehensive vulnerability finding"""
        evidence = []
        recommendations = []

        # Determine vulnerability status
        status = VulnerabilityStatus.UNKNOWN
        risk_score = 0.0

        # Check if framework version is vulnerable
        if framework == FrameworkType.NEXTJS and version:
            if self._is_version_vulnerable(version, "nextjs"):
                status = VulnerabilityStatus.VULNERABLE
                risk_score = 9.5
                evidence.append(f"Next.js version {version} is in vulnerable range for CVE-2025-55182")

        # Flight protocol exposure is critical
        if flight_exposed:
            risk_score = max(risk_score, 8.0)
            if status != VulnerabilityStatus.VULNERABLE:
                status = VulnerabilityStatus.POTENTIALLY_VULNERABLE
            evidence.append("Flight protocol endpoints are exposed and accepting requests")

        # Server configuration exposure
        if config_exposure["server_files_exposed"]:
            risk_score = max(risk_score, 7.0)
            status = VulnerabilityStatus.POTENTIALLY_VULNERABLE if status == VulnerabilityStatus.UNKNOWN else status
            evidence.append("Server-side configuration files are publicly accessible")

        if config_exposure["env_variables_leaked"]:
            risk_score = max(risk_score, 9.0)
            evidence.append("Environment variables may be exposed")

        # Analyze endpoints
        high_risk_endpoints = [e for e in endpoints if e.risk_score >= 5.0]
        if high_risk_endpoints:
            risk_score = max(risk_score, max(e.risk_score for e in high_risk_endpoints))
            status = VulnerabilityStatus.POTENTIALLY_VULNERABLE if status == VulnerabilityStatus.UNKNOWN else status
            evidence.append(f"Found {len(high_risk_endpoints)} high-risk RSC endpoints")

        # Generate recommendations
        if status in [VulnerabilityStatus.VULNERABLE, VulnerabilityStatus.POTENTIALLY_VULNERABLE]:
            recommendations.extend([
                "Upgrade to the latest patched version of Next.js/React immediately",
                "Block public access to /.next/ directory via web server configuration",
                "Implement strict Content-Security-Policy headers",
                "Review and restrict server action exports",
                "Enable React's production mode to minimize exposed internals",
            ])

        if config_exposure["server_files_exposed"]:
            recommendations.append("Configure web server to deny access to build artifacts")

        if not endpoints and not flight_exposed:
            status = VulnerabilityStatus.LIKELY_SAFE
            risk_score = min(risk_score, 2.0)

        return React2ShellFinding(
            target=target,
            status=status,
            framework=framework,
            framework_version=version,
            endpoints=endpoints,
            evidence=evidence,
            risk_score=risk_score,
            recommendations=recommendations,
        )

    def _is_version_vulnerable(self, version: str, framework: str) -> bool:
        """Check if version is in vulnerable range"""
        try:
            parts = tuple(int(p) for p in version.split('.')[:3])

            ranges = self.VULNERABLE_VERSIONS.get(framework, [])
            for i in range(0, len(ranges), 2):
                min_ver = ranges[i]
                max_ver = ranges[i + 1] if i + 1 < len(ranges) else ranges[i]

                if min_ver <= parts <= max_ver:
                    return True
        except (ValueError, IndexError):
            pass

        return False

    def generate_report(self, finding: React2ShellFinding) -> str:
        """Generate human-readable report"""
        lines = [
            "=" * 70,
            "REACT2SHELL VULNERABILITY ASSESSMENT",
            f"Target: {finding.target}",
            f"CVE: {finding.cve_id} (CVSS: {finding.cvss_score})",
            "=" * 70,
            "",
            f"Status: {finding.status.value.upper()}",
            f"Framework: {finding.framework.value}",
            f"Version: {finding.framework_version or 'Unknown'}",
            f"Risk Score: {finding.risk_score:.1f}/10.0",
            "",
        ]

        if finding.evidence:
            lines.append("EVIDENCE:")
            for item in finding.evidence:
                lines.append(f"  • {item}")
            lines.append("")

        if finding.endpoints:
            lines.append(f"DISCOVERED ENDPOINTS ({len(finding.endpoints)}):")
            for endpoint in sorted(finding.endpoints, key=lambda e: -e.risk_score)[:10]:
                lines.append(f"  [{endpoint.risk_score:.1f}] {endpoint.url}")
                lines.append(f"       Type: {endpoint.endpoint_type}")
                if endpoint.response_indicators:
                    lines.append(f"       Indicators: {', '.join(endpoint.response_indicators[:3])}")
            lines.append("")

        if finding.recommendations:
            lines.append("RECOMMENDATIONS:")
            for rec in finding.recommendations:
                lines.append(f"  ⚠ {rec}")
            lines.append("")

        lines.append("=" * 70)
        return "\n".join(lines)


async def main():
    """CLI entry point for standalone usage"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python react2shell_detector.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    detector = React2ShellDetector(deep_scan=True)

    print(f"[*] Scanning {target} for React2Shell vulnerability...")
    finding = await detector.scan(target)
    print(detector.generate_report(finding))


if __name__ == "__main__":
    asyncio.run(main())
