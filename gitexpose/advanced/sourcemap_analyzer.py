"""
Source Map & Webpack Bundle Analyzer.

Detects and exploits exposed JavaScript source maps (.map files) and
Webpack bundle configurations to recover original source code.

This is a critical security gap - many production sites accidentally
expose source maps which reveal:
- Original TypeScript/React/Vue source code
- API endpoints and keys hardcoded in frontend
- Internal business logic
- Comments with sensitive information
- Development paths and usernames
"""

import asyncio
import base64
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import aiofiles
import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class SourceMapFinding:
    """Represents a discovered source map exposure."""
    url: str
    source_map_url: str
    severity: str
    original_sources: List[str] = field(default_factory=list)
    secrets_found: List[Dict] = field(default_factory=list)
    source_count: int = 0
    total_lines: int = 0
    frameworks_detected: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


@dataclass
class RecoveredSource:
    """Represents a recovered source file."""
    path: str
    content: str
    original_url: str
    size: int
    secrets: List[Dict] = field(default_factory=list)


class SourceMapAnalyzer:
    """
    Analyze and exploit exposed JavaScript source maps.
    
    Features:
    - Detect source map references in JS files
    - Download and parse .map files
    - Reconstruct original source code
    - Extract secrets from recovered sources
    - Identify framework/library versions
    - Detect webpack/vite/rollup configurations
    """

    # Patterns to find source map references
    SOURCEMAP_PATTERNS = [
        # Standard sourceMappingURL comment
        r'//[#@]\s*sourceMappingURL\s*=\s*([^\s\'"]+)',
        r'/\*[#@]\s*sourceMappingURL\s*=\s*([^\s\'"*]+)\s*\*/',

        # X-SourceMap header reference
        r'X-SourceMap:\s*([^\s]+)',
        r'SourceMap:\s*([^\s]+)',
    ]

    # Common source map paths to check
    COMMON_SOURCEMAP_PATHS = [
        # Standard patterns
        '{js_path}.map',
        '{js_dir}/{js_name}.map',

        # Webpack patterns
        '{js_dir}/static/js/{js_name}.map',
        '{js_dir}/static/js/{js_name}.chunk.js.map',
        '{js_dir}/_next/static/chunks/{js_name}.map',

        # Build output patterns
        '{js_dir}/dist/{js_name}.map',
        '{js_dir}/build/{js_name}.map',
        '{js_dir}/bundle/{js_name}.map',
        '{js_dir}/assets/{js_name}.map',

        # Vite patterns
        '{js_dir}/assets/{js_name}.js.map',
        '{js_dir}/.vite/{js_name}.map',
    ]

    # Secrets patterns to find in recovered source
    SECRET_PATTERNS = {
        'api_key': r'(?i)(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
        'api_secret': r'(?i)(api[_-]?secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'private_key': r'-----BEGIN (?:RSA |EC |)PRIVATE KEY-----',
        'jwt_secret': r'(?i)(jwt[_-]?secret|secret[_-]?key)["\']?\s*[:=]\s*["\']([^\s"\']{10,})["\']',
        'database_url': r'(?i)(database[_-]?url|db[_-]?url)["\']?\s*[:=]\s*["\']([^\s"\']+)["\']',
        'stripe_key': r'(?:pk|sk)_(?:live|test)_[a-zA-Z0-9]{24,}',
        'firebase_key': r'AIza[0-9A-Za-z\-_]{35}',
        'oauth_secret': r'(?i)(oauth[_-]?secret|client[_-]?secret)["\']?\s*[:=]\s*["\']([^\s"\']{10,})["\']',
        'bearer_token': r'(?i)bearer\s+[a-zA-Z0-9_\-\.=]{20,}',
        'password_field': r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^\s"\']{8,})["\']',
        'internal_endpoint': r'(?i)(internal|staging|dev)[a-zA-Z0-9.-]*\.(?:com|io|net|org)/api',
    }

    # Framework detection patterns
    FRAMEWORK_PATTERNS = {
        'react': [r'react(?:-dom)?["\']:\s*["\'][\d.]+', r'from\s+["\']react["\']', r'React\.createElement'],
        'vue': [r'vue["\']:\s*["\'][\d.]+', r'from\s+["\']vue["\']', r'Vue\.component'],
        'angular': [r'@angular/core', r'from\s+["\']@angular', r'NgModule'],
        'svelte': [r'svelte["\']:\s*["\'][\d.]+', r'from\s+["\']svelte["\']'],
        'next': [r'next["\']:\s*["\'][\d.]+', r'from\s+["\']next', r'__NEXT_DATA__'],
        'nuxt': [r'nuxt["\']:\s*["\'][\d.]+', r'from\s+["\']nuxt'],
        'webpack': [r'webpackChunk', r'__webpack_require__', r'webpack/runtime'],
        'vite': [r'vite["\']:\s*["\'][\d.]+', r'/@vite/', r'__vite_'],
        'rollup': [r'rollup["\']:\s*["\'][\d.]+'],
        'typescript': [r'\.tsx?$', r'typescript', r'tslib'],
        'graphql': [r'graphql', r'__typename', r'gql`'],
    }

    def __init__(
        self,
        session: Optional[aiohttp.ClientSession] = None,
        timeout: int = 15,
        max_concurrent: int = 10,
        extract_sources: bool = True,
        scan_secrets: bool = True,
        output_dir: Optional[Path] = None
    ):
        """
        Initialize Source Map Analyzer.
        
        Args:
            session: aiohttp session (created if not provided)
            timeout: Request timeout in seconds
            max_concurrent: Maximum concurrent requests
            extract_sources: Whether to extract original sources
            scan_secrets: Whether to scan for secrets in sources
            output_dir: Directory to save recovered sources
        """
        self.session = session
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.extract_sources = extract_sources
        self.scan_secrets = scan_secrets
        self.output_dir = Path(output_dir) if output_dir else None

        self._owns_session = session is None
        self._checked_urls: Set[str] = set()

    async def __aenter__(self):
        """Async context manager entry."""
        if self._owns_session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'}
            )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._owns_session and self.session:
            await self.session.close()

    async def analyze_target(self, target_url: str) -> List[SourceMapFinding]:
        """
        Analyze a target for exposed source maps.
        
        Args:
            target_url: Target URL to analyze
            
        Returns:
            List of SourceMapFinding objects
        """
        findings = []

        # Step 1: Fetch main page and find JS files
        js_urls = await self._discover_js_files(target_url)
        logger.info(f"Discovered {len(js_urls)} JavaScript files")

        # Step 2: Check each JS file for source map references
        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks = [
            self._analyze_js_file(js_url, semaphore)
            for js_url in js_urls
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, SourceMapFinding):
                findings.append(result)

        # Step 3: Try common source map paths
        additional = await self._try_common_paths(target_url, js_urls)
        findings.extend(additional)

        return findings

    async def _discover_js_files(self, url: str) -> List[str]:
        """Discover JavaScript files from target."""
        js_urls = set()

        try:
            async with self.session.get(url, ssl=False) as resp:
                if resp.status != 200:
                    return list(js_urls)

                body = await resp.text()

                # Find script tags
                script_pattern = r'<script[^>]*src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']'
                matches = re.findall(script_pattern, body, re.IGNORECASE)

                for match in matches:
                    js_url = urljoin(url, match)
                    js_urls.add(js_url)

                # Find dynamically loaded scripts
                dynamic_patterns = [
                    r'["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
                    r'import\s*\(["\']([^"\']+)["\']',
                    r'from\s+["\']([^"\']+)["\']',
                ]

                for pattern in dynamic_patterns:
                    matches = re.findall(pattern, body)
                    for match in matches:
                        if match.endswith('.js') or '/js/' in match:
                            js_url = urljoin(url, match)
                            js_urls.add(js_url)

                # Check for Next.js/_next patterns
                if '/_next/' in body:
                    next_patterns = [
                        r'/_next/static/chunks/([^"\']+\.js)',
                        r'/_next/static/[^/]+/pages/([^"\']+\.js)',
                    ]
                    for pattern in next_patterns:
                        matches = re.findall(pattern, body)
                        for match in matches:
                            js_url = urljoin(url, f'/_next/static/chunks/{match}')
                            js_urls.add(js_url)

        except Exception as e:
            logger.debug(f"Error discovering JS files: {e}")

        return list(js_urls)

    async def _analyze_js_file(
        self,
        js_url: str,
        semaphore: asyncio.Semaphore
    ) -> Optional[SourceMapFinding]:
        """Analyze a JS file for source map references."""

        if js_url in self._checked_urls:
            return None
        self._checked_urls.add(js_url)

        async with semaphore:
            try:
                async with self.session.get(js_url, ssl=False) as resp:
                    if resp.status != 200:
                        return None

                    # Check X-SourceMap header
                    sourcemap_header = resp.headers.get('X-SourceMap') or resp.headers.get('SourceMap')

                    body = await resp.text()

                    # Find sourceMappingURL in body
                    sourcemap_url = None

                    if sourcemap_header:
                        sourcemap_url = urljoin(js_url, sourcemap_header)
                    else:
                        for pattern in self.SOURCEMAP_PATTERNS:
                            match = re.search(pattern, body[-5000:])  # Check end of file
                            if match:
                                sourcemap_ref = match.group(1)

                                # Handle data URLs
                                if sourcemap_ref.startswith('data:'):
                                    return await self._parse_inline_sourcemap(
                                        js_url, sourcemap_ref
                                    )

                                sourcemap_url = urljoin(js_url, sourcemap_ref)
                                break

                    if sourcemap_url:
                        return await self._fetch_and_analyze_sourcemap(
                            js_url, sourcemap_url
                        )

            except asyncio.TimeoutError:
                logger.debug(f"Timeout fetching {js_url}")
            except Exception as e:
                logger.debug(f"Error analyzing {js_url}: {e}")

        return None

    async def _fetch_and_analyze_sourcemap(
        self,
        js_url: str,
        sourcemap_url: str
    ) -> Optional[SourceMapFinding]:
        """Fetch and analyze a source map file."""

        try:
            async with self.session.get(sourcemap_url, ssl=False) as resp:
                if resp.status != 200:
                    return None

                content = await resp.text()

                try:
                    sourcemap = json.loads(content)
                except json.JSONDecodeError:
                    return None

                return await self._analyze_sourcemap_content(
                    js_url, sourcemap_url, sourcemap
                )

        except Exception as e:
            logger.debug(f"Error fetching source map: {e}")

        return None

    async def _parse_inline_sourcemap(
        self,
        js_url: str,
        data_url: str
    ) -> Optional[SourceMapFinding]:
        """Parse an inline base64 source map."""

        try:
            # Extract base64 content
            if 'base64,' not in data_url:
                return None

            base64_content = data_url.split('base64,')[1]
            decoded = base64.b64decode(base64_content).decode('utf-8')
            sourcemap = json.loads(decoded)

            return await self._analyze_sourcemap_content(
                js_url, f"{js_url}#inline-sourcemap", sourcemap
            )

        except Exception as e:
            logger.debug(f"Error parsing inline source map: {e}")

        return None

    async def _analyze_sourcemap_content(
        self,
        js_url: str,
        sourcemap_url: str,
        sourcemap: Dict
    ) -> SourceMapFinding:
        """Analyze source map content for sensitive information."""

        sources = sourcemap.get('sources', [])
        sources_content = sourcemap.get('sourcesContent', [])

        # Collect original source paths
        original_sources = []
        frameworks_detected = set()
        all_secrets = []
        total_lines = 0

        for i, source_path in enumerate(sources):
            original_sources.append(source_path)

            # Detect frameworks from paths
            for framework, patterns in self.FRAMEWORK_PATTERNS.items():
                if any(re.search(p, source_path, re.IGNORECASE) for p in patterns):
                    frameworks_detected.add(framework)

            # Analyze source content if available
            if i < len(sources_content) and sources_content[i]:
                content = sources_content[i]
                total_lines += content.count('\n') + 1

                # Detect frameworks from content
                for framework, patterns in self.FRAMEWORK_PATTERNS.items():
                    if any(re.search(p, content[:5000], re.IGNORECASE) for p in patterns):
                        frameworks_detected.add(framework)

                # Scan for secrets
                if self.scan_secrets:
                    secrets = self._scan_for_secrets(content, source_path)
                    all_secrets.extend(secrets)

                # Save recovered source
                if self.extract_sources and self.output_dir:
                    await self._save_recovered_source(source_path, content, js_url)

        # Calculate severity
        severity = self._calculate_severity(original_sources, all_secrets)

        return SourceMapFinding(
            url=js_url,
            source_map_url=sourcemap_url,
            severity=severity,
            original_sources=original_sources,
            secrets_found=all_secrets,
            source_count=len(sources),
            total_lines=total_lines,
            frameworks_detected=list(frameworks_detected),
            metadata={
                'version': sourcemap.get('version'),
                'file': sourcemap.get('file'),
                'sourceRoot': sourcemap.get('sourceRoot', '')
            }
        )

    def _scan_for_secrets(self, content: str, source_path: str) -> List[Dict]:
        """Scan source content for secrets."""
        secrets = []

        for secret_type, pattern in self.SECRET_PATTERNS.items():
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)

            for match in matches:
                secret_value = match.group()
                line_num = content[:match.start()].count('\n') + 1

                # Get context
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                context = content[start:end].replace('\n', ' ')

                secrets.append({
                    'type': secret_type,
                    'value': self._mask_secret(secret_value),
                    'value_full': secret_value,
                    'source_file': source_path,
                    'line': line_num,
                    'context': context
                })

        return secrets

    @staticmethod
    def _mask_secret(secret: str) -> str:
        """Mask secret for display."""
        if len(secret) <= 8:
            return secret[:2] + '*' * (len(secret) - 2)
        return secret[:4] + '*' * (len(secret) - 8) + secret[-4:]

    def _calculate_severity(
        self,
        sources: List[str],
        secrets: List[Dict]
    ) -> str:
        """Calculate severity based on exposure."""

        # Critical: Secrets found
        if secrets:
            critical_types = ['aws_key', 'private_key', 'stripe_key', 'database_url']
            if any(s['type'] in critical_types for s in secrets):
                return 'critical'
            return 'high'

        # High: Source code exposure
        sensitive_paths = [
            'config', 'settings', 'secret', 'admin', 'auth',
            'api', 'service', 'internal', 'private'
        ]

        if any(any(p in s.lower() for p in sensitive_paths) for s in sources):
            return 'high'

        # Medium: Any source exposure
        if sources:
            return 'medium'

        return 'low'

    async def _save_recovered_source(
        self,
        source_path: str,
        content: str,
        origin_url: str
    ):
        """Save recovered source to output directory."""
        if not self.output_dir:
            return

        try:
            # Clean path
            clean_path = source_path.lstrip('./')
            clean_path = re.sub(r'^(webpack://|node_modules/)', '', clean_path)

            # Create full path
            full_path = self.output_dir / clean_path
            full_path.parent.mkdir(parents=True, exist_ok=True)

            async with aiofiles.open(full_path, 'w', encoding='utf-8') as f:
                await f.write(f"// Recovered from: {origin_url}\n")
                await f.write(f"// Original path: {source_path}\n")
                await f.write("// " + "=" * 60 + "\n\n")
                await f.write(content)

            logger.debug(f"Saved recovered source: {full_path}")

        except Exception as e:
            logger.debug(f"Error saving source: {e}")

    async def _try_common_paths(
        self,
        target_url: str,
        js_urls: List[str]
    ) -> List[SourceMapFinding]:
        """Try common source map paths."""
        findings = []
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def check_path(map_url: str):
            async with semaphore:
                if map_url in self._checked_urls:
                    return None
                self._checked_urls.add(map_url)

                try:
                    async with self.session.get(map_url, ssl=False) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            try:
                                sourcemap = json.loads(content)
                                return await self._analyze_sourcemap_content(
                                    map_url.replace('.map', ''),
                                    map_url,
                                    sourcemap
                                )
                            except json.JSONDecodeError:
                                pass
                except Exception:
                    pass
                return None

        # Generate paths to check
        map_urls = set()
        base_url = urlparse(target_url)
        base = f"{base_url.scheme}://{base_url.netloc}"

        for js_url in js_urls:
            # Simple .map appending
            map_urls.add(f"{js_url}.map")

            # Parse JS path for pattern substitution
            parsed = urlparse(js_url)
            js_path = parsed.path
            js_dir = str(Path(js_path).parent)
            js_name = Path(js_path).stem

            for pattern in self.COMMON_SOURCEMAP_PATHS:
                try:
                    path = pattern.format(
                        js_path=js_path,
                        js_dir=js_dir,
                        js_name=js_name
                    )
                    map_urls.add(urljoin(base, path))
                except Exception:
                    pass

        # Check all paths
        tasks = [check_path(url) for url in map_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, SourceMapFinding):
                findings.append(result)

        return findings


def generate_sourcemap_report(findings: List[SourceMapFinding]) -> str:
    """Generate a formatted report of source map findings."""

    if not findings:
        return "No exposed source maps detected.\n"

    lines = [
        "=" * 80,
        "SOURCE MAP EXPOSURE REPORT",
        "=" * 80,
        f"\nTotal exposed source maps: {len(findings)}",
        f"Total original sources: {sum(f.source_count for f in findings)}",
        f"Total lines of code: {sum(f.total_lines for f in findings):,}",
        f"Total secrets found: {sum(len(f.secrets_found) for f in findings)}",
        ""
    ]

    for i, finding in enumerate(findings, 1):
        severity_icon = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🔵'
        }.get(finding.severity, '⚪')

        lines.append(f"\n{severity_icon} Finding #{i}")
        lines.append("-" * 60)
        lines.append(f"JS File: {finding.url}")
        lines.append(f"Source Map: {finding.source_map_url}")
        lines.append(f"Severity: {finding.severity.upper()}")
        lines.append(f"Sources: {finding.source_count} files, {finding.total_lines:,} lines")

        if finding.frameworks_detected:
            lines.append(f"Frameworks: {', '.join(finding.frameworks_detected)}")

        if finding.secrets_found:
            lines.append(f"\n⚠️  SECRETS FOUND ({len(finding.secrets_found)}):")
            for secret in finding.secrets_found[:5]:
                lines.append(f"  - [{secret['type']}] {secret['value']}")
                lines.append(f"    File: {secret['source_file']}, Line: {secret['line']}")
            if len(finding.secrets_found) > 5:
                lines.append(f"  ... and {len(finding.secrets_found) - 5} more")

        if finding.original_sources:
            lines.append("\nSource Files (showing first 10):")
            for source in finding.original_sources[:10]:
                lines.append(f"  - {source}")
            if len(finding.original_sources) > 10:
                lines.append(f"  ... and {len(finding.original_sources) - 10} more")

    lines.append("\n" + "=" * 80)
    return "\n".join(lines)
