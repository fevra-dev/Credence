"""
API Endpoint Discovery & Analysis.

Discovers and analyzes exposed API endpoints:
- GraphQL introspection
- OpenAPI/Swagger documentation
- REST API endpoints
- WebSocket endpoints
- Debug/internal endpoints

This module identifies attack surfaces and potential vulnerabilities
in exposed API infrastructure.
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin

import aiohttp

logger = logging.getLogger(__name__)


class APIType(Enum):
    """Supported API types."""
    GRAPHQL = "graphql"
    REST = "rest"
    OPENAPI = "openapi"
    SWAGGER = "swagger"
    WEBSOCKET = "websocket"
    GRPC = "grpc"
    UNKNOWN = "unknown"


class SecurityIssue(Enum):
    """API security issues."""
    INTROSPECTION_ENABLED = "introspection_enabled"
    NO_AUTHENTICATION = "no_authentication"
    VERBOSE_ERRORS = "verbose_errors"
    DEBUG_MODE = "debug_mode"
    INTERNAL_ENDPOINT = "internal_endpoint"
    SENSITIVE_OPERATION = "sensitive_operation"
    CORS_MISCONFIGURED = "cors_misconfigured"
    RATE_LIMIT_ABSENT = "rate_limit_absent"


@dataclass
class APIEndpoint:
    """Represents a discovered API endpoint."""
    path: str
    method: str
    description: str = ""
    parameters: List[Dict] = field(default_factory=list)
    authentication: Optional[str] = None
    deprecated: bool = False


@dataclass
class APIFinding:
    """Represents a discovered API exposure."""
    api_type: APIType
    url: str
    severity: str
    endpoints: List[APIEndpoint] = field(default_factory=list)
    security_issues: List[str] = field(default_factory=list)
    types_exposed: List[str] = field(default_factory=list)
    mutations_found: List[str] = field(default_factory=list)
    queries_found: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


class APIDiscovery:
    """
    Discover and analyze exposed API endpoints.
    
    Features:
    - GraphQL introspection query execution
    - OpenAPI/Swagger specification parsing
    - REST endpoint enumeration
    - WebSocket endpoint detection
    - Authentication bypass detection
    - Sensitive operation identification
    """

    # Common API paths to probe
    API_PATHS = {
        APIType.GRAPHQL: [
            '/graphql',
            '/graphql/',
            '/api/graphql',
            '/v1/graphql',
            '/graphql/v1',
            '/query',
            '/gql',
            '/__graphql',
            '/graphiql',
            '/playground',
            '/altair',
        ],

        APIType.OPENAPI: [
            '/openapi.json',
            '/openapi.yaml',
            '/openapi.yml',
            '/api/openapi.json',
            '/api-docs.json',
            '/v3/api-docs',
            '/v2/api-docs',
        ],

        APIType.SWAGGER: [
            '/swagger.json',
            '/swagger.yaml',
            '/swagger.yml',
            '/swagger-ui.html',
            '/swagger-ui/',
            '/api/swagger.json',
            '/swagger/v1/swagger.json',
            '/api-docs',
            '/docs',
            '/documentation',
            '/redoc',
        ],

        APIType.REST: [
            '/api',
            '/api/',
            '/api/v1',
            '/api/v2',
            '/api/v3',
            '/v1',
            '/v2',
            '/rest',
            '/rest/api',
        ],

        APIType.WEBSOCKET: [
            '/ws',
            '/websocket',
            '/socket.io',
            '/sockjs',
            '/realtime',
            '/live',
        ],
    }

    # GraphQL introspection query
    GRAPHQL_INTROSPECTION_QUERY = """
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                name
                kind
                description
                fields {
                    name
                    description
                    args {
                        name
                        type { name kind }
                    }
                    type { name kind }
                }
            }
            directives { name description }
        }
    }
    """

    # Simplified introspection for quick check
    GRAPHQL_QUICK_INTROSPECTION = """
    query { __typename }
    """

    # Sensitive GraphQL operation patterns
    SENSITIVE_GRAPHQL_OPERATIONS = [
        'createUser', 'deleteUser', 'updateUser', 'registerUser',
        'login', 'logout', 'authenticate', 'resetPassword',
        'createAdmin', 'promoteToAdmin', 'grantRole',
        'deleteAll', 'dropDatabase', 'truncate',
        'payment', 'charge', 'refund', 'transfer',
        'upload', 'importData', 'exportData',
        'debug', 'internal', 'admin', 'system',
        'executeQuery', 'runScript', 'evaluate',
    ]

    # Sensitive REST endpoint patterns
    SENSITIVE_REST_PATTERNS = [
        r'/admin', r'/debug', r'/internal', r'/system',
        r'/users?/\d+', r'/accounts?/', r'/profiles?/',
        r'/payments?/', r'/orders?/', r'/transactions?/',
        r'/config', r'/settings', r'/preferences',
        r'/export', r'/import', r'/backup', r'/restore',
        r'/logs?', r'/metrics', r'/health', r'/status',
        r'/tokens?', r'/sessions?', r'/auth',
    ]

    def __init__(
        self,
        session: Optional[aiohttp.ClientSession] = None,
        timeout: int = 15,
        max_concurrent: int = 10,
        full_introspection: bool = True,
        check_authentication: bool = True
    ):
        """
        Initialize API Discovery.
        
        Args:
            session: aiohttp session (created if not provided)
            timeout: Request timeout in seconds
            max_concurrent: Maximum concurrent requests
            full_introspection: Whether to run full GraphQL introspection
            check_authentication: Whether to check for authentication
        """
        self.session = session
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.full_introspection = full_introspection
        self.check_authentication = check_authentication

        self._owns_session = session is None
        self._checked_urls: Set[str] = set()

    async def __aenter__(self):
        """Async context manager entry."""
        if self._owns_session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={
                    'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                }
            )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._owns_session and self.session:
            await self.session.close()

    async def discover(self, target_url: str) -> List[APIFinding]:
        """
        Discover API endpoints on target.
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            List of APIFinding objects
        """
        findings = []
        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks = []

        # Generate all paths to check
        for api_type, paths in self.API_PATHS.items():
            for path in paths:
                url = urljoin(target_url.rstrip('/'), path)
                tasks.append(self._check_endpoint(url, api_type, semaphore))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, APIFinding):
                findings.append(result)

        # Deduplicate and merge findings
        findings = self._deduplicate_findings(findings)

        logger.info(f"Discovered {len(findings)} API endpoints")
        return findings

    async def _check_endpoint(
        self,
        url: str,
        api_type: APIType,
        semaphore: asyncio.Semaphore
    ) -> Optional[APIFinding]:
        """Check a single API endpoint."""

        if url in self._checked_urls:
            return None
        self._checked_urls.add(url)

        async with semaphore:
            try:
                if api_type == APIType.GRAPHQL:
                    return await self._check_graphql(url)
                elif api_type in (APIType.OPENAPI, APIType.SWAGGER):
                    return await self._check_openapi(url, api_type)
                elif api_type == APIType.REST:
                    return await self._check_rest(url)
                elif api_type == APIType.WEBSOCKET:
                    return await self._check_websocket(url)

            except asyncio.TimeoutError:
                logger.debug(f"Timeout checking {url}")
            except Exception as e:
                logger.debug(f"Error checking {url}: {e}")

        return None

    async def _check_graphql(self, url: str) -> Optional[APIFinding]:
        """Check for GraphQL endpoint with introspection."""

        # First, quick check if GraphQL endpoint exists
        try:
            quick_query = {"query": self.GRAPHQL_QUICK_INTROSPECTION}

            async with self.session.post(url, json=quick_query, ssl=False) as resp:
                if resp.status not in (200, 400):  # GraphQL often returns 400 for bad queries
                    return None

                body = await resp.text()

                # Check if this looks like GraphQL response
                if '__typename' not in body and 'errors' not in body.lower():
                    return None
        except Exception:
            return None

        # Run full introspection if enabled
        security_issues = [SecurityIssue.INTROSPECTION_ENABLED.value]
        types_exposed = []
        queries = []
        mutations = []

        if self.full_introspection:
            try:
                intro_query = {"query": self.GRAPHQL_INTROSPECTION_QUERY}

                async with self.session.post(url, json=intro_query, ssl=False) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        schema = data.get('data', {}).get('__schema', {})

                        # Extract types
                        for t in schema.get('types', []):
                            type_name = t.get('name', '')
                            if not type_name.startswith('__'):
                                types_exposed.append(type_name)

                                # Check for sensitive operations
                                for field in t.get('fields', []) or []:
                                    field_name = field.get('name', '')

                                    if t.get('name') == schema.get('queryType', {}).get('name'):
                                        queries.append(field_name)
                                    elif t.get('name') == schema.get('mutationType', {}).get('name'):
                                        mutations.append(field_name)

                                        # Check for sensitive mutations
                                        if any(s.lower() in field_name.lower()
                                               for s in self.SENSITIVE_GRAPHQL_OPERATIONS):
                                            security_issues.append(
                                                f"sensitive_mutation:{field_name}"
                                            )

            except Exception as e:
                logger.debug(f"Error during introspection: {e}")

        # Check for authentication
        if self.check_authentication:
            if await self._check_no_auth(url, 'graphql'):
                security_issues.append(SecurityIssue.NO_AUTHENTICATION.value)

        severity = self._calculate_graphql_severity(security_issues, mutations)

        return APIFinding(
            api_type=APIType.GRAPHQL,
            url=url,
            severity=severity,
            security_issues=security_issues,
            types_exposed=types_exposed[:50],  # Limit
            mutations_found=mutations,
            queries_found=queries,
            metadata={
                'introspection_enabled': True,
                'types_count': len(types_exposed),
                'mutations_count': len(mutations),
                'queries_count': len(queries),
            }
        )

    async def _check_openapi(
        self,
        url: str,
        api_type: APIType
    ) -> Optional[APIFinding]:
        """Check for OpenAPI/Swagger specification."""

        try:
            async with self.session.get(url, ssl=False) as resp:
                if resp.status != 200:
                    return None

                content_type = resp.headers.get('Content-Type', '')
                body = await resp.text()

                # Parse spec
                spec = None
                try:
                    if 'json' in content_type or body.strip().startswith('{'):
                        spec = json.loads(body)
                    else:
                        # Try YAML
                        try:
                            import yaml
                            spec = yaml.safe_load(body)
                        except ImportError:
                            pass
                except Exception:
                    return None

                if not spec:
                    return None

                # Validate it's an OpenAPI spec
                if not any(k in spec for k in ['swagger', 'openapi', 'paths']):
                    return None

                # Extract endpoints
                endpoints = []
                security_issues = []

                paths = spec.get('paths', {})
                for path, methods in paths.items():
                    if isinstance(methods, dict):
                        for method, details in methods.items():
                            if method.lower() in ('get', 'post', 'put', 'delete', 'patch'):
                                endpoint = APIEndpoint(
                                    path=path,
                                    method=method.upper(),
                                    description=details.get('summary', ''),
                                    deprecated=details.get('deprecated', False),
                                )

                                # Check for auth
                                if not details.get('security'):
                                    endpoint.authentication = 'none'

                                endpoints.append(endpoint)

                                # Check for sensitive paths
                                if any(re.search(p, path) for p in self.SENSITIVE_REST_PATTERNS):
                                    security_issues.append(f"sensitive_endpoint:{path}")

                # Check global security
                if not spec.get('security') and not spec.get('securityDefinitions'):
                    security_issues.append(SecurityIssue.NO_AUTHENTICATION.value)

                # Check for internal/debug endpoints
                if any('/debug' in p or '/internal' in p or '/admin' in p for p in paths):
                    security_issues.append(SecurityIssue.INTERNAL_ENDPOINT.value)

                severity = self._calculate_openapi_severity(endpoints, security_issues)

                return APIFinding(
                    api_type=api_type,
                    url=url,
                    severity=severity,
                    endpoints=endpoints[:100],  # Limit
                    security_issues=security_issues,
                    metadata={
                        'openapi_version': spec.get('openapi') or spec.get('swagger'),
                        'title': spec.get('info', {}).get('title'),
                        'endpoints_count': len(endpoints),
                    }
                )

        except Exception as e:
            logger.debug(f"Error checking OpenAPI at {url}: {e}")

        return None

    async def _check_rest(self, url: str) -> Optional[APIFinding]:
        """Check for REST API endpoints."""

        try:
            # Check OPTIONS for CORS and methods
            async with self.session.options(url, ssl=False) as resp:
                if resp.status in (200, 204):
                    security_issues = []

                    # Check CORS
                    cors_origin = resp.headers.get('Access-Control-Allow-Origin', '')
                    if cors_origin == '*':
                        security_issues.append(SecurityIssue.CORS_MISCONFIGURED.value)

                    # Check rate limiting
                    if not any(h in resp.headers for h in
                               ['X-RateLimit-Limit', 'RateLimit-Limit', 'X-Rate-Limit']):
                        security_issues.append(SecurityIssue.RATE_LIMIT_ABSENT.value)

                    # Check allowed methods
                    methods = resp.headers.get('Access-Control-Allow-Methods', '')

                    if security_issues:
                        return APIFinding(
                            api_type=APIType.REST,
                            url=url,
                            severity='medium',
                            security_issues=security_issues,
                            metadata={
                                'cors_origin': cors_origin,
                                'allowed_methods': methods,
                            }
                        )

        except Exception:
            pass

        # Try GET request
        try:
            async with self.session.get(url, ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()

                    # Check if it looks like API response
                    if body.strip().startswith(('{', '[')):
                        try:
                            data = json.loads(body)

                            # Check for verbose errors or debug info
                            security_issues = []
                            if 'debug' in str(data).lower():
                                security_issues.append(SecurityIssue.DEBUG_MODE.value)
                            if 'error' in data and 'trace' in str(data).lower():
                                security_issues.append(SecurityIssue.VERBOSE_ERRORS.value)

                            return APIFinding(
                                api_type=APIType.REST,
                                url=url,
                                severity='low' if not security_issues else 'medium',
                                security_issues=security_issues,
                                metadata={'response_keys': list(data.keys())[:10] if isinstance(data, dict) else []}
                            )
                        except json.JSONDecodeError:
                            pass

        except Exception:
            pass

        return None

    async def _check_websocket(self, url: str) -> Optional[APIFinding]:
        """Check for WebSocket endpoints."""

        # Convert HTTP URL to WebSocket URL
        ws_url = url.replace('http://', 'ws://').replace('https://', 'wss://')

        try:
            async with self.session.ws_connect(ws_url, ssl=False, timeout=5) as ws:
                # WebSocket connected successfully
                await ws.close()

                return APIFinding(
                    api_type=APIType.WEBSOCKET,
                    url=url,
                    severity='medium',
                    security_issues=[],
                    metadata={'websocket_url': ws_url}
                )

        except Exception:
            pass

        return None

    async def _check_no_auth(self, url: str, api_type: str) -> bool:
        """Check if endpoint allows unauthenticated access."""

        if api_type == 'graphql':
            # Try a simple query
            query = {"query": "{ __typename }"}
            try:
                async with self.session.post(url, json=query, ssl=False) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return 'data' in data
            except Exception:
                pass

        return False

    def _calculate_graphql_severity(
        self,
        issues: List[str],
        mutations: List[str]
    ) -> str:
        """Calculate severity for GraphQL finding."""

        # Critical: Sensitive mutations exposed
        sensitive_mutations = [
            m for m in mutations
            if any(s.lower() in m.lower() for s in self.SENSITIVE_GRAPHQL_OPERATIONS)
        ]

        if sensitive_mutations and SecurityIssue.NO_AUTHENTICATION.value in issues:
            return 'critical'

        if sensitive_mutations:
            return 'high'

        if SecurityIssue.INTROSPECTION_ENABLED.value in issues:
            return 'high'

        return 'medium'

    def _calculate_openapi_severity(
        self,
        endpoints: List[APIEndpoint],
        issues: List[str]
    ) -> str:
        """Calculate severity for OpenAPI finding."""

        # Critical: Unauthenticated admin/sensitive endpoints
        if SecurityIssue.NO_AUTHENTICATION.value in issues:
            if SecurityIssue.INTERNAL_ENDPOINT.value in issues:
                return 'critical'
            return 'high'

        if SecurityIssue.INTERNAL_ENDPOINT.value in issues:
            return 'high'

        # High: Many endpoints exposed
        if len(endpoints) > 50:
            return 'high'

        return 'medium'

    def _deduplicate_findings(self, findings: List[APIFinding]) -> List[APIFinding]:
        """Deduplicate findings by URL."""
        seen = set()
        unique = []

        for finding in findings:
            if finding.url not in seen:
                seen.add(finding.url)
                unique.append(finding)

        return unique


def generate_api_report(findings: List[APIFinding]) -> str:
    """Generate a formatted report of API findings."""

    if not findings:
        return "No exposed API endpoints detected.\n"

    lines = [
        "=" * 80,
        "API DISCOVERY REPORT",
        "=" * 80,
        f"\nTotal API endpoints discovered: {len(findings)}",
        ""
    ]

    # Group by type
    by_type = {}
    for finding in findings:
        api_type = finding.api_type.value
        if api_type not in by_type:
            by_type[api_type] = []
        by_type[api_type].append(finding)

    for api_type, type_findings in sorted(by_type.items()):
        lines.append(f"\n[{api_type.upper()}] - {len(type_findings)} endpoints")
        lines.append("-" * 60)

        for finding in type_findings:
            severity_icon = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🔵'
            }.get(finding.severity, '⚪')

            lines.append(f"\n  {severity_icon} {finding.url}")
            lines.append(f"     Severity: {finding.severity.upper()}")

            if finding.security_issues:
                lines.append(f"     ⚠️  Issues: {', '.join(finding.security_issues[:5])}")

            if finding.types_exposed:
                lines.append(f"     Types exposed: {len(finding.types_exposed)}")
                lines.append(f"       {', '.join(finding.types_exposed[:10])}")
                if len(finding.types_exposed) > 10:
                    lines.append(f"       ... and {len(finding.types_exposed) - 10} more")

            if finding.mutations_found:
                lines.append(f"     Mutations: {len(finding.mutations_found)}")
                lines.append(f"       {', '.join(finding.mutations_found[:10])}")

            if finding.queries_found:
                lines.append(f"     Queries: {len(finding.queries_found)}")

            if finding.endpoints:
                lines.append(f"     REST Endpoints: {len(finding.endpoints)}")
                for ep in finding.endpoints[:5]:
                    auth_status = "🔓" if ep.authentication == 'none' else "🔒"
                    lines.append(f"       {auth_status} {ep.method} {ep.path}")

    lines.append("\n" + "=" * 80)
    return "\n".join(lines)
