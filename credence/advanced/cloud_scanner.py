"""
Cloud Asset Exposure Scanner.

Detects misconfigured cloud storage buckets, container registries,
and cloud infrastructure exposure across AWS, Azure, GCP, and more.

This module addresses a critical gap in security tooling by identifying
exposed cloud assets through passive reconnaissance and active probing.
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

import aiohttp

logger = logging.getLogger(__name__)


class CloudProvider(Enum):
    """Supported cloud providers for asset scanning."""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    DIGITALOCEAN = "digitalocean"
    ALIBABA = "alibaba"
    ORACLE = "oracle"
    UNKNOWN = "unknown"


class BucketPermission(Enum):
    """Bucket permission levels detected."""
    PUBLIC_READ = "public-read"
    PUBLIC_WRITE = "public-write"
    PUBLIC_READ_WRITE = "public-read-write"
    AUTHENTICATED_READ = "authenticated-read"
    PRIVATE = "private"
    UNKNOWN = "unknown"


@dataclass
class CloudAssetFinding:
    """Represents a discovered cloud asset exposure."""
    provider: CloudProvider
    asset_type: str  # 's3', 'blob', 'bucket', 'registry', etc.
    asset_name: str
    url: str
    permission: BucketPermission
    severity: str  # 'critical', 'high', 'medium', 'low'
    evidence: str
    files_listed: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


class CloudAssetScanner:
    """
    Scan for exposed cloud storage and infrastructure.
    
    Features:
    - S3 bucket enumeration and permission checking
    - Azure Blob Storage exposure detection
    - GCP Cloud Storage bucket scanning
    - Container registry exposure (ECR, ACR, GCR)
    - Cloud function/Lambda endpoint discovery
    - CDN origin exposure detection
    """

    # Cloud storage URL patterns for detection
    CLOUD_PATTERNS = {
        # AWS S3 patterns
        's3_virtual': r'([a-zA-Z0-9][\w.-]{1,61}[a-zA-Z0-9])\.s3[\w.-]*\.amazonaws\.com',
        's3_path': r's3\.[\w.-]*\.amazonaws\.com/([a-zA-Z0-9][\w.-]{1,61}[a-zA-Z0-9])',
        's3_direct': r's3://([a-zA-Z0-9][\w.-]{1,61}[a-zA-Z0-9])',

        # Azure Blob Storage patterns
        'azure_blob': r'([a-zA-Z0-9]{3,24})\.blob\.core\.windows\.net',
        'azure_dfs': r'([a-zA-Z0-9]{3,24})\.dfs\.core\.windows\.net',
        'azure_file': r'([a-zA-Z0-9]{3,24})\.file\.core\.windows\.net',
        'azure_queue': r'([a-zA-Z0-9]{3,24})\.queue\.core\.windows\.net',
        'azure_table': r'([a-zA-Z0-9]{3,24})\.table\.core\.windows\.net',

        # GCP Cloud Storage patterns
        'gcp_storage': r'storage\.googleapis\.com/([a-zA-Z0-9][\w.-]{1,61}[a-zA-Z0-9])',
        'gcp_bucket': r'([a-zA-Z0-9][\w.-]{1,61}[a-zA-Z0-9])\.storage\.googleapis\.com',

        # DigitalOcean Spaces
        'do_spaces': r'([a-z0-9][\w-]{1,61}[a-z0-9])\.([a-z]{3}\d)\.digitaloceanspaces\.com',

        # Alibaba Cloud OSS
        'alibaba_oss': r'([a-zA-Z0-9][\w-]{2,62})\.oss[a-z0-9-]*\.aliyuncs\.com',

        # Oracle Cloud Infrastructure Object Storage
        'oracle_oci': r'objectstorage\.([a-z]{2}-[a-z]+-\d)\.oraclecloud\.com/n/([a-zA-Z0-9]+)/b/([a-zA-Z0-9-_]+)',

        # Container registries
        'ecr': r'(\d{12})\.dkr\.ecr\.([a-z]{2}-[a-z]+-\d)\.amazonaws\.com',
        'gcr': r'gcr\.io/([a-zA-Z0-9][\w.-]+)',
        'acr': r'([a-zA-Z0-9]+)\.azurecr\.io',

        # CDN origins that may expose buckets
        'cloudfront': r'[a-z0-9]+\.cloudfront\.net',
        'azure_cdn': r'[a-z0-9]+\.azureedge\.net',
        'cloudflare_r2': r'([a-f0-9]{32})\.r2\.cloudflarestorage\.com',
    }

    # Common bucket name patterns to enumerate
    BUCKET_WORDLIST = [
        # Generic patterns
        '{domain}', '{domain}-backup', '{domain}-backups', '{domain}-bak',
        '{domain}-dev', '{domain}-development', '{domain}-staging', '{domain}-stage',
        '{domain}-prod', '{domain}-production', '{domain}-public', '{domain}-private',
        '{domain}-assets', '{domain}-static', '{domain}-media', '{domain}-images',
        '{domain}-uploads', '{domain}-files', '{domain}-data', '{domain}-logs',
        '{domain}-cdn', '{domain}-content', '{domain}-storage', '{domain}-archive',

        # Common naming conventions
        'backup-{domain}', 'backups-{domain}', 'bak-{domain}',
        'dev-{domain}', 'staging-{domain}', 'prod-{domain}',
        'assets-{domain}', 'static-{domain}', 'media-{domain}',

        # Year-based backups
        '{domain}-backup-2023', '{domain}-backup-2024', '{domain}-backup-2025',

        # Environment-specific
        '{domain}-test', '{domain}-qa', '{domain}-uat',
    ]

    def __init__(
        self,
        session: Optional[aiohttp.ClientSession] = None,
        timeout: int = 10,
        max_concurrent: int = 20,
        enumerate_buckets: bool = True,
        check_permissions: bool = True,
        list_files: bool = True,
        max_files_to_list: int = 100
    ):
        """
        Initialize Cloud Asset Scanner.
        
        Args:
            session: aiohttp session (created if not provided)
            timeout: Request timeout in seconds
            max_concurrent: Maximum concurrent requests
            enumerate_buckets: Whether to enumerate bucket names
            check_permissions: Whether to check bucket permissions
            list_files: Whether to list files in public buckets
            max_files_to_list: Maximum files to enumerate per bucket
        """
        self.session = session
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.enumerate_buckets = enumerate_buckets
        self.check_permissions = check_permissions
        self.list_files = list_files
        self.max_files_to_list = max_files_to_list

        self._owns_session = session is None
        self._found_assets: Set[str] = set()

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

    async def scan_target(self, target: str, content: str = "") -> List[CloudAssetFinding]:
        """
        Scan a target for cloud asset exposures.
        
        Args:
            target: Target URL or domain
            content: Optional response content to scan for cloud URLs
            
        Returns:
            List of CloudAssetFinding objects
        """
        findings = []
        domain = self._extract_domain(target)

        # Step 1: Extract cloud URLs from content
        if content:
            extracted = await self._extract_cloud_urls(content)
            for url, provider, asset_type, asset_name in extracted:
                finding = await self._check_asset(url, provider, asset_type, asset_name)
                if finding:
                    findings.append(finding)

        # Step 2: Enumerate common bucket names
        if self.enumerate_buckets and domain:
            enumerated = await self._enumerate_buckets(domain)
            findings.extend(enumerated)

        return findings

    async def _extract_cloud_urls(self, content: str) -> List[tuple]:
        """Extract cloud asset URLs from content."""
        results = []

        for pattern_name, pattern in self.CLOUD_PATTERNS.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)

            for match in matches:
                try:
                    full_match = match.group(0)
                    asset_name = match.group(1) if match.lastindex else full_match

                    # Determine provider and construct check URL
                    provider, asset_type, check_url = self._parse_match(
                        pattern_name, full_match, asset_name, match
                    )

                    if check_url and check_url not in self._found_assets:
                        self._found_assets.add(check_url)
                        results.append((check_url, provider, asset_type, asset_name))

                except Exception as e:
                    logger.debug(f"Error parsing cloud pattern match: {e}")
                    continue

        return results

    def _parse_match(self, pattern_name: str, full_match: str, asset_name: str, match) -> tuple:
        """Parse regex match into provider, type, and URL."""

        if pattern_name.startswith('s3'):
            return (
                CloudProvider.AWS,
                's3_bucket',
                f"https://{asset_name}.s3.amazonaws.com/"
            )

        elif pattern_name.startswith('azure'):
            storage_type = pattern_name.split('_')[1]  # blob, dfs, file, etc.
            return (
                CloudProvider.AZURE,
                f'azure_{storage_type}',
                f"https://{asset_name}.blob.core.windows.net/?restype=container&comp=list"
            )

        elif pattern_name.startswith('gcp'):
            return (
                CloudProvider.GCP,
                'gcp_bucket',
                f"https://storage.googleapis.com/{asset_name}/"
            )

        elif pattern_name == 'do_spaces':
            region = match.group(2) if match.lastindex >= 2 else 'nyc3'
            return (
                CloudProvider.DIGITALOCEAN,
                'spaces',
                f"https://{asset_name}.{region}.digitaloceanspaces.com/"
            )

        elif pattern_name == 'alibaba_oss':
            return (
                CloudProvider.ALIBABA,
                'oss_bucket',
                f"https://{asset_name}.oss.aliyuncs.com/"
            )

        elif pattern_name == 'ecr':
            account_id = match.group(1)
            region = match.group(2)
            return (
                CloudProvider.AWS,
                'ecr_registry',
                f"https://{account_id}.dkr.ecr.{region}.amazonaws.com/v2/_catalog"
            )

        elif pattern_name == 'gcr':
            project = match.group(1)
            return (
                CloudProvider.GCP,
                'gcr_registry',
                f"https://gcr.io/v2/{project}/tags/list"
            )

        elif pattern_name == 'acr':
            registry = match.group(1)
            return (
                CloudProvider.AZURE,
                'acr_registry',
                f"https://{registry}.azurecr.io/v2/_catalog"
            )

        return (CloudProvider.UNKNOWN, 'unknown', None)

    async def _check_asset(
        self,
        url: str,
        provider: CloudProvider,
        asset_type: str,
        asset_name: str
    ) -> Optional[CloudAssetFinding]:
        """Check if a cloud asset is publicly accessible."""

        try:
            async with self.session.get(url, ssl=False) as resp:
                body = await resp.text()

                # Check for public access indicators
                if resp.status == 200:
                    permission, evidence = self._analyze_response(
                        resp.status, body, provider, asset_type
                    )

                    if permission != BucketPermission.PRIVATE:
                        files = []
                        if self.list_files:
                            files = self._extract_file_list(body, provider)

                        severity = self._calculate_severity(permission, asset_type, files)

                        return CloudAssetFinding(
                            provider=provider,
                            asset_type=asset_type,
                            asset_name=asset_name,
                            url=url,
                            permission=permission,
                            severity=severity,
                            evidence=evidence,
                            files_listed=files[:self.max_files_to_list],
                            metadata={
                                'status_code': resp.status,
                                'content_length': len(body),
                                'content_type': resp.headers.get('Content-Type', '')
                            }
                        )

                # Check for listing enabled (403 vs 404 distinction)
                elif resp.status == 403:
                    # Bucket exists but listing denied
                    return CloudAssetFinding(
                        provider=provider,
                        asset_type=asset_type,
                        asset_name=asset_name,
                        url=url,
                        permission=BucketPermission.PRIVATE,
                        severity='low',
                        evidence='Bucket exists (403 Forbidden - listing denied)',
                        metadata={'status_code': resp.status}
                    )

        except asyncio.TimeoutError:
            logger.debug(f"Timeout checking {url}")
        except Exception as e:
            logger.debug(f"Error checking {url}: {e}")

        return None

    def _analyze_response(
        self,
        status: int,
        body: str,
        provider: CloudProvider,
        asset_type: str
    ) -> tuple:
        """Analyze response to determine permission level."""

        body_lower = body.lower()

        # S3-specific indicators
        if provider == CloudProvider.AWS:
            if '<listbucketresult' in body_lower:
                return (BucketPermission.PUBLIC_READ, "S3 bucket listing enabled")
            if 'accessdenied' in body_lower:
                return (BucketPermission.PRIVATE, "Access denied")

        # Azure-specific indicators
        elif provider == CloudProvider.AZURE:
            if '<enumerationresults' in body_lower or '<blobs>' in body_lower:
                return (BucketPermission.PUBLIC_READ, "Azure container listing enabled")
            if 'authorizationfailure' in body_lower:
                return (BucketPermission.PRIVATE, "Authorization failure")

        # GCP-specific indicators
        elif provider == CloudProvider.GCP:
            if '<listbucketresult' in body_lower or '"items"' in body_lower:
                return (BucketPermission.PUBLIC_READ, "GCP bucket listing enabled")

        # Generic indicators
        if any(x in body_lower for x in ['<key>', '<name>', '"key":', '"name":']):
            return (BucketPermission.PUBLIC_READ, "Bucket listing detected")

        # Check for actual file content vs error
        if status == 200 and len(body) > 100:
            return (BucketPermission.PUBLIC_READ, "Public read access detected")

        return (BucketPermission.UNKNOWN, "Unable to determine permissions")

    def _extract_file_list(self, body: str, provider: CloudProvider) -> List[str]:
        """Extract file list from bucket listing response."""
        files = []

        # XML-based listings (S3, GCP, Azure)
        key_pattern = r'<Key>([^<]+)</Key>'
        matches = re.findall(key_pattern, body, re.IGNORECASE)
        files.extend(matches)

        # JSON-based listings
        name_pattern = r'"name"\s*:\s*"([^"]+)"'
        matches = re.findall(name_pattern, body)
        files.extend(matches)

        # Azure blob names
        blob_pattern = r'<Name>([^<]+)</Name>'
        matches = re.findall(blob_pattern, body, re.IGNORECASE)
        files.extend(matches)

        return list(set(files))  # Deduplicate

    def _calculate_severity(
        self,
        permission: BucketPermission,
        asset_type: str,
        files: List[str]
    ) -> str:
        """Calculate severity based on exposure type and contents."""

        # Critical: Write access or sensitive file types detected
        sensitive_extensions = [
            '.env', '.pem', '.key', '.sql', '.bak', '.backup',
            '.credentials', '.config', 'wp-config', 'id_rsa',
            '.pfx', '.p12', '.jks', '.keystore'
        ]

        if permission in (BucketPermission.PUBLIC_WRITE, BucketPermission.PUBLIC_READ_WRITE):
            return 'critical'

        if any(any(ext in f.lower() for ext in sensitive_extensions) for f in files):
            return 'critical'

        # High: Container registries or data stores
        if asset_type in ('ecr_registry', 'gcr_registry', 'acr_registry'):
            return 'high'

        if permission == BucketPermission.PUBLIC_READ:
            return 'high'

        return 'medium'

    async def _enumerate_buckets(self, domain: str) -> List[CloudAssetFinding]:
        """Enumerate common bucket names for a domain."""
        findings = []
        domain_parts = domain.replace('.', '-')
        domain_short = domain.split('.')[0]

        # Generate bucket names to check
        bucket_names = set()
        for pattern in self.BUCKET_WORDLIST:
            for d in [domain, domain_parts, domain_short]:
                name = pattern.format(domain=d)
                bucket_names.add(name.lower())

        # Check buckets concurrently
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def check_bucket(name: str):
            async with semaphore:
                # Check S3
                s3_url = f"https://{name}.s3.amazonaws.com/"
                finding = await self._check_asset(
                    s3_url, CloudProvider.AWS, 's3_bucket', name
                )
                if finding and finding.permission != BucketPermission.PRIVATE:
                    return finding

                # Check GCP
                gcp_url = f"https://storage.googleapis.com/{name}/"
                finding = await self._check_asset(
                    gcp_url, CloudProvider.GCP, 'gcp_bucket', name
                )
                if finding and finding.permission != BucketPermission.PRIVATE:
                    return finding

                return None

        tasks = [check_bucket(name) for name in bucket_names]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, CloudAssetFinding):
                findings.append(result)

        return findings

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            if not url.startswith(('http://', 'https://')):
                url = f"https://{url}"
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            # Remove www prefix and port
            domain = re.sub(r'^www\.', '', domain)
            domain = domain.split(':')[0]
            return domain
        except Exception:
            return ""


def generate_cloud_report(findings: List[CloudAssetFinding]) -> str:
    """Generate a formatted report of cloud asset findings."""

    if not findings:
        return "No exposed cloud assets detected.\n"

    lines = [
        "=" * 80,
        "CLOUD ASSET EXPOSURE REPORT",
        "=" * 80,
        f"\nTotal exposed assets: {len(findings)}\n"
    ]

    # Group by provider
    by_provider = {}
    for finding in findings:
        provider = finding.provider.value
        if provider not in by_provider:
            by_provider[provider] = []
        by_provider[provider].append(finding)

    for provider, provider_findings in sorted(by_provider.items()):
        lines.append(f"\n[{provider.upper()}] - {len(provider_findings)} assets")
        lines.append("-" * 60)

        for finding in provider_findings:
            severity_icon = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🔵'
            }.get(finding.severity, '⚪')

            lines.append(f"\n  {severity_icon} {finding.asset_name}")
            lines.append(f"     Type: {finding.asset_type}")
            lines.append(f"     URL: {finding.url}")
            lines.append(f"     Permission: {finding.permission.value}")
            lines.append(f"     Evidence: {finding.evidence}")

            if finding.files_listed:
                lines.append(f"     Files ({len(finding.files_listed)}):")
                for f in finding.files_listed[:10]:
                    lines.append(f"       - {f}")
                if len(finding.files_listed) > 10:
                    lines.append(f"       ... and {len(finding.files_listed) - 10} more")

    lines.append("\n" + "=" * 80)
    return "\n".join(lines)
