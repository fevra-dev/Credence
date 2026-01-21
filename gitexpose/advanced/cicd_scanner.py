"""
CI/CD Pipeline Exposure Detection.

Detects exposed CI/CD configuration files that reveal:
- Build processes and deployment pipelines
- Secret management patterns
- Infrastructure details
- Internal service endpoints
- Cloud provider configurations

This is a significant security gap as CI/CD configs often contain
or reference sensitive credentials and reveal attack surfaces.
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
from urllib.parse import urljoin

import aiohttp

logger = logging.getLogger(__name__)


class CICDPlatform(Enum):
    """Supported CI/CD platforms."""
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"
    CIRCLECI = "circleci"
    TRAVIS_CI = "travis_ci"
    AZURE_DEVOPS = "azure_devops"
    BITBUCKET_PIPELINES = "bitbucket_pipelines"
    DRONE = "drone"
    TEAMCITY = "teamcity"
    BUILDKITE = "buildkite"
    ARGO_CD = "argocd"
    TEKTON = "tekton"
    UNKNOWN = "unknown"


@dataclass
class CICDFinding:
    """Represents a discovered CI/CD configuration exposure."""
    platform: CICDPlatform
    file_path: str
    url: str
    severity: str
    content: str
    secrets_referenced: List[str] = field(default_factory=list)
    services_exposed: List[str] = field(default_factory=list)
    cloud_providers: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


class CICDScanner:
    """
    Scan for exposed CI/CD pipeline configurations.
    
    Features:
    - Detect exposed workflow files
    - Identify secret references and patterns
    - Map deployment infrastructure
    - Discover internal service endpoints
    - Identify potential attack vectors
    """

    # CI/CD configuration paths to scan
    CICD_PATHS = {
        # GitHub Actions
        CICDPlatform.GITHUB_ACTIONS: [
            '.github/workflows/main.yml',
            '.github/workflows/main.yaml',
            '.github/workflows/ci.yml',
            '.github/workflows/ci.yaml',
            '.github/workflows/cd.yml',
            '.github/workflows/build.yml',
            '.github/workflows/deploy.yml',
            '.github/workflows/test.yml',
            '.github/workflows/release.yml',
            '.github/workflows/publish.yml',
            '.github/workflows/docker.yml',
            '.github/workflows/codeql.yml',
            '.github/workflows/codeql-analysis.yml',
            '.github/dependabot.yml',
            '.github/CODEOWNERS',
        ],

        # GitLab CI
        CICDPlatform.GITLAB_CI: [
            '.gitlab-ci.yml',
            '.gitlab-ci.yaml',
            'gitlab-ci.yml',
            '.gitlab/ci/pipeline.yml',
            '.gitlab/ci/build.yml',
            '.gitlab/ci/deploy.yml',
        ],

        # Jenkins
        CICDPlatform.JENKINS: [
            'Jenkinsfile',
            'jenkins/Jenkinsfile',
            'ci/Jenkinsfile',
            '.jenkins/Jenkinsfile',
            'jenkins.groovy',
            'pipeline.groovy',
        ],

        # CircleCI
        CICDPlatform.CIRCLECI: [
            '.circleci/config.yml',
            '.circleci/config.yaml',
            'circle.yml',
        ],

        # Travis CI
        CICDPlatform.TRAVIS_CI: [
            '.travis.yml',
            '.travis.yaml',
            'travis.yml',
        ],

        # Azure DevOps
        CICDPlatform.AZURE_DEVOPS: [
            'azure-pipelines.yml',
            'azure-pipelines.yaml',
            '.azure-pipelines/main.yml',
            '.azure-pipelines/ci.yml',
            '.azure-pipelines/cd.yml',
            'azure-pipelines-pr.yml',
        ],

        # Bitbucket Pipelines
        CICDPlatform.BITBUCKET_PIPELINES: [
            'bitbucket-pipelines.yml',
            'bitbucket-pipelines.yaml',
        ],

        # Drone CI
        CICDPlatform.DRONE: [
            '.drone.yml',
            '.drone.yaml',
            'drone.yml',
        ],

        # BuildKite
        CICDPlatform.BUILDKITE: [
            '.buildkite/pipeline.yml',
            '.buildkite/pipeline.yaml',
            'buildkite.yml',
        ],

        # ArgoCD
        CICDPlatform.ARGO_CD: [
            'argocd/application.yaml',
            '.argocd/application.yaml',
            'argocd-app.yaml',
        ],

        # Tekton
        CICDPlatform.TEKTON: [
            'tekton/pipeline.yaml',
            '.tekton/pipeline.yaml',
        ],
    }

    # Patterns indicating secrets
    SECRET_PATTERNS = [
        r'\$\{\{\s*secrets\.([A-Z_]+)\s*\}\}',  # GitHub Actions
        r'\$([A-Z_]+)',  # Generic env vars
        r'env:\s*([A-Z_]+)',  # Environment variables
        r'secret:\s*([a-zA-Z0-9_-]+)',  # Kubernetes secrets
        r'credentials\s*\(\s*["\']([^"\']+)["\']',  # Jenkins credentials
        r'password:\s*([^\s]+)',  # Password fields
        r'token:\s*([^\s]+)',  # Token fields
        r'api[_-]?key:\s*([^\s]+)',  # API keys
        r'AWS_ACCESS_KEY_ID',
        r'AWS_SECRET_ACCESS_KEY',
        r'DOCKER_PASSWORD',
        r'GITHUB_TOKEN',
        r'NPM_TOKEN',
        r'PYPI_TOKEN',
        r'SONAR_TOKEN',
        r'CODECOV_TOKEN',
        r'HEROKU_API_KEY',
        r'FIREBASE_TOKEN',
        r'SLACK_WEBHOOK',
    ]

    # Patterns indicating cloud services
    CLOUD_PATTERNS = {
        'aws': [r'aws', r'ecr\.', r's3:', r'arn:aws', r'amazonaws\.com'],
        'gcp': [r'gcloud', r'gcr\.io', r'google-cloud', r'\.googleapis\.com'],
        'azure': [r'azure', r'acr\.io', r'\.azure\.', r'azurecr\.io'],
        'kubernetes': [r'kubectl', r'kube', r'k8s', r'helm', r'kubernetes'],
        'docker': [r'docker', r'dockerfile', r'docker-compose', r'dockerhub'],
        'terraform': [r'terraform', r'\.tf$', r'tfstate'],
        'heroku': [r'heroku', r'herokuapp\.com'],
        'vercel': [r'vercel', r'\.vercel\.'],
        'netlify': [r'netlify', r'\.netlify\.'],
        'digitalocean': [r'digitalocean', r'doctl', r'\.digitalocean\.'],
    }

    # Patterns indicating internal services/endpoints
    SERVICE_PATTERNS = [
        r'https?://(?:internal|staging|dev|test|api|backend)[a-zA-Z0-9.-]*\.[a-z]+',
        r'(?:mongodb|postgres|mysql|redis)://[^\s]+',
        r'(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)',
        r'localhost:\d+',
        r'[a-zA-Z0-9-]+\.internal',
        r'[a-zA-Z0-9-]+\.local',
        r'[a-zA-Z0-9-]+\.svc\.cluster\.local',
    ]

    # Attack vectors to identify
    ATTACK_VECTORS = {
        'command_injection': [
            r'\$\(\s*[^)]+\)',  # Command substitution
            r'`[^`]+`',  # Backtick execution
            r'eval\s+',  # Eval usage
            r'exec\s+',  # Exec usage
        ],
        'secret_extraction': [
            r'echo\s+\$',  # Echo environment
            r'printenv',  # Print environment
            r'env\s*$',  # List environment
        ],
        'artifact_access': [
            r'artifacts?:',  # Artifact definitions
            r'cache:',  # Cache configurations
            r'upload-artifact',  # Artifact upload
            r'download-artifact',  # Artifact download
        ],
        'privileged_execution': [
            r'privileged:\s*true',  # Docker privileged
            r'--privileged',  # Privileged flag
            r'sudo\s+',  # Sudo usage
            r'as:\s*root',  # Run as root
        ],
        'network_exposure': [
            r'ports:',  # Port exposures
            r'expose:',  # Docker expose
            r'NodePort',  # K8s NodePort
            r'LoadBalancer',  # K8s LoadBalancer
        ],
    }

    def __init__(
        self,
        session: Optional[aiohttp.ClientSession] = None,
        timeout: int = 10,
        max_concurrent: int = 20,
        analyze_content: bool = True
    ):
        """
        Initialize CI/CD Scanner.
        
        Args:
            session: aiohttp session (created if not provided)
            timeout: Request timeout in seconds
            max_concurrent: Maximum concurrent requests
            analyze_content: Whether to analyze file contents
        """
        self.session = session
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.analyze_content = analyze_content

        self._owns_session = session is None

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

    async def scan_target(self, target_url: str) -> List[CICDFinding]:
        """
        Scan a target for exposed CI/CD configurations.
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            List of CICDFinding objects
        """
        findings = []
        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks = []

        # Generate all paths to check
        for platform, paths in self.CICD_PATHS.items():
            for path in paths:
                url = urljoin(target_url.rstrip('/') + '/', path)
                tasks.append(self._check_path(url, path, platform, semaphore))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, CICDFinding):
                findings.append(result)

        logger.info(f"Found {len(findings)} CI/CD configurations")
        return findings

    async def _check_path(
        self,
        url: str,
        path: str,
        platform: CICDPlatform,
        semaphore: asyncio.Semaphore
    ) -> Optional[CICDFinding]:
        """Check a single CI/CD path."""

        async with semaphore:
            try:
                async with self.session.get(url, ssl=False) as resp:
                    if resp.status != 200:
                        return None

                    content = await resp.text()

                    # Validate content looks like CI/CD config
                    if not self._validate_cicd_content(content, platform):
                        return None

                    # Analyze content if enabled
                    secrets = []
                    services = []
                    clouds = []
                    vectors = []

                    if self.analyze_content:
                        secrets = self._extract_secrets(content)
                        services = self._extract_services(content)
                        clouds = self._extract_cloud_providers(content)
                        vectors = self._extract_attack_vectors(content)

                    severity = self._calculate_severity(secrets, services, vectors)

                    return CICDFinding(
                        platform=platform,
                        file_path=path,
                        url=url,
                        severity=severity,
                        content=content[:5000],  # Limit stored content
                        secrets_referenced=secrets,
                        services_exposed=services,
                        cloud_providers=clouds,
                        attack_vectors=vectors,
                        metadata={
                            'content_length': len(content),
                            'content_type': resp.headers.get('Content-Type', '')
                        }
                    )

            except asyncio.TimeoutError:
                logger.debug(f"Timeout checking {url}")
            except Exception as e:
                logger.debug(f"Error checking {url}: {e}")

        return None

    def _validate_cicd_content(self, content: str, platform: CICDPlatform) -> bool:
        """Validate that content looks like valid CI/CD config."""

        content_lower = content.lower()

        # Platform-specific validation
        validators = {
            CICDPlatform.GITHUB_ACTIONS: [
                'on:', 'jobs:', 'runs-on:', 'steps:', 'uses:', 'name:'
            ],
            CICDPlatform.GITLAB_CI: [
                'stages:', 'script:', 'image:', 'before_script:', 'after_script:'
            ],
            CICDPlatform.JENKINS: [
                'pipeline', 'stage', 'steps', 'agent', 'node'
            ],
            CICDPlatform.CIRCLECI: [
                'version:', 'jobs:', 'workflows:', 'executors:', 'orbs:'
            ],
            CICDPlatform.TRAVIS_CI: [
                'language:', 'script:', 'install:', 'before_install:'
            ],
            CICDPlatform.AZURE_DEVOPS: [
                'trigger:', 'pool:', 'stages:', 'jobs:', 'steps:'
            ],
            CICDPlatform.BITBUCKET_PIPELINES: [
                'pipelines:', 'definitions:', 'steps:', 'script:'
            ],
            CICDPlatform.DRONE: [
                'kind:', 'type:', 'steps:', 'image:'
            ],
            CICDPlatform.BUILDKITE: [
                'steps:', 'command:', 'plugins:', 'agents:'
            ],
        }

        keywords = validators.get(platform, ['stage', 'step', 'script', 'build'])

        # Check if at least 2 keywords are present
        matches = sum(1 for kw in keywords if kw.lower() in content_lower)
        return matches >= 2

    def _extract_secrets(self, content: str) -> List[str]:
        """Extract secret references from content."""
        secrets = set()

        for pattern in self.SECRET_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    secrets.add(match[0] if match[0] else match[-1])
                else:
                    secrets.add(match)

        return list(secrets)

    def _extract_services(self, content: str) -> List[str]:
        """Extract internal service references."""
        services = set()

        for pattern in self.SERVICE_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            services.update(matches)

        return list(services)

    def _extract_cloud_providers(self, content: str) -> List[str]:
        """Extract cloud provider references."""
        clouds = set()
        content_lower = content.lower()

        for cloud, patterns in self.CLOUD_PATTERNS.items():
            if any(re.search(p, content_lower) for p in patterns):
                clouds.add(cloud)

        return list(clouds)

    def _extract_attack_vectors(self, content: str) -> List[str]:
        """Identify potential attack vectors."""
        vectors = []

        for vector_name, patterns in self.ATTACK_VECTORS.items():
            if any(re.search(p, content, re.IGNORECASE) for p in patterns):
                vectors.append(vector_name)

        return vectors

    def _calculate_severity(
        self,
        secrets: List[str],
        services: List[str],
        vectors: List[str]
    ) -> str:
        """Calculate severity based on exposure."""

        # Critical: Hardcoded secrets or privileged execution
        if 'privileged_execution' in vectors:
            return 'critical'

        # High: Secrets referenced or internal services exposed
        if len(secrets) >= 3 or 'secret_extraction' in vectors:
            return 'high'

        if services:
            return 'high'

        # Medium: Any CI/CD config exposure
        if secrets or vectors:
            return 'medium'

        return 'low'


def generate_cicd_report(findings: List[CICDFinding]) -> str:
    """Generate a formatted report of CI/CD findings."""

    if not findings:
        return "No exposed CI/CD configurations detected.\n"

    lines = [
        "=" * 80,
        "CI/CD PIPELINE EXPOSURE REPORT",
        "=" * 80,
        f"\nTotal exposed configurations: {len(findings)}",
        ""
    ]

    # Group by platform
    by_platform = {}
    for finding in findings:
        platform = finding.platform.value
        if platform not in by_platform:
            by_platform[platform] = []
        by_platform[platform].append(finding)

    for platform, platform_findings in sorted(by_platform.items()):
        lines.append(f"\n[{platform.upper()}] - {len(platform_findings)} configs")
        lines.append("-" * 60)

        for finding in platform_findings:
            severity_icon = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🔵'
            }.get(finding.severity, '⚪')

            lines.append(f"\n  {severity_icon} {finding.file_path}")
            lines.append(f"     URL: {finding.url}")
            lines.append(f"     Severity: {finding.severity.upper()}")

            if finding.secrets_referenced:
                lines.append(f"     Secrets Referenced: {', '.join(finding.secrets_referenced[:5])}")
                if len(finding.secrets_referenced) > 5:
                    lines.append(f"       ... and {len(finding.secrets_referenced) - 5} more")

            if finding.cloud_providers:
                lines.append(f"     Cloud Providers: {', '.join(finding.cloud_providers)}")

            if finding.services_exposed:
                lines.append("     Internal Services:")
                for svc in finding.services_exposed[:5]:
                    lines.append(f"       - {svc}")

            if finding.attack_vectors:
                lines.append(f"     ⚠️  Attack Vectors: {', '.join(finding.attack_vectors)}")

    lines.append("\n" + "=" * 80)
    return "\n".join(lines)
