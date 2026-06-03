"""
Infrastructure as Code (IaC) Security Scanner.

Detects exposed IaC files and analyzes them for security misconfigurations:
- Terraform configurations
- Kubernetes manifests
- Docker Compose files
- Ansible playbooks
- CloudFormation templates
- Helm charts

These files often expose cloud architecture, credentials, and vulnerabilities.
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


class IaCType(Enum):
    """Supported IaC types."""
    TERRAFORM = "terraform"
    KUBERNETES = "kubernetes"
    DOCKER_COMPOSE = "docker_compose"
    DOCKERFILE = "dockerfile"
    ANSIBLE = "ansible"
    CLOUDFORMATION = "cloudformation"
    HELM = "helm"
    VAGRANT = "vagrant"
    PULUMI = "pulumi"
    UNKNOWN = "unknown"


class SecurityIssueType(Enum):
    """Types of security issues in IaC."""
    HARDCODED_SECRET = "hardcoded_secret"
    OVERLY_PERMISSIVE = "overly_permissive"
    UNENCRYPTED_DATA = "unencrypted_data"
    PRIVILEGED_CONTAINER = "privileged_container"
    EXPOSED_PORT = "exposed_port"
    MISSING_RESOURCE_LIMITS = "missing_resource_limits"
    ROOT_USER = "root_user"
    INSECURE_PROTOCOL = "insecure_protocol"
    PUBLIC_ACCESS = "public_access"
    MISSING_LOGGING = "missing_logging"


@dataclass
class SecurityIssue:
    """Represents a security issue found in IaC."""
    issue_type: SecurityIssueType
    severity: str
    description: str
    line_number: int = 0
    remediation: str = ""
    resource_name: str = ""


@dataclass
class IaCFinding:
    """Represents a discovered IaC file exposure."""
    iac_type: IaCType
    file_path: str
    url: str
    severity: str
    content: str
    security_issues: List[SecurityIssue] = field(default_factory=list)
    resources_exposed: List[str] = field(default_factory=list)
    cloud_provider: Optional[str] = None
    metadata: Dict = field(default_factory=dict)


class IaCScanner:
    """
    Scan for exposed Infrastructure as Code files.
    
    Features:
    - Detect exposed IaC configuration files
    - Analyze for security misconfigurations
    - Identify hardcoded credentials
    - Map infrastructure architecture
    - Detect privileged configurations
    """

    # IaC paths to scan
    IAC_PATHS = {
        IaCType.TERRAFORM: [
            'main.tf',
            'variables.tf',
            'outputs.tf',
            'providers.tf',
            'terraform.tfvars',
            'terraform.tfstate',
            '.terraform/terraform.tfstate',
            'infrastructure/main.tf',
            'terraform/main.tf',
            'infra/main.tf',
            'deploy/terraform/main.tf',
        ],

        IaCType.KUBERNETES: [
            'kubernetes.yml',
            'kubernetes.yaml',
            'k8s.yml',
            'k8s.yaml',
            'deployment.yml',
            'deployment.yaml',
            'service.yml',
            'service.yaml',
            'configmap.yml',
            'configmap.yaml',
            'secret.yml',
            'secret.yaml',
            'ingress.yml',
            'ingress.yaml',
            'namespace.yml',
            'kustomization.yaml',
            'k8s/deployment.yaml',
            'kubernetes/deployment.yaml',
            'manifests/deployment.yaml',
        ],

        IaCType.DOCKER_COMPOSE: [
            'docker-compose.yml',
            'docker-compose.yaml',
            'docker-compose.dev.yml',
            'docker-compose.prod.yml',
            'docker-compose.override.yml',
            'compose.yml',
            'compose.yaml',
        ],

        IaCType.DOCKERFILE: [
            'Dockerfile',
            'Dockerfile.dev',
            'Dockerfile.prod',
            'Dockerfile.test',
            'docker/Dockerfile',
            '.docker/Dockerfile',
        ],

        IaCType.ANSIBLE: [
            'playbook.yml',
            'playbook.yaml',
            'site.yml',
            'main.yml',
            'ansible/playbook.yml',
            'ansible/site.yml',
            'group_vars/all.yml',
            'host_vars/localhost.yml',
            'inventory.yml',
            'ansible.cfg',
        ],

        IaCType.CLOUDFORMATION: [
            'template.yml',
            'template.yaml',
            'template.json',
            'cloudformation.yml',
            'cloudformation.yaml',
            'stack.yml',
            'stack.yaml',
            'infrastructure.yml',
            'aws/cloudformation.yml',
        ],

        IaCType.HELM: [
            'Chart.yaml',
            'values.yaml',
            'values.dev.yaml',
            'values.prod.yaml',
            'templates/deployment.yaml',
            'templates/service.yaml',
            'templates/configmap.yaml',
            'charts/Chart.yaml',
            'helm/Chart.yaml',
        ],

        IaCType.VAGRANT: [
            'Vagrantfile',
            'vagrant/Vagrantfile',
        ],

        IaCType.PULUMI: [
            'Pulumi.yaml',
            'Pulumi.dev.yaml',
            'Pulumi.prod.yaml',
        ],
    }

    # Security check rules per IaC type
    SECURITY_RULES = {
        IaCType.TERRAFORM: {
            'hardcoded_secret': [
                (r'password\s*=\s*"[^${}]+"', 'Hardcoded password in Terraform'),
                (r'secret\s*=\s*"[^${}]+"', 'Hardcoded secret in Terraform'),
                (r'api_key\s*=\s*"[^${}]+"', 'Hardcoded API key in Terraform'),
                (r'access_key\s*=\s*"AKIA[A-Z0-9]{16}"', 'Hardcoded AWS access key'),
            ],
            'public_access': [
                (r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]', 'Public access allowed (0.0.0.0/0)'),
                (r'publicly_accessible\s*=\s*true', 'Resource is publicly accessible'),
                (r'acl\s*=\s*"public', 'Public ACL configured'),
            ],
            'unencrypted': [
                (r'encrypted\s*=\s*false', 'Encryption disabled'),
                (r'storage_encrypted\s*=\s*false', 'Storage encryption disabled'),
            ],
        },

        IaCType.KUBERNETES: {
            'privileged_container': [
                (r'privileged:\s*true', 'Privileged container detected'),
                (r'runAsRoot:\s*true', 'Running as root'),
                (r'runAsUser:\s*0', 'Running as UID 0 (root)'),
                (r'allowPrivilegeEscalation:\s*true', 'Privilege escalation allowed'),
            ],
            'hardcoded_secret': [
                (r'password:\s*["\'][^${}]+["\']', 'Hardcoded password in manifest'),
                (r'apiKey:\s*["\'][^${}]+["\']', 'Hardcoded API key in manifest'),
            ],
            'missing_limits': [
                (r'resources:\s*\{\}', 'Empty resource limits'),
            ],
            'host_network': [
                (r'hostNetwork:\s*true', 'Host network enabled'),
                (r'hostPID:\s*true', 'Host PID namespace enabled'),
                (r'hostIPC:\s*true', 'Host IPC namespace enabled'),
            ],
        },

        IaCType.DOCKER_COMPOSE: {
            'privileged_container': [
                (r'privileged:\s*true', 'Privileged container'),
            ],
            'exposed_port': [
                (r'ports:\s*\n\s*-\s*"?0\.0\.0\.0:', 'Port bound to all interfaces'),
                (r'ports:\s*\n\s*-\s*"?\d+:\d+"?', 'Port exposed'),
            ],
            'hardcoded_secret': [
                (r'PASSWORD\s*[:=]\s*["\']?[^${}]+', 'Hardcoded password'),
                (r'SECRET\s*[:=]\s*["\']?[^${}]+', 'Hardcoded secret'),
            ],
            'root_user': [
                (r'user:\s*root', 'Running as root user'),
                (r'user:\s*0', 'Running as UID 0'),
            ],
        },

        IaCType.DOCKERFILE: {
            'root_user': [
                (r'^(?!.*USER\s+\S).*$', 'No USER directive, running as root'),
            ],
            'hardcoded_secret': [
                (r'ENV\s+\w*(?:PASSWORD|SECRET|KEY|TOKEN)\w*\s*=\s*\S+', 'Secret in ENV'),
                (r'ARG\s+\w*(?:PASSWORD|SECRET|KEY|TOKEN)\w*\s*=\s*\S+', 'Secret in ARG'),
            ],
            'insecure_protocol': [
                (r'http://', 'Insecure HTTP protocol used'),
                (r'curl\s+--insecure', 'Insecure curl with certificate bypass'),
                (r'wget\s+--no-check-certificate', 'Certificate verification disabled'),
            ],
            'latest_tag': [
                (r'FROM\s+\S+:latest', 'Using :latest tag (unpinned version)'),
                (r'FROM\s+\S+\s*$', 'No tag specified (defaults to latest)'),
            ],
        },

        IaCType.ANSIBLE: {
            'hardcoded_secret': [
                (r'password:\s*["\'][^{]+["\']', 'Hardcoded password'),
                (r'ansible_ssh_pass:\s*\S+', 'Hardcoded SSH password'),
                (r'api_key:\s*["\'][^{]+["\']', 'Hardcoded API key'),
            ],
            'no_encryption': [
                (r'no_log:\s*false', 'Logging enabled for sensitive task'),
            ],
        },

        IaCType.CLOUDFORMATION: {
            'hardcoded_secret': [
                (r'"Password"\s*:\s*"[^{]+?"', 'Hardcoded password'),
                (r'"SecretKey"\s*:\s*"[^{]+?"', 'Hardcoded secret key'),
            ],
            'public_access': [
                (r'"CidrIp"\s*:\s*"0\.0\.0\.0/0"', 'Public access allowed'),
                (r'"PubliclyAccessible"\s*:\s*true', 'Publicly accessible'),
            ],
        },
    }

    # Remediation advice
    REMEDIATION = {
        SecurityIssueType.HARDCODED_SECRET: "Use environment variables, secrets management, or encrypted vault",
        SecurityIssueType.PRIVILEGED_CONTAINER: "Remove privileged flag and use minimal capabilities",
        SecurityIssueType.ROOT_USER: "Add USER directive with non-root user",
        SecurityIssueType.PUBLIC_ACCESS: "Restrict CIDR blocks to specific IP ranges",
        SecurityIssueType.EXPOSED_PORT: "Bind to localhost (127.0.0.1) if possible",
        SecurityIssueType.INSECURE_PROTOCOL: "Use HTTPS and verify certificates",
        SecurityIssueType.UNENCRYPTED_DATA: "Enable encryption at rest",
        SecurityIssueType.MISSING_RESOURCE_LIMITS: "Define CPU and memory limits",
    }

    def __init__(
        self,
        session: Optional[aiohttp.ClientSession] = None,
        timeout: int = 10,
        max_concurrent: int = 20,
        analyze_security: bool = True
    ):
        """
        Initialize IaC Scanner.
        
        Args:
            session: aiohttp session (created if not provided)
            timeout: Request timeout in seconds
            max_concurrent: Maximum concurrent requests
            analyze_security: Whether to analyze for security issues
        """
        self.session = session
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.analyze_security = analyze_security

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

    async def scan_target(self, target_url: str) -> List[IaCFinding]:
        """
        Scan a target for exposed IaC files.
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            List of IaCFinding objects
        """
        findings = []
        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks = []

        # Generate all paths to check
        for iac_type, paths in self.IAC_PATHS.items():
            for path in paths:
                url = urljoin(target_url.rstrip('/') + '/', path)
                tasks.append(self._check_path(url, path, iac_type, semaphore))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, IaCFinding):
                findings.append(result)

        logger.info(f"Found {len(findings)} IaC configurations")
        return findings

    async def _check_path(
        self,
        url: str,
        path: str,
        iac_type: IaCType,
        semaphore: asyncio.Semaphore
    ) -> Optional[IaCFinding]:
        """Check a single IaC path."""

        async with semaphore:
            try:
                async with self.session.get(url, ssl=False) as resp:
                    if resp.status != 200:
                        return None

                    content = await resp.text()

                    # Validate content looks like IaC
                    if not self._validate_iac_content(content, iac_type):
                        return None

                    # Analyze for security issues
                    security_issues = []
                    resources = []
                    cloud_provider = None

                    if self.analyze_security:
                        security_issues = self._analyze_security(content, iac_type)
                        resources = self._extract_resources(content, iac_type)
                        cloud_provider = self._detect_cloud_provider(content)

                    severity = self._calculate_severity(iac_type, security_issues)

                    return IaCFinding(
                        iac_type=iac_type,
                        file_path=path,
                        url=url,
                        severity=severity,
                        content=content[:10000],  # Limit stored content
                        security_issues=security_issues,
                        resources_exposed=resources,
                        cloud_provider=cloud_provider,
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

    def _validate_iac_content(self, content: str, iac_type: IaCType) -> bool:
        """Validate that content looks like valid IaC."""

        validators = {
            IaCType.TERRAFORM: ['resource', 'provider', 'variable', 'output', 'module'],
            IaCType.KUBERNETES: ['apiVersion', 'kind', 'metadata', 'spec'],
            IaCType.DOCKER_COMPOSE: ['version', 'services', 'volumes', 'networks'],
            IaCType.DOCKERFILE: ['FROM', 'RUN', 'COPY', 'CMD', 'ENTRYPOINT'],
            IaCType.ANSIBLE: ['hosts', 'tasks', 'vars', 'roles', 'become'],
            IaCType.CLOUDFORMATION: ['AWSTemplateFormatVersion', 'Resources', 'Parameters'],
            IaCType.HELM: ['apiVersion', 'name', 'version', 'description'],
            IaCType.VAGRANT: ['Vagrant', 'config.vm', 'define'],
            IaCType.PULUMI: ['name', 'runtime', 'description'],
        }

        keywords = validators.get(iac_type, [])
        matches = sum(1 for kw in keywords if kw in content)
        return matches >= 2

    def _analyze_security(self, content: str, iac_type: IaCType) -> List[SecurityIssue]:
        """Analyze IaC content for security issues."""
        issues = []

        rules = self.SECURITY_RULES.get(iac_type, {})

        for issue_category, patterns in rules.items():
            for pattern, description in patterns:
                matches = list(re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE))

                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1

                    # Map category to issue type
                    issue_type = self._map_issue_type(issue_category)
                    severity = self._get_issue_severity(issue_type)

                    issues.append(SecurityIssue(
                        issue_type=issue_type,
                        severity=severity,
                        description=description,
                        line_number=line_num,
                        remediation=self.REMEDIATION.get(issue_type, "Review and fix configuration"),
                    ))

        return issues

    def _map_issue_type(self, category: str) -> SecurityIssueType:
        """Map category string to SecurityIssueType."""
        mapping = {
            'hardcoded_secret': SecurityIssueType.HARDCODED_SECRET,
            'privileged_container': SecurityIssueType.PRIVILEGED_CONTAINER,
            'public_access': SecurityIssueType.PUBLIC_ACCESS,
            'exposed_port': SecurityIssueType.EXPOSED_PORT,
            'root_user': SecurityIssueType.ROOT_USER,
            'insecure_protocol': SecurityIssueType.INSECURE_PROTOCOL,
            'unencrypted': SecurityIssueType.UNENCRYPTED_DATA,
            'missing_limits': SecurityIssueType.MISSING_RESOURCE_LIMITS,
            'host_network': SecurityIssueType.OVERLY_PERMISSIVE,
            'latest_tag': SecurityIssueType.OVERLY_PERMISSIVE,
            'no_encryption': SecurityIssueType.UNENCRYPTED_DATA,
        }
        return mapping.get(category, SecurityIssueType.OVERLY_PERMISSIVE)

    def _get_issue_severity(self, issue_type: SecurityIssueType) -> str:
        """Get severity for an issue type."""
        severity_map = {
            SecurityIssueType.HARDCODED_SECRET: 'critical',
            SecurityIssueType.PRIVILEGED_CONTAINER: 'critical',
            SecurityIssueType.PUBLIC_ACCESS: 'high',
            SecurityIssueType.ROOT_USER: 'high',
            SecurityIssueType.EXPOSED_PORT: 'medium',
            SecurityIssueType.UNENCRYPTED_DATA: 'medium',
            SecurityIssueType.INSECURE_PROTOCOL: 'medium',
            SecurityIssueType.MISSING_RESOURCE_LIMITS: 'low',
            SecurityIssueType.MISSING_LOGGING: 'low',
        }
        return severity_map.get(issue_type, 'medium')

    def _extract_resources(self, content: str, iac_type: IaCType) -> List[str]:
        """Extract resource names from IaC content."""
        resources = []

        if iac_type == IaCType.TERRAFORM:
            # Match resource "type" "name"
            matches = re.findall(r'resource\s+"([^"]+)"\s+"([^"]+)"', content)
            resources.extend([f"{t}.{n}" for t, n in matches])

        elif iac_type == IaCType.KUBERNETES:
            # Match kind and name
            kinds = re.findall(r'kind:\s*(\S+)', content)
            names = re.findall(r'name:\s*(\S+)', content)
            resources.extend([f"{k}/{n}" for k, n in zip(kinds, names)])

        elif iac_type == IaCType.DOCKER_COMPOSE:
            # Match service names
            matches = re.findall(r'^\s*(\w+):\s*$', content, re.MULTILINE)
            resources.extend(matches)

        return resources[:20]  # Limit

    def _detect_cloud_provider(self, content: str) -> Optional[str]:
        """Detect cloud provider from content."""
        content_lower = content.lower()

        if any(x in content_lower for x in ['aws', 'amazonaws', 'arn:aws']):
            return 'aws'
        elif any(x in content_lower for x in ['azure', 'microsoft', '.azure.']):
            return 'azure'
        elif any(x in content_lower for x in ['gcp', 'google', 'googleapis']):
            return 'gcp'
        elif 'digitalocean' in content_lower:
            return 'digitalocean'

        return None

    def _calculate_severity(self, iac_type: IaCType, issues: List[SecurityIssue]) -> str:
        """Calculate overall severity."""

        if not issues:
            # Terraform state files are always critical
            if iac_type == IaCType.TERRAFORM:
                return 'high'
            return 'medium'

        # Get highest severity issue
        severities = ['critical', 'high', 'medium', 'low']
        for sev in severities:
            if any(i.severity == sev for i in issues):
                return sev

        return 'low'


def generate_iac_report(findings: List[IaCFinding]) -> str:
    """Generate a formatted report of IaC findings."""

    if not findings:
        return "No exposed IaC configurations detected.\n"

    # Count security issues
    total_issues = sum(len(f.security_issues) for f in findings)
    critical_issues = sum(
        1 for f in findings for i in f.security_issues if i.severity == 'critical'
    )

    lines = [
        "=" * 80,
        "INFRASTRUCTURE AS CODE EXPOSURE REPORT",
        "=" * 80,
        f"\nTotal exposed configurations: {len(findings)}",
        f"Total security issues: {total_issues}",
        f"Critical issues: {critical_issues}",
        ""
    ]

    # Group by type
    by_type = {}
    for finding in findings:
        iac_type = finding.iac_type.value
        if iac_type not in by_type:
            by_type[iac_type] = []
        by_type[iac_type].append(finding)

    for iac_type, type_findings in sorted(by_type.items()):
        lines.append(f"\n[{iac_type.upper()}] - {len(type_findings)} files")
        lines.append("-" * 60)

        for finding in type_findings:
            severity_icon = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🔵'
            }.get(finding.severity, '⚪')

            lines.append(f"\n  {severity_icon} {finding.file_path}")
            lines.append(f"     URL: {finding.url}")
            lines.append(f"     Severity: {finding.severity.upper()}")

            if finding.cloud_provider:
                lines.append(f"     Cloud Provider: {finding.cloud_provider.upper()}")

            if finding.resources_exposed:
                lines.append(f"     Resources: {', '.join(finding.resources_exposed[:5])}")

            if finding.security_issues:
                lines.append(f"\n     ⚠️  Security Issues ({len(finding.security_issues)}):")
                for issue in finding.security_issues[:5]:
                    lines.append(f"       - [{issue.severity.upper()}] {issue.description}")
                    lines.append(f"         Line: {issue.line_number}")
                    lines.append(f"         Fix: {issue.remediation}")

                if len(finding.security_issues) > 5:
                    lines.append(f"       ... and {len(finding.security_issues) - 5} more")

    lines.append("\n" + "=" * 80)
    return "\n".join(lines)
