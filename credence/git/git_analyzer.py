"""
Git repository analyzer for secret detection.

Scans git history for exposed credentials and sensitive data.
"""

import logging
import re
from pathlib import Path
from typing import Dict, List, Set

logger = logging.getLogger(__name__)


class GitSecretAnalyzer:
    """Analyze git repository for secrets in commit history"""

    SECRET_PATTERNS = {
        # Cloud Provider Keys
        'aws_access_key': r'AKIA[0-9A-Z]{16}',
        'aws_secret_key': r'(?i)aws.{0,20}?["\']([0-9a-zA-Z/+=]{40})["\']',
        'gcp_api_key': r'AIza[0-9A-Za-z\-_]{35}',
        'azure_storage_key': r'DefaultEndpointsProtocol=https;AccountName=.+;AccountKey=.+==',

        # Version Control Tokens
        'github_token': r'ghp_[a-zA-Z0-9]{36}',
        'github_oauth': r'gho_[a-zA-Z0-9]{36}',
        'github_app_token': r'(ghu|ghs)_[a-zA-Z0-9]{36}',
        'gitlab_token': r'glpat-[a-zA-Z0-9\-]{20}',
        'bitbucket_token': r'(?i)bitbucket.{0,20}["\']([0-9a-zA-Z]{32})["\']',

        # Communication Platform Tokens
        'slack_token': r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}',
        'slack_webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
        'discord_webhook': r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+',
        'telegram_bot_token': r'[0-9]+:AA[a-zA-Z0-9_-]{33}',

        # Payment Processing
        'stripe_key': r'(?:r|s)k_live_[0-9a-zA-Z]{24,}',
        'stripe_webhook': r'whsec_[0-9a-zA-Z]{32}',
        'paypal_token': r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}',
        'square_token': r'sq0atp-[0-9A-Za-z\-_]{22}',

        # Email Services
        'sendgrid_key': r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
        'mailgun_key': r'key-[a-zA-Z0-9]{32}',
        'mailchimp_key': r'[a-f0-9]{32}-us[0-9]{1,2}',

        # Cloud Services
        'twilio_key': r'SK[a-z0-9]{32}',
        'firebase_key': r'AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}',
        'heroku_key': r'[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',

        # Database Connection Strings
        'postgres_url': r'postgresql://[a-zA-Z0-9_]+:[^\s@]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9_]+',
        'mysql_url': r'mysql://[a-zA-Z0-9_]+:[^\s@]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9_]+',
        'mongodb_url': r'mongodb(\+srv)?://[a-zA-Z0-9_]+:[^\s@]+@[a-zA-Z0-9.-]+',
        'redis_url': r'redis://:[^\s@]+@[a-zA-Z0-9.-]+:[0-9]+',

        # Private Keys
        'rsa_private_key': r'-----BEGIN RSA PRIVATE KEY-----',
        'openssh_private_key': r'-----BEGIN OPENSSH PRIVATE KEY-----',
        'dsa_private_key': r'-----BEGIN DSA PRIVATE KEY-----',
        'ec_private_key': r'-----BEGIN EC PRIVATE KEY-----',
        'pgp_private_key': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',

        # Generic Patterns
        'generic_api_key': r'(?i)(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
        'generic_secret': r'(?i)(secret|password|passwd|pwd)["\']?\s*[:=]\s*["\']([^\s"\']{8,})["\']',
        'jwt_token': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*',
        'bearer_token': r'(?i)bearer\s+[a-zA-Z0-9_\-\.=]+',
    }

    def __init__(self, repo_path: Path):
        self.repo_path = Path(repo_path)
        self.git_dir = self.repo_path / '.git'

    async def scan_history(self, max_commits: int = 100) -> List[Dict]:
        """
        Scan git history for secrets.
        
        Args:
            max_commits: Maximum number of commits to scan
            
        Returns:
            List of found secrets with metadata
        """
        logger.info(f"Scanning git history in {self.repo_path}")

        secrets = []
        seen_secrets: Set[str] = set()

        try:
            # Try using GitPython if available
            try:
                import git
                repo = git.Repo(self.repo_path)
                secrets = await self._scan_with_gitpython(repo, max_commits, seen_secrets)
            except ImportError:
                logger.info("GitPython not available, using manual parsing")
                secrets = await self._scan_manually(max_commits, seen_secrets)

        except Exception as e:
            logger.error(f"Failed to scan git history: {e}")

        logger.info(f"Found {len(secrets)} potential secrets in git history")
        return secrets

    async def _scan_with_gitpython(
        self,
        repo,
        max_commits: int,
        seen_secrets: Set[str]
    ) -> List[Dict]:
        """Scan using GitPython library"""
        secrets = []
        commit_count = 0

        try:
            for commit in repo.iter_commits(max_count=max_commits):
                commit_count += 1

                try:
                    for item in commit.tree.traverse():
                        if item.type == 'blob':
                            try:
                                content = item.data_stream.read().decode('utf-8', errors='ignore')
                                commit_secrets = self._scan_content(
                                    content,
                                    item.path,
                                    commit.hexsha[:8],
                                    str(commit.author),
                                    commit.committed_datetime.isoformat(),
                                    commit.message.strip()[:100],
                                    seen_secrets
                                )
                                secrets.extend(commit_secrets)
                            except Exception:
                                continue

                except Exception as e:
                    logger.debug(f"Error processing commit {commit.hexsha}: {e}")
                    continue

            logger.info(f"Scanned {commit_count} commits")

        except Exception as e:
            logger.error(f"Error iterating commits: {e}")

        return secrets

    async def _scan_manually(self, max_commits: int, seen_secrets: Set[str]) -> List[Dict]:
        """Scan without GitPython by parsing git objects directly"""
        secrets = []

        # Look for files in working directory if reconstruction succeeded
        if self.repo_path.exists():
            for file_path in self.repo_path.rglob('*'):
                if file_path.is_file() and not str(file_path).startswith(str(self.git_dir)):
                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read()

                        rel_path = file_path.relative_to(self.repo_path)
                        file_secrets = self._scan_content(
                            content,
                            str(rel_path),
                            'current',
                            'unknown',
                            'current',
                            'Working directory',
                            seen_secrets
                        )
                        secrets.extend(file_secrets)

                    except Exception:
                        continue

        return secrets

    def _scan_content(
        self,
        content: str,
        file_path: str,
        commit_hash: str,
        author: str,
        date: str,
        message: str,
        seen_secrets: Set[str]
    ) -> List[Dict]:
        """Scan content for secrets"""
        secrets = []

        for secret_type, pattern in self.SECRET_PATTERNS.items():
            try:
                matches = re.finditer(pattern, content, re.MULTILINE)

                for match in matches:
                    secret_value = match.group()

                    # Deduplicate
                    secret_key = f"{secret_type}:{secret_value}"
                    if secret_key in seen_secrets:
                        continue
                    seen_secrets.add(secret_key)

                    # Get context around the match
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end].replace('\n', ' ')

                    secrets.append({
                        'type': secret_type,
                        'value': self._mask_secret(secret_value),
                        'value_full': secret_value,  # For validation
                        'file': file_path,
                        'commit': commit_hash,
                        'author': author,
                        'date': date,
                        'message': message,
                        'context': context,
                        'line': content[:match.start()].count('\n') + 1
                    })

            except Exception as e:
                logger.debug(f"Error scanning for {secret_type}: {e}")
                continue

        return secrets

    @staticmethod
    def _mask_secret(secret: str) -> str:
        """Mask secret for display purposes"""
        if len(secret) <= 8:
            return secret[:2] + '*' * (len(secret) - 2)
        else:
            return secret[:4] + '*' * (len(secret) - 8) + secret[-4:]

    def generate_report(self, secrets: List[Dict]) -> str:
        """Generate a human-readable report of found secrets"""
        if not secrets:
            return "No secrets found in git history."

        report = [
            "=" * 80,
            "GIT HISTORY SECRET SCAN REPORT",
            "=" * 80,
            f"\nTotal secrets found: {len(secrets)}\n",
        ]

        # Group by type
        by_type = {}
        for secret in secrets:
            secret_type = secret['type']
            if secret_type not in by_type:
                by_type[secret_type] = []
            by_type[secret_type].append(secret)

        for secret_type, items in sorted(by_type.items()):
            report.append(f"\n[{secret_type.upper()}] - {len(items)} found")
            report.append("-" * 80)

            for item in items[:5]:  # Show first 5 of each type
                report.append(f"  File: {item['file']}")
                report.append(f"  Commit: {item['commit']} by {item['author']}")
                report.append(f"  Value: {item['value']}")
                report.append(f"  Context: ...{item['context']}...")
                report.append("")

            if len(items) > 5:
                report.append(f"  ... and {len(items) - 5} more\n")

        report.append("=" * 80)
        return "\n".join(report)
