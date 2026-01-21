"""
Secret extraction and validation.

Extracts credentials and secrets from responses, then validates them.
"""

import logging
import re
from typing import Dict, List, Optional, Set

import aiohttp

logger = logging.getLogger(__name__)


class SecretExtractor:
    """Extract secrets from content"""

    # Reuse patterns from GitSecretAnalyzer
    PATTERNS = {
        'aws_access_key': r'AKIA[0-9A-Z]{16}',
        'aws_secret_key': r'(?i)aws.{0,20}?["\']([0-9a-zA-Z/+=]{40})["\']',
        'gcp_api_key': r'AIza[0-9A-Za-z\-_]{35}',
        'github_token': r'gh[ps]_[a-zA-Z0-9]{36}',
        'slack_token': r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}',
        'slack_webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
        'stripe_key': r'(?:r|s)k_live_[0-9a-zA-Z]{24,}',
        'sendgrid_key': r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
        'postgres_url': r'postgresql://[a-zA-Z0-9_]+:[^\s@]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9_]+',
        'mysql_url': r'mysql://[a-zA-Z0-9_]+:[^\s@]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9_]+',
        'mongodb_url': r'mongodb(\+srv)?://[a-zA-Z0-9_]+:[^\s@]+@[a-zA-Z0-9.-]+',
        'private_key': r'-----BEGIN (?:RSA |OPENSSH |DSA |EC |)PRIVATE KEY-----',
        'jwt_token': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*',
        'generic_api_key': r'(?i)(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
        'generic_password': r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']([^\s"\']{8,})["\']',
    }

    def __init__(self, validate: bool = False):
        self.validate = validate
        self.validator = SecretValidator() if validate else None

    async def extract(self, content: str, source: str = "unknown") -> List[Dict]:
        """
        Extract secrets from content.
        
        Args:
            content: Text content to scan
            source: Source identifier (URL, file path, etc.)
            
        Returns:
            List of found secrets
        """
        secrets = []
        seen: Set[str] = set()

        for secret_type, pattern in self.PATTERNS.items():
            try:
                matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)

                for match in matches:
                    secret_value = match.group()

                    # Deduplicate
                    if secret_value in seen:
                        continue
                    seen.add(secret_value)

                    # Get line number
                    line_num = content[:match.start()].count('\n') + 1

                    # Get context
                    start = max(0, match.start() - 40)
                    end = min(len(content), match.end() + 40)
                    context = content[start:end].replace('\n', ' ')

                    secret_info = {
                        'type': secret_type,
                        'value': self._mask_value(secret_value),
                        'value_full': secret_value,
                        'source': source,
                        'line': line_num,
                        'context': context,
                        'validated': None
                    }

                    # Validate if requested
                    if self.validate and self.validator:
                        is_valid = await self.validator.validate(secret_type, secret_value)
                        secret_info['validated'] = is_valid

                    secrets.append(secret_info)

            except Exception as e:
                logger.debug(f"Error extracting {secret_type}: {e}")

        return secrets

    @staticmethod
    def _mask_value(value: str) -> str:
        """Mask secret value for display"""
        if len(value) <= 8:
            return value[:2] + '*' * (len(value) - 2)
        return value[:4] + '*' * (len(value) - 8) + value[-4:]


class SecretValidator:
    """Validate extracted secrets"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    async def validate(self, secret_type: str, secret_value: str) -> Optional[bool]:
        """
        Validate a secret by testing it.
        
        Args:
            secret_type: Type of secret
            secret_value: Secret value to validate
            
        Returns:
            True if valid, False if invalid, None if unknown
        """
        validators = {
            'github_token': self._validate_github,
            'slack_token': self._validate_slack,
            'stripe_key': self._validate_stripe,
        }

        validator = validators.get(secret_type)
        if validator:
            try:
                return await validator(secret_value)
            except Exception as e:
                logger.debug(f"Validation error for {secret_type}: {e}")
                return None

        return None  # Cannot validate this type

    async def _validate_github(self, token: str) -> bool:
        """Validate GitHub token"""
        try:
            async with aiohttp.ClientSession() as session:
                headers = {'Authorization': f'token {token}'}
                async with session.get(
                    'https://api.github.com/user',
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def _validate_slack(self, token: str) -> bool:
        """Validate Slack token"""
        try:
            async with aiohttp.ClientSession() as session:
                headers = {'Authorization': f'Bearer {token}'}
                async with session.get(
                    'https://slack.com/api/auth.test',
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get('ok', False)
                    return False
        except Exception:
            return False

    async def _validate_stripe(self, key: str) -> bool:
        """Validate Stripe key"""
        try:
            async with aiohttp.ClientSession() as session:
                auth = aiohttp.BasicAuth(key, '')
                async with session.get(
                    'https://api.stripe.com/v1/charges?limit=1',
                    auth=auth,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as resp:
                    return resp.status != 401
        except Exception:
            return False


class SecretExporter:
    """Export secrets to various formats"""

    @staticmethod
    def to_json(secrets: List[Dict]) -> str:
        """Export to JSON"""
        import json
        # Remove full values from export
        export_secrets = []
        for secret in secrets:
            export_secret = secret.copy()
            if 'value_full' in export_secret:
                del export_secret['value_full']
            export_secrets.append(export_secret)

        return json.dumps(export_secrets, indent=2)

    @staticmethod
    def to_csv(secrets: List[Dict]) -> str:
        """Export to CSV"""
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow(['Type', 'Value', 'Source', 'Line', 'Validated', 'Context'])

        # Data
        for secret in secrets:
            writer.writerow([
                secret['type'],
                secret['value'],
                secret['source'],
                secret['line'],
                secret.get('validated', 'N/A'),
                secret['context'][:100]
            ])

        return output.getvalue()

    @staticmethod
    def to_markdown(secrets: List[Dict]) -> str:
        """Export to Markdown"""
        if not secrets:
            return "No secrets found.\n"

        lines = [
            "# Secret Scan Results",
            "",
            f"**Total Secrets Found:** {len(secrets)}",
            ""
        ]

        # Group by type
        by_type = {}
        for secret in secrets:
            t = secret['type']
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(secret)

        for secret_type, items in sorted(by_type.items()):
            lines.append(f"## {secret_type.replace('_', ' ').title()} ({len(items)})")
            lines.append("")

            for item in items:
                lines.append(f"- **Value:** `{item['value']}`")
                lines.append(f"  - **Source:** {item['source']}")
                lines.append(f"  - **Line:** {item['line']}")

                if item.get('validated') is not None:
                    status = "✅ Valid" if item['validated'] else "❌ Invalid"
                    lines.append(f"  - **Status:** {status}")

                lines.append("")

        return "\n".join(lines)
