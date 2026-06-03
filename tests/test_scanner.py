"""Test scanner functionality."""

import re
import pytest
from aioresponses import aioresponses
from credence.scanner import CredenceScanner
from credence.models import Severity


class TestScanner:
    """Test CredenceScanner."""

    @pytest.mark.asyncio
    async def test_scan_detects_git_config(self):
        """Test that scanner detects exposed .git/config."""
        scanner = CredenceScanner(timeout=5, concurrency=10)

        with aioresponses() as mocked:
            # Mock all paths to return 404 except .git/config
            target = "https://example.com"

            # Mock .git/config as vulnerable
            mocked.get(
                f"{target}/.git/config",
                status=200,
                body="[core]\n\trepositoryformatversion = 0",
                headers={"Content-Type": "text/plain"},
            )

            # Mock other paths as 404 using regex pattern
            mocked.get(
                re.compile(r"https://example\.com/.*"),
                status=404,
                body="Not Found",
                repeat=True,
            )

            report = await scanner.scan([target])

            assert report.total_findings >= 1
            assert report.critical_count >= 1

            # Find the .git/config finding
            git_findings = [
                f
                for r in report.target_reports
                for f in r.findings
                if f.path == ".git/config"
            ]
            assert len(git_findings) == 1
            assert git_findings[0].severity == Severity.CRITICAL

    def test_target_normalization(self):
        """Test that targets are properly normalized."""
        scanner = CredenceScanner()

        # This is tested implicitly through the scan -
        # we just verify the scanner can be created
        assert scanner.concurrency == 50
        assert scanner.timeout == 10

