"""
Async HTTP scanner engine.

Handles concurrent scanning of multiple targets and paths using aiohttp.
"""

import asyncio
import logging
from datetime import datetime
from typing import List, Optional

import aiohttp
from aiohttp import ClientTimeout, TCPConnector

from .models import (
    PathDefinition,
    ScanReport,
    ScanResult,
    Severity,
    TargetReport,
)
from .paths import get_all_paths
from .signatures import validate_response

logger = logging.getLogger(__name__)


class GitExposeScanner:
    """Async scanner for exposed sensitive files."""

    def __init__(
        self,
        timeout: int = 10,
        concurrency: int = 50,
        user_agent: str = "GitExpose/1.0 (Security Scanner)",
        follow_redirects: bool = False,
        paths: Optional[List[PathDefinition]] = None,
    ):
        """
        Initialize scanner.

        Args:
            timeout: Request timeout in seconds
            concurrency: Max concurrent requests
            user_agent: User-Agent header value
            follow_redirects: Whether to follow redirects
            paths: Custom paths to scan (uses default if None)
        """
        self.timeout = timeout
        self.concurrency = concurrency
        self.user_agent = user_agent
        self.follow_redirects = follow_redirects
        self.paths = paths or get_all_paths()

        logger.info(
            f"Scanner initialized: timeout={timeout}s, "
            f"concurrency={concurrency}, paths={len(self.paths)}"
        )

    async def _create_session(self) -> aiohttp.ClientSession:
        """Create configured aiohttp session."""
        timeout = ClientTimeout(
            total=self.timeout,
            connect=5,
            sock_read=self.timeout,
        )

        connector = TCPConnector(
            limit=self.concurrency * 2,
            limit_per_host=10,
            ssl=False,  # Skip SSL verification for scanning
            enable_cleanup_closed=True,
        )

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }

        return aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=headers,
        )

    async def _scan_single_path(
        self,
        session: aiohttp.ClientSession,
        target: str,
        path_def: PathDefinition,
        semaphore: asyncio.Semaphore,
    ) -> ScanResult:
        """
        Scan a single path on a target.

        Args:
            session: aiohttp session
            target: Base target URL
            path_def: Path definition to scan
            semaphore: Concurrency control semaphore

        Returns:
            ScanResult object
        """
        url = f"{target.rstrip('/')}/{path_def.path.lstrip('/')}"

        async with semaphore:
            try:
                logger.debug(f"Scanning: {url}")

                async with session.get(
                    url, allow_redirects=self.follow_redirects, ssl=False
                ) as response:
                    # Read body with size limit
                    body = await response.text(encoding="utf-8", errors="ignore")
                    if len(body) > 100000:  # 100KB limit
                        body = body[:100000]

                    content_type = response.headers.get("Content-Type", "")

                    result = validate_response(
                        url=url,
                        path_def=path_def,
                        status_code=response.status,
                        body=body,
                        content_type=content_type,
                        error=None,
                    )

                    if result.vulnerable:
                        logger.info(
                            f"[FOUND] {result.severity.value}: {url} - {result.evidence}"
                        )

                    return result

            except asyncio.TimeoutError:
                logger.debug(f"Timeout: {url}")
                return validate_response(
                    url=url,
                    path_def=path_def,
                    status_code=0,
                    body="",
                    content_type="",
                    error="Request timeout",
                )

            except aiohttp.ClientError as e:
                logger.debug(f"Client error: {url} - {e}")
                return validate_response(
                    url=url,
                    path_def=path_def,
                    status_code=0,
                    body="",
                    content_type="",
                    error=str(e),
                )

            except Exception as e:
                logger.warning(f"Unexpected error: {url} - {e}")
                return validate_response(
                    url=url,
                    path_def=path_def,
                    status_code=0,
                    body="",
                    content_type="",
                    error=f"Unexpected: {e}",
                )

    async def scan_target(
        self,
        session: aiohttp.ClientSession,
        target: str,
        semaphore: asyncio.Semaphore,
    ) -> TargetReport:
        """
        Scan all paths on a single target.

        Args:
            session: aiohttp session
            target: Target URL to scan
            semaphore: Concurrency control semaphore

        Returns:
            TargetReport with all findings
        """
        start_time = datetime.now()
        logger.info(f"Scanning target: {target}")

        # Create tasks for all paths
        tasks = [
            self._scan_single_path(session, target, path_def, semaphore)
            for path_def in self.paths
        ]

        # Execute all scans concurrently
        results: List[ScanResult] = await asyncio.gather(*tasks)

        # Collect findings and errors
        findings = [r for r in results if r.vulnerable]
        errors = [r.error for r in results if r.error]

        # Sort findings by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        findings.sort(key=lambda x: severity_order[x.severity])

        duration = int((datetime.now() - start_time).total_seconds() * 1000)

        logger.info(
            f"Target complete: {target} - "
            f"{len(findings)} findings, {len(errors)} errors, {duration}ms"
        )

        return TargetReport(
            target=target,
            total_paths_checked=len(self.paths),
            vulnerable_count=len(findings),
            findings=findings,
            errors=errors[:10],  # Limit errors to avoid huge reports
            scan_duration_ms=duration,
        )

    async def scan(self, targets: List[str]) -> ScanReport:
        """
        Scan multiple targets.

        Args:
            targets: List of target URLs

        Returns:
            Complete ScanReport
        """
        start_time = datetime.now()
        logger.info(f"Starting scan of {len(targets)} targets")

        # Normalize targets
        normalized = []
        for target in targets:
            if not target.startswith(("http://", "https://")):
                target = f"https://{target}"
            normalized.append(target.rstrip("/"))

        # Deduplicate
        targets = list(dict.fromkeys(normalized))

        session = await self._create_session()
        semaphore = asyncio.Semaphore(self.concurrency)

        try:
            # Scan all targets
            tasks = [
                self.scan_target(session, target, semaphore) for target in targets
            ]
            target_reports: List[TargetReport] = await asyncio.gather(*tasks)

        finally:
            await session.close()

        # Aggregate results
        end_time = datetime.now()
        duration = int((end_time - start_time).total_seconds() * 1000)

        total_findings = sum(r.vulnerable_count for r in target_reports)
        targets_vulnerable = sum(1 for r in target_reports if r.vulnerable_count > 0)

        # Count by severity
        all_findings = [f for r in target_reports for f in r.findings]
        critical = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in all_findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in all_findings if f.severity == Severity.LOW)

        report = ScanReport(
            targets_scanned=len(targets),
            targets_vulnerable=targets_vulnerable,
            total_findings=total_findings,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            scan_start=start_time.isoformat(),
            scan_end=end_time.isoformat(),
            scan_duration_ms=duration,
            target_reports=target_reports,
        )

        logger.info(
            f"Scan complete: {len(targets)} targets, "
            f"{total_findings} findings ({critical} critical, {high} high), "
            f"{duration}ms"
        )

        return report

    def scan_sync(self, targets: List[str]) -> ScanReport:
        """
        Synchronous wrapper for scan().

        Args:
            targets: List of target URLs

        Returns:
            Complete ScanReport
        """
        return asyncio.run(self.scan(targets))

