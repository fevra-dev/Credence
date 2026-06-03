"""
Advanced Stealth & Evasion Module.

Implements sophisticated techniques to evade detection:
- WAF/IDS detection and bypass
- Adaptive rate limiting
- Request fingerprint randomization
- Proxy rotation support
- TLS fingerprint spoofing
- Header randomization

This module enables scanning in hostile environments where security
controls may block or rate-limit scanning activity.
"""

import asyncio
import logging
import random
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Tuple

import aiohttp

logger = logging.getLogger(__name__)


class WAFType(Enum):
    """Detected WAF types."""
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    AWS_WAF = "aws_waf"
    IMPERVA = "imperva"
    SUCURI = "sucuri"
    F5_BIG_IP = "f5_big_ip"
    MOD_SECURITY = "mod_security"
    BARRACUDA = "barracuda"
    FORTINET = "fortinet"
    NGINX_ULTIMATE = "nginx_ultimate"
    UNKNOWN = "unknown"
    NONE = "none"


class StealthLevel(Enum):
    """Stealth operation levels."""
    NORMAL = 1  # No stealth, maximum speed
    LOW = 2     # Basic UA rotation
    MEDIUM = 3  # UA rotation + random delays
    HIGH = 4    # Full header randomization + delays
    PARANOID = 5  # Maximum stealth, slow but undetectable


@dataclass
class WAFDetectionResult:
    """Result of WAF detection."""
    waf_detected: bool
    waf_type: WAFType
    confidence: float
    evidence: List[str] = field(default_factory=list)
    bypass_techniques: List[str] = field(default_factory=list)


@dataclass
class ProxyConfig:
    """Proxy configuration."""
    url: str
    protocol: str  # http, https, socks5
    username: Optional[str] = None
    password: Optional[str] = None
    country: Optional[str] = None
    last_used: Optional[datetime] = None
    failure_count: int = 0


class WAFDetector:
    """
    Detect and identify WAF/IDS systems.
    
    Analyzes response headers, cookies, and body content to identify
    the presence of Web Application Firewalls.
    """

    # WAF detection signatures
    WAF_SIGNATURES = {
        WAFType.CLOUDFLARE: {
            'headers': ['cf-ray', '__cfduid', 'cf-cache-status', 'cf-request-id'],
            'cookies': ['__cfduid', '__cf_bm', 'cf_clearance'],
            'body': ['cloudflare', 'cf-browser-verification', 'ray id:', 'checking your browser'],
            'status_codes': [403, 503],
        },

        WAFType.AKAMAI: {
            'headers': ['x-akamai-', 'akamai-ghost', 'akamai-origin'],
            'cookies': ['_abck', 'bm_sz', 'ak_bmsc'],
            'body': ['akamai', 'access denied', 'reference #'],
            'status_codes': [403],
        },

        WAFType.AWS_WAF: {
            'headers': ['x-amzn-requestid', 'x-amz-cf-id', 'x-amz-apigw-id'],
            'cookies': ['awsalbcors', 'awsalb'],
            'body': ['aws', 'amazon', 'request blocked'],
            'status_codes': [403],
        },

        WAFType.IMPERVA: {
            'headers': ['x-iinfo', 'x-cdn'],
            'cookies': ['incap_ses_', 'visid_incap_', 'nlbi_'],
            'body': ['imperva', 'incapsula', 'incident id', '_incapsula_resource'],
            'status_codes': [403],
        },

        WAFType.SUCURI: {
            'headers': ['x-sucuri-id', 'x-sucuri-cache'],
            'cookies': ['sucuri_cloudproxy'],
            'body': ['sucuri', 'access denied', 'sucuri website firewall'],
            'status_codes': [403],
        },

        WAFType.F5_BIG_IP: {
            'headers': ['x-wa-info', 'x-cnection'],
            'cookies': ['bigipserver', 'f5_hz', 'ts', 'f5avraaaaaaa'],
            'body': ['bigip', 'f5', 'the requested url was rejected'],
            'status_codes': [403],
        },

        WAFType.MOD_SECURITY: {
            'headers': ['mod_security', 'modsecurity'],
            'cookies': [],
            'body': ['mod_security', 'modsecurity', 'naxsi', 'blocked by', 'forbidden'],
            'status_codes': [403, 406],
        },

        WAFType.BARRACUDA: {
            'headers': ['barra_counter'],
            'cookies': ['barra_counter_session'],
            'body': ['barracuda', 'blocked', 'barra'],
            'status_codes': [403],
        },

        WAFType.FORTINET: {
            'headers': [],
            'cookies': ['fgd_webportal', 'fwb'],
            'body': ['fortiweb', 'fortigate', '.fgd'],
            'status_codes': [403],
        },
    }

    async def detect(
        self,
        url: str,
        session: aiohttp.ClientSession
    ) -> WAFDetectionResult:
        """
        Detect WAF on target.
        
        Args:
            url: Target URL
            session: aiohttp session
            
        Returns:
            WAFDetectionResult with detection details
        """
        evidence = []
        detected_waf = WAFType.NONE
        max_confidence = 0.0

        try:
            # Normal request
            async with session.get(url, ssl=False) as resp:
                headers = dict(resp.headers)
                cookies = {c.key: c.value for c in resp.cookies.values()}
                body = await resp.text()
                status = resp.status

                # Check each WAF signature
                for waf_type, sigs in self.WAF_SIGNATURES.items():
                    confidence = self._check_signatures(
                        headers, cookies, body, status, sigs
                    )

                    if confidence > max_confidence:
                        max_confidence = confidence
                        detected_waf = waf_type

                        # Collect evidence
                        evidence = self._collect_evidence(
                            headers, cookies, body, sigs
                        )

            # Try triggering WAF with malicious payload
            malicious_url = f"{url}?id=1' OR '1'='1"
            try:
                async with session.get(malicious_url, ssl=False) as resp:
                    if resp.status in (403, 406, 429, 503):
                        if detected_waf == WAFType.NONE:
                            detected_waf = WAFType.UNKNOWN
                            max_confidence = 0.5
                            evidence.append(f"Blocked malicious request (status {resp.status})")
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"WAF detection error: {e}")

        # Get bypass techniques
        bypass_techniques = self._get_bypass_techniques(detected_waf)

        return WAFDetectionResult(
            waf_detected=detected_waf != WAFType.NONE,
            waf_type=detected_waf,
            confidence=max_confidence,
            evidence=evidence,
            bypass_techniques=bypass_techniques
        )

    def _check_signatures(
        self,
        headers: Dict,
        cookies: Dict,
        body: str,
        status: int,
        signatures: Dict
    ) -> float:
        """Check response against WAF signatures."""
        matches = 0
        total = 0

        # Check headers
        headers_lower = {k.lower(): v for k, v in headers.items()}
        for header in signatures.get('headers', []):
            total += 1
            if header.lower() in headers_lower:
                matches += 1

        # Check cookies
        cookies_lower = {k.lower(): v for k, v in cookies.items()}
        for cookie in signatures.get('cookies', []):
            total += 1
            if any(cookie.lower() in c for c in cookies_lower):
                matches += 1

        # Check body patterns
        body_lower = body.lower()
        for pattern in signatures.get('body', []):
            total += 1
            if pattern.lower() in body_lower:
                matches += 1

        if total == 0:
            return 0.0

        return matches / total

    def _collect_evidence(
        self,
        headers: Dict,
        cookies: Dict,
        body: str,
        signatures: Dict
    ) -> List[str]:
        """Collect evidence of WAF detection."""
        evidence = []

        headers_lower = {k.lower(): v for k, v in headers.items()}
        for header in signatures.get('headers', []):
            if header.lower() in headers_lower:
                evidence.append(f"Header: {header}")

        cookies_lower = {k.lower(): v for k, v in cookies.items()}
        for cookie in signatures.get('cookies', []):
            if any(cookie.lower() in c for c in cookies_lower):
                evidence.append(f"Cookie: {cookie}")

        return evidence[:10]

    def _get_bypass_techniques(self, waf_type: WAFType) -> List[str]:
        """Get recommended bypass techniques for WAF."""

        techniques = {
            WAFType.CLOUDFLARE: [
                "Use origin IP if available",
                "Rate limit to avoid captcha",
                "Avoid known malicious patterns",
                "Use legitimate User-Agent strings",
            ],
            WAFType.AKAMAI: [
                "Slow down requests significantly",
                "Use browser-like headers",
                "Avoid automation indicators",
            ],
            WAFType.AWS_WAF: [
                "Use normal browser headers",
                "Avoid SQLi/XSS patterns in URLs",
                "Rate limit requests",
            ],
            WAFType.IMPERVA: [
                "Use rotating proxies",
                "Mimic real browser behavior",
                "Add realistic delays between requests",
            ],
            WAFType.MOD_SECURITY: [
                "Avoid common attack patterns in URLs",
                "Use URL encoding selectively",
                "Add legitimate Referer headers",
            ],
        }

        return techniques.get(waf_type, ["Use slow rate limiting", "Randomize headers"])


class AdaptiveRateLimiter:
    """
    Adaptive rate limiter that adjusts based on responses.
    
    Automatically backs off when detecting rate limiting or blocking,
    and speeds up when successful.
    """

    def __init__(
        self,
        base_rate: int = 50,
        min_rate: int = 5,
        max_rate: int = 100,
        backoff_factor: float = 0.5,
        recovery_factor: float = 1.1
    ):
        """
        Initialize adaptive rate limiter.
        
        Args:
            base_rate: Starting requests per second
            min_rate: Minimum requests per second
            max_rate: Maximum requests per second
            backoff_factor: Factor to reduce rate on errors
            recovery_factor: Factor to increase rate on success
        """
        self.base_rate = base_rate
        self.current_rate = base_rate
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.backoff_factor = backoff_factor
        self.recovery_factor = recovery_factor

        self.request_times: deque = deque()
        self.consecutive_success = 0
        self.consecutive_errors = 0
        self._lock = asyncio.Lock()

    async def acquire(self):
        """Acquire permission to make a request."""
        async with self._lock:
            now = datetime.now()

            # Remove old request times (older than 1 second)
            cutoff = now - timedelta(seconds=1)
            while self.request_times and self.request_times[0] < cutoff:
                self.request_times.popleft()

            # Wait if at rate limit
            if len(self.request_times) >= self.current_rate:
                wait_time = 1.0 - (now - self.request_times[0]).total_seconds()
                if wait_time > 0:
                    await asyncio.sleep(wait_time)

            self.request_times.append(datetime.now())

    def report_success(self):
        """Report a successful request."""
        self.consecutive_success += 1
        self.consecutive_errors = 0

        # Gradually increase rate after consistent success
        if self.consecutive_success > 10:
            self.current_rate = min(
                self.current_rate * self.recovery_factor,
                self.max_rate
            )
            self.consecutive_success = 0
            logger.debug(f"Rate increased to {self.current_rate:.1f}/s")

    def report_error(self, status_code: int):
        """Report an error response."""
        self.consecutive_errors += 1
        self.consecutive_success = 0

        # Significant backoff for rate limits
        if status_code in (429, 503, 504):
            self.current_rate = max(
                self.current_rate * self.backoff_factor,
                self.min_rate
            )
            logger.debug(f"Rate limit detected, reduced to {self.current_rate:.1f}/s")

        # Moderate backoff for server errors
        elif status_code >= 500:
            self.current_rate = max(
                self.current_rate * 0.75,
                self.min_rate
            )

    def report_block(self):
        """Report a WAF block."""
        self.current_rate = self.min_rate
        logger.warning(f"Block detected, reduced to minimum rate {self.min_rate}/s")

    @property
    def requests_per_second(self) -> float:
        """Get current requests per second."""
        return self.current_rate


class StealthScanner:
    """
    Stealth-enabled HTTP scanner with evasion capabilities.
    
    Features:
    - User-Agent rotation
    - Header randomization
    - Request timing jitter
    - Proxy rotation
    - TLS fingerprint variation
    - Referer chain building
    """

    # Realistic User-Agent strings (updated for 2025)
    USER_AGENTS = [
        # Chrome on Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',

        # Chrome on Mac
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',

        # Firefox on Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',

        # Firefox on Mac
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',

        # Safari on Mac
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',

        # Edge on Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',

        # Mobile browsers
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    ]

    # Realistic Accept headers by content type
    ACCEPT_HEADERS = {
        'html': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'json': 'application/json, text/plain, */*',
        'any': '*/*',
    }

    # Common Accept-Language values
    ACCEPT_LANGUAGES = [
        'en-US,en;q=0.9',
        'en-GB,en;q=0.9',
        'en-US,en;q=0.9,es;q=0.8',
        'en-US,en;q=0.9,fr;q=0.8',
        'en,es;q=0.9',
    ]

    def __init__(
        self,
        stealth_level: StealthLevel = StealthLevel.MEDIUM,
        proxies: Optional[List[ProxyConfig]] = None,
        timeout: int = 15,
        detect_waf: bool = True
    ):
        """
        Initialize stealth scanner.
        
        Args:
            stealth_level: Level of stealth to apply
            proxies: Optional list of proxy configurations
            timeout: Request timeout in seconds
            detect_waf: Whether to detect WAF before scanning
        """
        self.stealth_level = stealth_level
        self.proxies = proxies or []
        self.timeout = timeout
        self.detect_waf = detect_waf

        self.rate_limiter = AdaptiveRateLimiter()
        self.waf_detector = WAFDetector()
        self.session: Optional[aiohttp.ClientSession] = None

        self._proxy_index = 0
        self._ua_index = 0
        self._detected_waf: Optional[WAFDetectionResult] = None
        self._referer_chain: List[str] = []

    async def __aenter__(self):
        """Async context manager entry."""
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=10,
            ssl=False,
            enable_cleanup_closed=True,
        )

        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            connector=connector,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()

    async def detect_protection(self, url: str) -> WAFDetectionResult:
        """
        Detect WAF/protection on target.
        
        Args:
            url: Target URL
            
        Returns:
            WAFDetectionResult
        """
        if self.session is None:
            raise RuntimeError("Scanner not initialized. Use 'async with' context manager.")

        self._detected_waf = await self.waf_detector.detect(url, self.session)

        # Adjust rate limiter based on WAF
        if self._detected_waf.waf_detected:
            logger.info(f"WAF detected: {self._detected_waf.waf_type.value}")

            # Reduce rate for known aggressive WAFs
            if self._detected_waf.waf_type in (WAFType.CLOUDFLARE, WAFType.AKAMAI):
                self.rate_limiter.current_rate = min(
                    self.rate_limiter.current_rate,
                    20  # Max 20 req/s for these WAFs
                )

        return self._detected_waf

    async def request(
        self,
        url: str,
        method: str = 'GET',
        **kwargs
    ) -> Tuple[Optional[aiohttp.ClientResponse], Optional[str]]:
        """
        Make a stealthy HTTP request.
        
        Args:
            url: Target URL
            method: HTTP method
            **kwargs: Additional request arguments
            
        Returns:
            Tuple of (response, body) or (None, None) on error
        """
        if self.session is None:
            raise RuntimeError("Scanner not initialized. Use 'async with' context manager.")

        # Rate limiting
        await self.rate_limiter.acquire()

        # Add stealth delay
        await self._add_delay()

        # Build stealth headers
        headers = self._build_headers(url)
        headers.update(kwargs.pop('headers', {}))

        # Get proxy if available
        proxy = self._get_next_proxy()

        try:
            async with self.session.request(
                method,
                url,
                headers=headers,
                proxy=proxy,
                ssl=False,
                **kwargs
            ) as resp:
                body = await resp.text()

                # Update rate limiter
                if resp.status in (429, 503):
                    self.rate_limiter.report_error(resp.status)
                elif resp.status >= 400:
                    self.rate_limiter.report_error(resp.status)
                else:
                    self.rate_limiter.report_success()

                # Update referer chain
                if resp.status == 200:
                    self._update_referer_chain(url)

                return resp, body

        except asyncio.TimeoutError:
            self.rate_limiter.report_error(504)
            return None, None
        except Exception as e:
            logger.debug(f"Request error: {e}")
            return None, None

    def _build_headers(self, url: str) -> Dict[str, str]:
        """Build stealth headers based on stealth level."""
        headers = {}

        if self.stealth_level.value >= StealthLevel.LOW.value:
            # Rotate User-Agent
            headers['User-Agent'] = self._get_next_ua()

        if self.stealth_level.value >= StealthLevel.MEDIUM.value:
            # Add realistic Accept headers
            headers['Accept'] = self.ACCEPT_HEADERS['html']
            headers['Accept-Language'] = random.choice(self.ACCEPT_LANGUAGES)
            headers['Accept-Encoding'] = 'gzip, deflate, br'

        if self.stealth_level.value >= StealthLevel.HIGH.value:
            # Full header randomization
            headers['DNT'] = random.choice(['1', '0'])
            headers['Upgrade-Insecure-Requests'] = '1'
            headers['Sec-Fetch-Dest'] = 'document'
            headers['Sec-Fetch-Mode'] = 'navigate'
            headers['Sec-Fetch-Site'] = 'none'
            headers['Sec-Fetch-User'] = '?1'
            headers['Cache-Control'] = random.choice(['no-cache', 'max-age=0'])

            # Add referer if available
            if self._referer_chain:
                headers['Referer'] = self._referer_chain[-1]

        if self.stealth_level.value >= StealthLevel.PARANOID.value:
            # Additional fingerprint randomization
            headers['Sec-CH-UA'] = self._generate_client_hints()
            headers['Sec-CH-UA-Mobile'] = '?0'
            headers['Sec-CH-UA-Platform'] = random.choice(['"Windows"', '"macOS"', '"Linux"'])

        return headers

    async def _add_delay(self):
        """Add stealth delay between requests."""
        if self.stealth_level == StealthLevel.NORMAL:
            return

        delays = {
            StealthLevel.LOW: (0.1, 0.5),
            StealthLevel.MEDIUM: (0.5, 1.5),
            StealthLevel.HIGH: (1.0, 3.0),
            StealthLevel.PARANOID: (2.0, 5.0),
        }

        min_delay, max_delay = delays.get(self.stealth_level, (0, 0))
        delay = random.uniform(min_delay, max_delay)
        await asyncio.sleep(delay)

    def _get_next_ua(self) -> str:
        """Get next User-Agent with rotation."""
        ua = self.USER_AGENTS[self._ua_index]
        self._ua_index = (self._ua_index + 1) % len(self.USER_AGENTS)
        return ua

    def _get_next_proxy(self) -> Optional[str]:
        """Get next proxy with rotation."""
        if not self.proxies:
            return None

        proxy = self.proxies[self._proxy_index]
        self._proxy_index = (self._proxy_index + 1) % len(self.proxies)

        # Build proxy URL
        if proxy.username and proxy.password:
            return f"{proxy.protocol}://{proxy.username}:{proxy.password}@{proxy.url}"
        return f"{proxy.protocol}://{proxy.url}"

    def _update_referer_chain(self, url: str):
        """Update referer chain for realistic browsing simulation."""
        self._referer_chain.append(url)

        # Keep only last 5 referers
        if len(self._referer_chain) > 5:
            self._referer_chain = self._referer_chain[-5:]

    def _generate_client_hints(self) -> str:
        """Generate Sec-CH-UA client hints."""
        versions = [
            ('"Chromium"', '120'),
            ('"Google Chrome"', '120'),
            ('"Not_A Brand"', '8'),
        ]

        hints = ', '.join(
            f'{name};v="{version}"'
            for name, version in versions
        )

        return hints


def generate_stealth_report(
    waf_result: WAFDetectionResult,
    rate_limiter: AdaptiveRateLimiter
) -> str:
    """Generate a report of stealth scan configuration."""

    lines = [
        "=" * 80,
        "STEALTH SCAN CONFIGURATION REPORT",
        "=" * 80,
        "",
    ]

    # WAF Detection
    lines.append("WAF DETECTION")
    lines.append("-" * 40)

    if waf_result.waf_detected:
        lines.append(f"  ⚠️  WAF Detected: {waf_result.waf_type.value.upper()}")
        lines.append(f"  Confidence: {waf_result.confidence:.0%}")

        if waf_result.evidence:
            lines.append("  Evidence:")
            for e in waf_result.evidence[:5]:
                lines.append(f"    - {e}")

        if waf_result.bypass_techniques:
            lines.append("  Recommended Bypass Techniques:")
            for t in waf_result.bypass_techniques:
                lines.append(f"    • {t}")
    else:
        lines.append("  ✅ No WAF detected")

    lines.append("")

    # Rate Limiting
    lines.append("RATE LIMITING")
    lines.append("-" * 40)
    lines.append(f"  Current Rate: {rate_limiter.requests_per_second:.1f} req/s")
    lines.append(f"  Min Rate: {rate_limiter.min_rate} req/s")
    lines.append(f"  Max Rate: {rate_limiter.max_rate} req/s")

    lines.append("\n" + "=" * 80)
    return "\n".join(lines)
