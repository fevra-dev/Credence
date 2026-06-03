#!/usr/bin/env python3
"""
Invisible Unicode Detector

Detects invisible Unicode characters used in supply chain attacks like GlassWorm.

Attack Vectors Detected:
- Unicode variation selectors (VS1-VS256)
- Zero-width characters (ZWSP, ZWNJ, ZWJ)
- Private Use Area (PUA) characters
- Right-to-Left Override (RLO) attacks
- Homoglyph attacks
- Tag characters (U+E0000-U+E007F)
- Bidirectional text exploits

These techniques are used to:
- Hide malicious code in plain sight
- Bypass code review
- Evade static analysis tools
- Create "truly invisible" malware

Based on research: GlassWorm VS Code extension worm (2025)

Author: Credence Security Research
"""

import asyncio
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urljoin

import aiohttp


class ThreatLevel(Enum):
    """Threat level for invisible unicode findings"""
    CRITICAL = "critical"   # Active code hiding/execution
    HIGH = "high"           # Likely malicious intent
    MEDIUM = "medium"       # Suspicious patterns
    LOW = "low"             # Unusual but possibly benign
    INFO = "info"           # Presence only


class UnicodeCategory(Enum):
    """Categories of invisible/dangerous Unicode"""
    ZERO_WIDTH = "zero_width"
    VARIATION_SELECTOR = "variation_selector"
    PRIVATE_USE_AREA = "private_use_area"
    TAG_CHARACTER = "tag_character"
    BIDIRECTIONAL = "bidirectional"
    HOMOGLYPH = "homoglyph"
    CONTROL_CHARACTER = "control_character"
    WHITESPACE_ABUSE = "whitespace_abuse"


@dataclass
class UnicodeAnomaly:
    """Represents a detected Unicode anomaly"""
    category: UnicodeCategory
    threat_level: ThreatLevel
    codepoint: str
    character_name: str
    position: int
    line_number: int
    context: str
    description: str


@dataclass
class FileAnalysis:
    """Analysis result for a single file"""
    url: str
    path: str
    anomalies: List[UnicodeAnomaly]
    total_invisible_chars: int
    suspicious_patterns: List[str]
    threat_level: ThreatLevel
    is_likely_malicious: bool


@dataclass
class UnicodeDetectorResult:
    """Complete detection result"""
    target: str
    analyzed_files: List[FileAnalysis]
    total_anomalies: int
    critical_findings: int
    recommendations: List[str]
    scan_duration: float = 0.0


class InvisibleUnicodeAnalyzer:
    """
    Deep analyzer for invisible Unicode characters.
    
    This analyzer is designed to catch sophisticated attacks
    that use Unicode to hide malicious code within seemingly
    innocent files.
    """

    # Zero-width characters
    ZERO_WIDTH_CHARS = {
        '\u200B': ('ZERO WIDTH SPACE', ThreatLevel.MEDIUM),
        '\u200C': ('ZERO WIDTH NON-JOINER', ThreatLevel.MEDIUM),
        '\u200D': ('ZERO WIDTH JOINER', ThreatLevel.MEDIUM),
        '\u200E': ('LEFT-TO-RIGHT MARK', ThreatLevel.LOW),
        '\u200F': ('RIGHT-TO-LEFT MARK', ThreatLevel.MEDIUM),
        '\u2060': ('WORD JOINER', ThreatLevel.LOW),
        '\u2061': ('FUNCTION APPLICATION', ThreatLevel.HIGH),
        '\u2062': ('INVISIBLE TIMES', ThreatLevel.HIGH),
        '\u2063': ('INVISIBLE SEPARATOR', ThreatLevel.HIGH),
        '\u2064': ('INVISIBLE PLUS', ThreatLevel.HIGH),
        '\uFEFF': ('BYTE ORDER MARK', ThreatLevel.LOW),
    }

    # Bidirectional control characters (used in Trojan Source attacks)
    BIDI_CHARS = {
        '\u202A': ('LEFT-TO-RIGHT EMBEDDING', ThreatLevel.HIGH),
        '\u202B': ('RIGHT-TO-LEFT EMBEDDING', ThreatLevel.HIGH),
        '\u202C': ('POP DIRECTIONAL FORMATTING', ThreatLevel.MEDIUM),
        '\u202D': ('LEFT-TO-RIGHT OVERRIDE', ThreatLevel.CRITICAL),
        '\u202E': ('RIGHT-TO-LEFT OVERRIDE', ThreatLevel.CRITICAL),
        '\u2066': ('LEFT-TO-RIGHT ISOLATE', ThreatLevel.HIGH),
        '\u2067': ('RIGHT-TO-LEFT ISOLATE', ThreatLevel.HIGH),
        '\u2068': ('FIRST STRONG ISOLATE', ThreatLevel.MEDIUM),
        '\u2069': ('POP DIRECTIONAL ISOLATE', ThreatLevel.MEDIUM),
    }

    # Variation selectors (VS1-VS16 and VS17-VS256)
    # These can make code invisible in editors
    VARIATION_SELECTOR_RANGES = [
        (0xFE00, 0xFE0F, 'VARIATION SELECTOR'),      # VS1-VS16
        (0xE0100, 0xE01EF, 'VARIATION SELECTOR'),     # VS17-VS256
    ]

    # Private Use Area ranges
    PUA_RANGES = [
        (0xE000, 0xF8FF, 'PRIVATE USE AREA'),
        (0xF0000, 0xFFFFD, 'SUPPLEMENTARY PRIVATE USE AREA-A'),
        (0x100000, 0x10FFFD, 'SUPPLEMENTARY PRIVATE USE AREA-B'),
    ]

    # Tag characters (can encode hidden data)
    TAG_CHAR_RANGE = (0xE0000, 0xE007F)

    # Common homoglyphs (characters that look like ASCII but aren't)
    HOMOGLYPHS = {
        # Cyrillic
        '\u0410': ('CYRILLIC A', 'A'),
        '\u0412': ('CYRILLIC VE', 'B'),
        '\u0421': ('CYRILLIC ES', 'C'),
        '\u0415': ('CYRILLIC IE', 'E'),
        '\u041D': ('CYRILLIC EN', 'H'),
        '\u041A': ('CYRILLIC KA', 'K'),
        '\u041C': ('CYRILLIC EM', 'M'),
        '\u041E': ('CYRILLIC O', 'O'),
        '\u0420': ('CYRILLIC ER', 'P'),
        '\u0422': ('CYRILLIC TE', 'T'),
        '\u0425': ('CYRILLIC HA', 'X'),
        '\u0430': ('CYRILLIC SMALL A', 'a'),
        '\u0435': ('CYRILLIC SMALL IE', 'e'),
        '\u043E': ('CYRILLIC SMALL O', 'o'),
        '\u0440': ('CYRILLIC SMALL ER', 'p'),
        '\u0441': ('CYRILLIC SMALL ES', 'c'),
        '\u0445': ('CYRILLIC SMALL HA', 'x'),
        '\u0443': ('CYRILLIC SMALL U', 'y'),
        # Greek
        '\u0391': ('GREEK ALPHA', 'A'),
        '\u0392': ('GREEK BETA', 'B'),
        '\u0395': ('GREEK EPSILON', 'E'),
        '\u0397': ('GREEK ETA', 'H'),
        '\u0399': ('GREEK IOTA', 'I'),
        '\u039A': ('GREEK KAPPA', 'K'),
        '\u039C': ('GREEK MU', 'M'),
        '\u039D': ('GREEK NU', 'N'),
        '\u039F': ('GREEK OMICRON', 'O'),
        '\u03A1': ('GREEK RHO', 'P'),
        '\u03A4': ('GREEK TAU', 'T'),
        '\u03A7': ('GREEK CHI', 'X'),
        '\u03A5': ('GREEK UPSILON', 'Y'),
        '\u0396': ('GREEK ZETA', 'Z'),
    }

    # Suspicious control characters
    CONTROL_CHARS = {
        '\u0000': ('NULL', ThreatLevel.HIGH),
        '\u0001': ('START OF HEADING', ThreatLevel.MEDIUM),
        '\u0002': ('START OF TEXT', ThreatLevel.MEDIUM),
        '\u0003': ('END OF TEXT', ThreatLevel.MEDIUM),
        '\u0004': ('END OF TRANSMISSION', ThreatLevel.MEDIUM),
        '\u0007': ('BELL', ThreatLevel.LOW),
        '\u0008': ('BACKSPACE', ThreatLevel.MEDIUM),
        '\u000B': ('VERTICAL TAB', ThreatLevel.LOW),
        '\u000C': ('FORM FEED', ThreatLevel.LOW),
        '\u001B': ('ESCAPE', ThreatLevel.HIGH),
        '\u007F': ('DELETE', ThreatLevel.MEDIUM),
    }

    # Whitespace characters that could be abused
    SUSPICIOUS_WHITESPACE = {
        '\u00A0': ('NO-BREAK SPACE', ThreatLevel.LOW),
        '\u1680': ('OGHAM SPACE MARK', ThreatLevel.MEDIUM),
        '\u2000': ('EN QUAD', ThreatLevel.LOW),
        '\u2001': ('EM QUAD', ThreatLevel.LOW),
        '\u2002': ('EN SPACE', ThreatLevel.LOW),
        '\u2003': ('EM SPACE', ThreatLevel.LOW),
        '\u2004': ('THREE-PER-EM SPACE', ThreatLevel.LOW),
        '\u2005': ('FOUR-PER-EM SPACE', ThreatLevel.LOW),
        '\u2006': ('SIX-PER-EM SPACE', ThreatLevel.LOW),
        '\u2007': ('FIGURE SPACE', ThreatLevel.LOW),
        '\u2008': ('PUNCTUATION SPACE', ThreatLevel.LOW),
        '\u2009': ('THIN SPACE', ThreatLevel.LOW),
        '\u200A': ('HAIR SPACE', ThreatLevel.LOW),
        '\u2028': ('LINE SEPARATOR', ThreatLevel.MEDIUM),
        '\u2029': ('PARAGRAPH SEPARATOR', ThreatLevel.MEDIUM),
        '\u202F': ('NARROW NO-BREAK SPACE', ThreatLevel.LOW),
        '\u205F': ('MEDIUM MATHEMATICAL SPACE', ThreatLevel.LOW),
        '\u3000': ('IDEOGRAPHIC SPACE', ThreatLevel.LOW),
    }

    def __init__(self, strict_mode: bool = True):
        """
        Initialize analyzer.
        
        Args:
            strict_mode: If True, flag more suspicious patterns
        """
        self.strict_mode = strict_mode

    def analyze(self, content: str, filename: str = "") -> List[UnicodeAnomaly]:
        """
        Analyze content for invisible Unicode characters.
        
        Args:
            content: Text content to analyze
            filename: Optional filename for context
            
        Returns:
            List of detected anomalies
        """
        anomalies = []
        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            for pos, char in enumerate(line):
                codepoint = ord(char)

                # Check zero-width characters
                if char in self.ZERO_WIDTH_CHARS:
                    name, threat = self.ZERO_WIDTH_CHARS[char]
                    anomalies.append(UnicodeAnomaly(
                        category=UnicodeCategory.ZERO_WIDTH,
                        threat_level=threat,
                        codepoint=f"U+{codepoint:04X}",
                        character_name=name,
                        position=pos,
                        line_number=line_num,
                        context=self._get_context(line, pos),
                        description=f"Zero-width character detected: {name}"
                    ))

                # Check bidirectional control characters
                elif char in self.BIDI_CHARS:
                    name, threat = self.BIDI_CHARS[char]
                    anomalies.append(UnicodeAnomaly(
                        category=UnicodeCategory.BIDIRECTIONAL,
                        threat_level=threat,
                        codepoint=f"U+{codepoint:04X}",
                        character_name=name,
                        position=pos,
                        line_number=line_num,
                        context=self._get_context(line, pos),
                        description=f"Bidirectional control character (Trojan Source): {name}"
                    ))

                # Check variation selectors
                elif self._is_in_ranges(codepoint, self.VARIATION_SELECTOR_RANGES):
                    anomalies.append(UnicodeAnomaly(
                        category=UnicodeCategory.VARIATION_SELECTOR,
                        threat_level=ThreatLevel.HIGH,
                        codepoint=f"U+{codepoint:04X}",
                        character_name=f"VARIATION SELECTOR-{codepoint - 0xFE00 + 1}" if codepoint < 0xE0100 else f"VS{codepoint - 0xE0100 + 17}",
                        position=pos,
                        line_number=line_num,
                        context=self._get_context(line, pos),
                        description="Variation selector can hide code (GlassWorm technique)"
                    ))

                # Check Private Use Area
                elif self._is_in_pua(codepoint):
                    anomalies.append(UnicodeAnomaly(
                        category=UnicodeCategory.PRIVATE_USE_AREA,
                        threat_level=ThreatLevel.MEDIUM,
                        codepoint=f"U+{codepoint:04X}",
                        character_name="PRIVATE USE AREA CHARACTER",
                        position=pos,
                        line_number=line_num,
                        context=self._get_context(line, pos),
                        description="Private Use Area character detected"
                    ))

                # Check tag characters
                elif self.TAG_CHAR_RANGE[0] <= codepoint <= self.TAG_CHAR_RANGE[1]:
                    anomalies.append(UnicodeAnomaly(
                        category=UnicodeCategory.TAG_CHARACTER,
                        threat_level=ThreatLevel.HIGH,
                        codepoint=f"U+{codepoint:04X}",
                        character_name="TAG CHARACTER",
                        position=pos,
                        line_number=line_num,
                        context=self._get_context(line, pos),
                        description="Tag character can encode hidden data"
                    ))

                # Check homoglyphs
                elif char in self.HOMOGLYPHS:
                    name, looks_like = self.HOMOGLYPHS[char]
                    anomalies.append(UnicodeAnomaly(
                        category=UnicodeCategory.HOMOGLYPH,
                        threat_level=ThreatLevel.MEDIUM,
                        codepoint=f"U+{codepoint:04X}",
                        character_name=name,
                        position=pos,
                        line_number=line_num,
                        context=self._get_context(line, pos),
                        description=f"Homoglyph: looks like '{looks_like}' but is {name}"
                    ))

                # Check control characters
                elif char in self.CONTROL_CHARS:
                    name, threat = self.CONTROL_CHARS[char]
                    anomalies.append(UnicodeAnomaly(
                        category=UnicodeCategory.CONTROL_CHARACTER,
                        threat_level=threat,
                        codepoint=f"U+{codepoint:04X}",
                        character_name=name,
                        position=pos,
                        line_number=line_num,
                        context=self._get_context(line, pos),
                        description=f"Control character: {name}"
                    ))

                # Check suspicious whitespace
                elif self.strict_mode and char in self.SUSPICIOUS_WHITESPACE:
                    name, threat = self.SUSPICIOUS_WHITESPACE[char]
                    anomalies.append(UnicodeAnomaly(
                        category=UnicodeCategory.WHITESPACE_ABUSE,
                        threat_level=threat,
                        codepoint=f"U+{codepoint:04X}",
                        character_name=name,
                        position=pos,
                        line_number=line_num,
                        context=self._get_context(line, pos),
                        description=f"Unusual whitespace: {name}"
                    ))

        return anomalies

    def _is_in_ranges(self, codepoint: int, ranges: List[Tuple]) -> bool:
        """Check if codepoint is in any of the given ranges"""
        for start, end, _ in ranges:
            if start <= codepoint <= end:
                return True
        return False

    def _is_in_pua(self, codepoint: int) -> bool:
        """Check if codepoint is in Private Use Area"""
        for start, end, _ in self.PUA_RANGES:
            if start <= codepoint <= end:
                return True
        return False

    def _get_context(self, line: str, pos: int, window: int = 20) -> str:
        """Get context around the detected character"""
        start = max(0, pos - window)
        end = min(len(line), pos + window)
        context = line[start:end]
        # Replace invisible chars with placeholders for display
        return ''.join(c if c.isprintable() or c.isspace() else f'[U+{ord(c):04X}]' for c in context)

    def decode_hidden_message(self, content: str) -> Optional[str]:
        """
        Attempt to decode hidden messages from tag characters.
        
        Tag characters (U+E0000-U+E007F) can encode ASCII text
        by mapping to ASCII range.
        """
        tag_chars = []
        for char in content:
            cp = ord(char)
            if self.TAG_CHAR_RANGE[0] <= cp <= self.TAG_CHAR_RANGE[1]:
                # Map back to ASCII
                ascii_cp = cp - self.TAG_CHAR_RANGE[0]
                if 0x20 <= ascii_cp <= 0x7E:
                    tag_chars.append(chr(ascii_cp))

        if tag_chars:
            return ''.join(tag_chars)
        return None


class InvisibleUnicodeScanner:
    """
    Scanner for detecting invisible Unicode in web-accessible files.
    
    Scans JavaScript, TypeScript, Python, and other code files
    for invisible Unicode characters that could hide malicious code.
    """

    # File extensions to scan
    SCANNABLE_EXTENSIONS = {
        '.js', '.mjs', '.cjs', '.jsx',
        '.ts', '.tsx', '.mts', '.cts',
        '.py', '.pyw',
        '.rb',
        '.php',
        '.java',
        '.c', '.h', '.cpp', '.hpp',
        '.go',
        '.rs',
        '.sh', '.bash',
        '.json',
        '.yaml', '.yml',
        '.xml',
        '.html', '.htm',
        '.css', '.scss', '.less',
    }

    # Common source code paths
    SOURCE_PATHS = [
        "/src/",
        "/lib/",
        "/dist/",
        "/build/",
        "/public/",
        "/static/",
        "/assets/",
        "/js/",
        "/scripts/",
        "/.vscode/extensions/",
        "/node_modules/",
    ]

    # Specific files to check
    SPECIFIC_FILES = [
        "/package.json",
        "/index.js",
        "/main.js",
        "/app.js",
        "/bundle.js",
        "/vendor.js",
        "/extension.js",
    ]

    def __init__(
        self,
        timeout: int = 15,
        max_concurrent: int = 20,
        max_file_size: int = 5 * 1024 * 1024,  # 5MB
        strict_mode: bool = True
    ):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_concurrent = max_concurrent
        self.max_file_size = max_file_size
        self.semaphore = asyncio.Semaphore(max_concurrent)

        self.analyzer = InvisibleUnicodeAnalyzer(strict_mode=strict_mode)

    async def scan(
        self,
        target: str,
        session: Optional[aiohttp.ClientSession] = None
    ) -> UnicodeDetectorResult:
        """
        Scan target for invisible Unicode characters.
        """
        import time
        start_time = time.time()

        own_session = session is None
        if own_session:
            connector = aiohttp.TCPConnector(ssl=False, limit=self.max_concurrent)
            session = aiohttp.ClientSession(connector=connector, timeout=self.timeout)

        try:
            target = self._normalize_url(target)

            # Collect files to scan
            files_to_scan = await self._discover_files(target, session)

            # Scan each file
            analyses = []
            tasks = []
            for file_path in files_to_scan:
                tasks.append(self._analyze_file(target, file_path, session))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, FileAnalysis):
                    analyses.append(result)

            # Generate result
            total_anomalies = sum(len(a.anomalies) for a in analyses)
            critical_findings = sum(
                1 for a in analyses
                for an in a.anomalies
                if an.threat_level == ThreatLevel.CRITICAL
            )

            recommendations = self._generate_recommendations(analyses)

            return UnicodeDetectorResult(
                target=target,
                analyzed_files=analyses,
                total_anomalies=total_anomalies,
                critical_findings=critical_findings,
                recommendations=recommendations,
                scan_duration=time.time() - start_time
            )

        finally:
            if own_session:
                await session.close()

    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        return url.rstrip('/')

    async def _discover_files(
        self,
        target: str,
        session: aiohttp.ClientSession
    ) -> List[str]:
        """Discover files to scan"""
        files = list(self.SPECIFIC_FILES)

        # Try to find more files from common paths
        for base_path in self.SOURCE_PATHS:
            try:
                url = urljoin(target, base_path)
                async with self.semaphore:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            content = await resp.text()

                            # Check if directory listing
                            if 'Index of' in content or '<title>Directory' in content:
                                # Extract file links
                                file_pattern = r'href="([^"]+\.\w+)"'
                                matches = re.findall(file_pattern, content)
                                for match in matches:
                                    ext = Path(match).suffix.lower()
                                    if ext in self.SCANNABLE_EXTENSIONS:
                                        files.append(f"{base_path.rstrip('/')}/{match}")
            except Exception:
                continue

        return list(set(files))

    async def _analyze_file(
        self,
        target: str,
        file_path: str,
        session: aiohttp.ClientSession
    ) -> Optional[FileAnalysis]:
        """Analyze a single file"""
        url = urljoin(target, file_path)

        try:
            async with self.semaphore:
                # Check file size first
                async with session.head(url) as resp:
                    if resp.status != 200:
                        return None

                    content_length = int(resp.headers.get('content-length', 0))
                    if content_length > self.max_file_size:
                        return None

                # Download and analyze
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return None

                    content = await resp.text(errors='replace')

                    # Run analysis
                    anomalies = self.analyzer.analyze(content, file_path)

                    # Only return if anomalies found
                    if not anomalies:
                        return None

                    # Calculate threat level
                    threat_level = self._calculate_threat_level(anomalies)

                    # Check for patterns
                    patterns = self._detect_patterns(anomalies)

                    # Determine if likely malicious
                    is_malicious = (
                        threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH] or
                        len([a for a in anomalies if a.category == UnicodeCategory.VARIATION_SELECTOR]) > 10 or
                        any(a.category == UnicodeCategory.BIDIRECTIONAL and a.threat_level == ThreatLevel.CRITICAL for a in anomalies)
                    )

                    # Try to decode hidden messages
                    hidden_msg = self.analyzer.decode_hidden_message(content)
                    if hidden_msg:
                        patterns.append(f"Hidden message decoded: {hidden_msg[:50]}...")

                    return FileAnalysis(
                        url=url,
                        path=file_path,
                        anomalies=anomalies,
                        total_invisible_chars=len(anomalies),
                        suspicious_patterns=patterns,
                        threat_level=threat_level,
                        is_likely_malicious=is_malicious
                    )
        except Exception:
            pass

        return None

    def _calculate_threat_level(self, anomalies: List[UnicodeAnomaly]) -> ThreatLevel:
        """Calculate overall threat level from anomalies"""
        if not anomalies:
            return ThreatLevel.INFO

        # Get highest threat level
        threat_priority = {
            ThreatLevel.CRITICAL: 5,
            ThreatLevel.HIGH: 4,
            ThreatLevel.MEDIUM: 3,
            ThreatLevel.LOW: 2,
            ThreatLevel.INFO: 1,
        }

        max_threat = max(anomalies, key=lambda a: threat_priority.get(a.threat_level, 0))

        # Escalate if many anomalies
        if len(anomalies) > 50:
            if max_threat.threat_level == ThreatLevel.MEDIUM:
                return ThreatLevel.HIGH
            if max_threat.threat_level == ThreatLevel.LOW:
                return ThreatLevel.MEDIUM

        return max_threat.threat_level

    def _detect_patterns(self, anomalies: List[UnicodeAnomaly]) -> List[str]:
        """Detect suspicious patterns in anomalies"""
        patterns = []

        # Check for clustered variation selectors (GlassWorm pattern)
        vs_positions = [a.position for a in anomalies if a.category == UnicodeCategory.VARIATION_SELECTOR]
        if len(vs_positions) > 5:
            patterns.append(f"Clustered variation selectors detected ({len(vs_positions)} instances)")

        # Check for bidirectional override (Trojan Source)
        bidi = [a for a in anomalies if a.category == UnicodeCategory.BIDIRECTIONAL]
        if bidi:
            patterns.append(f"Bidirectional text attack indicators ({len(bidi)} instances)")

        # Check for homoglyph clusters
        homoglyphs = [a for a in anomalies if a.category == UnicodeCategory.HOMOGLYPH]
        if len(homoglyphs) > 3:
            patterns.append(f"Multiple homoglyphs detected ({len(homoglyphs)} instances)")

        # Check for tag characters (hidden data)
        tags = [a for a in anomalies if a.category == UnicodeCategory.TAG_CHARACTER]
        if tags:
            patterns.append(f"Tag characters with potential encoded data ({len(tags)} chars)")

        return patterns

    def _generate_recommendations(self, analyses: List[FileAnalysis]) -> List[str]:
        """Generate recommendations based on findings"""
        recommendations = []

        has_critical = any(a.threat_level == ThreatLevel.CRITICAL for a in analyses)
        has_malicious = any(a.is_likely_malicious for a in analyses)
        has_vs = any(
            any(an.category == UnicodeCategory.VARIATION_SELECTOR for an in a.anomalies)
            for a in analyses
        )
        has_bidi = any(
            any(an.category == UnicodeCategory.BIDIRECTIONAL for an in a.anomalies)
            for a in analyses
        )

        if has_critical or has_malicious:
            recommendations.extend([
                "CRITICAL: Immediately quarantine affected files for forensic analysis",
                "Review source code for hidden malicious payloads",
                "Check for unauthorized modifications to codebase",
            ])

        if has_vs:
            recommendations.extend([
                "Enable Unicode visualization in code editors",
                "Implement pre-commit hooks to detect variation selectors",
                "Review VS Code extensions for GlassWorm-style infections",
            ])

        if has_bidi:
            recommendations.extend([
                "Check for Trojan Source attack patterns",
                "Configure IDE to highlight bidirectional control characters",
                "Review code review processes for invisible character detection",
            ])

        recommendations.extend([
            "Implement CI/CD checks for invisible Unicode characters",
            "Use static analysis tools that detect Unicode anomalies",
            "Configure web servers to validate source file integrity",
        ])

        return list(set(recommendations))

    def generate_report(self, result: UnicodeDetectorResult) -> str:
        """Generate human-readable report"""
        lines = [
            "=" * 70,
            "INVISIBLE UNICODE DETECTION SCAN",
            f"Target: {result.target}",
            f"Duration: {result.scan_duration:.2f}s",
            "=" * 70,
            "",
            f"Files Analyzed: {len(result.analyzed_files)}",
            f"Total Anomalies: {result.total_anomalies}",
            f"Critical Findings: {result.critical_findings}",
            "",
        ]

        # Show files with findings
        malicious_files = [a for a in result.analyzed_files if a.is_likely_malicious]
        suspicious_files = [a for a in result.analyzed_files if not a.is_likely_malicious and a.threat_level in [ThreatLevel.HIGH, ThreatLevel.MEDIUM]]

        if malicious_files:
            lines.append("🔴 LIKELY MALICIOUS FILES:")
            for analysis in malicious_files:
                lines.append(f"  • {analysis.path}")
                lines.append(f"    URL: {analysis.url}")
                lines.append(f"    Anomalies: {len(analysis.anomalies)}")
                if analysis.suspicious_patterns:
                    for pattern in analysis.suspicious_patterns:
                        lines.append(f"    ⚠ {pattern}")

                # Show sample anomalies
                lines.append("    Sample findings:")
                for anomaly in analysis.anomalies[:3]:
                    lines.append(f"      - [{anomaly.threat_level.value}] {anomaly.description}")
                    lines.append(f"        Line {anomaly.line_number}: {anomaly.context[:50]}...")
            lines.append("")

        if suspicious_files:
            lines.append("🟠 SUSPICIOUS FILES:")
            for analysis in suspicious_files[:5]:
                lines.append(f"  • {analysis.path} ({len(analysis.anomalies)} anomalies)")
            lines.append("")

        if result.recommendations:
            lines.append("RECOMMENDATIONS:")
            for rec in result.recommendations[:10]:
                lines.append(f"  → {rec}")
            lines.append("")

        lines.append("=" * 70)
        return "\n".join(lines)


async def main():
    """CLI entry point"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python invisible_unicode_detector.py <target_url>")
        print("       python invisible_unicode_detector.py --analyze <file>")
        sys.exit(1)

    if sys.argv[1] == "--analyze" and len(sys.argv) > 2:
        # Analyze local file
        filepath = sys.argv[2]
        with open(filepath, 'r', errors='replace') as f:
            content = f.read()

        analyzer = InvisibleUnicodeAnalyzer()
        anomalies = analyzer.analyze(content, filepath)

        if anomalies:
            print(f"Found {len(anomalies)} anomalies in {filepath}:")
            for anomaly in anomalies:
                print(f"  [{anomaly.threat_level.value}] Line {anomaly.line_number}: {anomaly.description}")
                print(f"    {anomaly.codepoint} - {anomaly.character_name}")
        else:
            print("No invisible Unicode anomalies found.")
    else:
        # Scan URL
        target = sys.argv[1]
        scanner = InvisibleUnicodeScanner()

        print(f"[*] Scanning {target} for invisible Unicode characters...")
        result = await scanner.scan(target)
        print(scanner.generate_report(result))


if __name__ == "__main__":
    asyncio.run(main())
