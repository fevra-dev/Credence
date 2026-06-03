#!/usr/bin/env python3
"""
ML Model Supply Chain Security Scanner

Detects exposed machine learning model files that could contain malicious payloads
through pickle deserialization, PyTorch hooks, or other code execution vectors.

Key Threats Addressed:
- Pickle deserialization RCE (arbitrary code execution on model load)
- PyTorch's torch.load() code execution
- TensorFlow SavedModel arbitrary code
- ONNX model graph manipulation
- HuggingFace model poisoning

Based on research: "nullifAI" campaign, broken Pickle format evasion, and
the broader AI/ML supply chain attack surface.

Author: Credence Security Research
"""

import asyncio
import base64
import hashlib
import json
import re
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import aiohttp


class ModelRisk(Enum):
    """Risk level for exposed models"""
    CRITICAL = "critical"      # Direct RCE on load
    HIGH = "high"              # Potential RCE with specific conditions
    MEDIUM = "medium"          # Data exposure, model theft
    LOW = "low"                # Minimal security impact
    INFO = "informational"     # Presence only


class ModelFormat(Enum):
    """Supported ML model formats"""
    PICKLE = "pickle"
    PYTORCH = "pytorch"
    TENSORFLOW = "tensorflow"
    KERAS = "keras"
    ONNX = "onnx"
    SAFETENSORS = "safetensors"
    HUGGINGFACE = "huggingface"
    SKLEARN = "sklearn"
    JOBLIB = "joblib"
    UNKNOWN = "unknown"


@dataclass
class MaliciousIndicator:
    """Indicator of potentially malicious content"""
    indicator_type: str
    description: str
    offset: Optional[int] = None
    raw_bytes: Optional[bytes] = None
    confidence: float = 0.0  # 0.0 - 1.0


@dataclass
class ExposedModel:
    """Represents an exposed ML model file"""
    url: str
    path: str
    format: ModelFormat
    size: int
    risk_level: ModelRisk
    indicators: List[MaliciousIndicator] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    content_hash: Optional[str] = None


@dataclass
class MLScanResult:
    """Complete scan result"""
    target: str
    exposed_models: List[ExposedModel]
    model_directories: List[str]
    total_risk_score: float
    recommendations: List[str]
    scan_duration: float = 0.0


class PickleAnalyzer:
    """
    Deep analysis of Python pickle files for malicious content.
    
    Pickle files can execute arbitrary Python code through:
    - __reduce__ method overrides
    - Global function references (os.system, subprocess, etc.)
    - Nested pickle streams
    """

    # Dangerous pickle opcodes
    DANGEROUS_OPCODES = {
        b'\x63': 'GLOBAL',      # Push global by module.name
        b'\x93': 'STACK_GLOBAL', # Push global from stack
        b'\x52': 'REDUCE',       # Apply callable to args
        b'\x81': 'NEWOBJ',       # Build object from class
        b'\x82': 'EXT1',         # Extension code
        b'\x83': 'EXT2',         # Extension code
        b'\x84': 'EXT4',         # Extension code
        b'\x92': 'NEWOBJ_EX',    # Extended newobj
    }

    # Known malicious module references
    DANGEROUS_MODULES = [
        b'os', b'subprocess', b'sys', b'builtins',
        b'commands', b'pty', b'socket', b'ctypes',
        b'pickle', b'_pickle', b'marshal', b'importlib',
        b'runpy', b'code', b'codeop', b'compile',
    ]

    # Known malicious function patterns
    DANGEROUS_FUNCTIONS = [
        b'system', b'popen', b'spawn', b'exec', b'eval',
        b'getattr', b'setattr', b'__import__', b'open',
        b'load', b'loads', b'Popen', b'call', b'check_output',
        b'run', b'create_connection', b'urlopen',
    ]

    # Pickle protocol signatures
    PICKLE_SIGNATURES = [
        b'\x80\x02',  # Protocol 2
        b'\x80\x03',  # Protocol 3
        b'\x80\x04',  # Protocol 4
        b'\x80\x05',  # Protocol 5
        b'(dp0',      # Protocol 0
        b'(lp0',      # Protocol 0 list
    ]

    def analyze(self, content: bytes) -> List[MaliciousIndicator]:
        """Analyze pickle content for malicious patterns"""
        indicators = []

        # Check for pickle signature
        if not self._is_pickle(content):
            return indicators

        # Scan for dangerous opcodes
        for opcode, name in self.DANGEROUS_OPCODES.items():
            positions = self._find_all(content, opcode)
            for pos in positions:
                # Extract context around opcode
                context = content[pos:pos+50]

                # Check if followed by dangerous module/function
                for module in self.DANGEROUS_MODULES:
                    if module in context:
                        indicators.append(MaliciousIndicator(
                            indicator_type="dangerous_global",
                            description=f"{name} opcode references dangerous module '{module.decode()}'",
                            offset=pos,
                            raw_bytes=context[:30],
                            confidence=0.9
                        ))

                for func in self.DANGEROUS_FUNCTIONS:
                    if func in context:
                        indicators.append(MaliciousIndicator(
                            indicator_type="dangerous_function",
                            description=f"{name} opcode may call dangerous function '{func.decode()}'",
                            offset=pos,
                            raw_bytes=context[:30],
                            confidence=0.85
                        ))

        # Check for nested pickles (obfuscation technique)
        nested_count = len(self._find_all(content, b'\x80\x04'))
        if nested_count > 1:
            indicators.append(MaliciousIndicator(
                indicator_type="nested_pickle",
                description=f"Contains {nested_count} nested pickle streams (obfuscation indicator)",
                confidence=0.6
            ))

        # Check for base64 encoded content (common obfuscation)
        b64_pattern = rb'[A-Za-z0-9+/]{50,}={0,2}'
        b64_matches = re.findall(b64_pattern, content)
        for match in b64_matches:
            try:
                decoded = base64.b64decode(match)
                # Check if decoded content is also pickle or contains code
                if any(sig in decoded for sig in self.PICKLE_SIGNATURES):
                    indicators.append(MaliciousIndicator(
                        indicator_type="encoded_pickle",
                        description="Contains base64 encoded pickle (evasion technique)",
                        raw_bytes=match[:30],
                        confidence=0.75
                    ))
            except Exception:
                pass

        # Check for 7z compression (nullifAI evasion technique)
        if content[:2] == b'7z' or b"7z\xbc\xaf\x27\x1c" in content[:20]:
            indicators.append(MaliciousIndicator(
                indicator_type="7z_compression",
                description="Uses 7z compression (known scanner evasion technique)",
                confidence=0.8
            ))

        return indicators

    def _is_pickle(self, content: bytes) -> bool:
        """Check if content appears to be a pickle file"""
        return any(content.startswith(sig) for sig in self.PICKLE_SIGNATURES)

    def _find_all(self, data: bytes, pattern: bytes) -> List[int]:
        """Find all occurrences of pattern in data"""
        positions = []
        start = 0
        while True:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
        return positions


class PyTorchAnalyzer:
    """
    Analyze PyTorch model files for security issues.
    
    PyTorch's torch.load() uses pickle by default, making it
    vulnerable to the same RCE vectors as raw pickle.
    """

    # PyTorch file signatures
    PYTORCH_SIGNATURES = [
        b'PK\x03\x04',  # ZIP format (modern .pt files)
        b'\x80\x02',    # Pickle protocol 2 (legacy)
    ]

    # Dangerous patterns in PyTorch serialized data
    DANGEROUS_PATTERNS = [
        (b'torch._C', "Native code loading"),
        (b'torch.cuda', "CUDA execution context"),
        (b'__reduce_ex__', "Custom deserialization"),
        (b'torch.jit', "JIT compilation"),
    ]

    def __init__(self):
        self.pickle_analyzer = PickleAnalyzer()

    def analyze(self, content: bytes) -> List[MaliciousIndicator]:
        """Analyze PyTorch model for security issues"""
        indicators = []

        # Check format
        if content.startswith(b'PK\x03\x04'):
            # Modern ZIP-based format
            indicators.extend(self._analyze_zip_pytorch(content))
        else:
            # Legacy pickle format - directly analyze
            indicators.extend(self.pickle_analyzer.analyze(content))

        # Check for dangerous patterns
        for pattern, description in self.DANGEROUS_PATTERNS:
            if pattern in content:
                indicators.append(MaliciousIndicator(
                    indicator_type="pytorch_pattern",
                    description=f"Contains {description}",
                    confidence=0.5
                ))

        return indicators

    def _analyze_zip_pytorch(self, content: bytes) -> List[MaliciousIndicator]:
        """Analyze ZIP-based PyTorch files"""
        indicators = []

        try:
            import io
            import zipfile

            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                for name in zf.namelist():
                    # Check for pickle files inside
                    if name.endswith(('.pkl', '.pickle', 'data.pkl')):
                        try:
                            pkl_content = zf.read(name)
                            pkl_indicators = self.pickle_analyzer.analyze(pkl_content)
                            for ind in pkl_indicators:
                                ind.description = f"[{name}] {ind.description}"
                            indicators.extend(pkl_indicators)
                        except Exception:
                            pass

                    # Check for suspicious files
                    if name.endswith(('.py', '.pyc', '.so', '.dll')):
                        indicators.append(MaliciousIndicator(
                            indicator_type="embedded_code",
                            description=f"Contains executable file: {name}",
                            confidence=0.7
                        ))
        except Exception:
            # Not a valid ZIP, analyze as raw pickle
            indicators.extend(self.pickle_analyzer.analyze(content))

        return indicators


class SafetensorsAnalyzer:
    """
    Analyze safetensors format - the secure alternative to pickle.
    
    Safetensors is designed to be safe, but we still check for:
    - Metadata injection
    - Unusually large metadata
    - Invalid format indicators
    """

    SAFETENSORS_MAGIC = b'safetensors'

    def analyze(self, content: bytes) -> List[MaliciousIndicator]:
        """Analyze safetensors file"""
        indicators = []

        try:
            # Safetensors format: 8-byte header size + JSON header + tensors
            if len(content) < 8:
                return indicators

            header_size = struct.unpack('<Q', content[:8])[0]

            # Check for suspiciously large header (metadata injection)
            if header_size > 10 * 1024 * 1024:  # 10MB header is suspicious
                indicators.append(MaliciousIndicator(
                    indicator_type="large_metadata",
                    description=f"Unusually large header ({header_size} bytes) - potential metadata injection",
                    confidence=0.6
                ))

            # Parse header JSON
            if len(content) >= 8 + header_size:
                header_json = content[8:8+header_size]
                try:
                    metadata = json.loads(header_json)

                    # Check for suspicious metadata keys
                    if '__metadata__' in metadata:
                        meta = metadata['__metadata__']
                        if any(k in str(meta).lower() for k in ['exec', 'eval', 'system', 'import']):
                            indicators.append(MaliciousIndicator(
                                indicator_type="suspicious_metadata",
                                description="Metadata contains code-like patterns",
                                confidence=0.5
                            ))
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass

        return indicators


class MLModelScanner:
    """
    Comprehensive scanner for exposed ML model files.
    
    Detects:
    - Exposed model files (.pkl, .pt, .h5, .onnx, etc.)
    - Model directories (/models/, /checkpoints/, etc.)
    - HuggingFace model repositories
    - Configuration files with model paths
    """

    # Model file extensions and their formats
    MODEL_EXTENSIONS = {
        '.pkl': ModelFormat.PICKLE,
        '.pickle': ModelFormat.PICKLE,
        '.pt': ModelFormat.PYTORCH,
        '.pth': ModelFormat.PYTORCH,
        '.bin': ModelFormat.PYTORCH,
        '.h5': ModelFormat.KERAS,
        '.hdf5': ModelFormat.KERAS,
        '.keras': ModelFormat.KERAS,
        '.onnx': ModelFormat.ONNX,
        '.safetensors': ModelFormat.SAFETENSORS,
        '.joblib': ModelFormat.JOBLIB,
        '.model': ModelFormat.UNKNOWN,
        '.weights': ModelFormat.UNKNOWN,
    }

    # Common model directories
    MODEL_DIRECTORIES = [
        "/models/",
        "/model/",
        "/checkpoints/",
        "/checkpoint/",
        "/saved_models/",
        "/trained_models/",
        "/weights/",
        "/artifacts/",
        "/ml/",
        "/ai/",
        "/huggingface/",
        "/.cache/huggingface/",
        "/transformers/",
        "/.transformers/",
    ]

    # Common model filenames
    MODEL_FILENAMES = [
        "model.pkl",
        "model.pt",
        "model.pth",
        "model.bin",
        "model.h5",
        "model.onnx",
        "model.safetensors",
        "pytorch_model.bin",
        "tf_model.h5",
        "weights.h5",
        "checkpoint.pt",
        "best_model.pt",
        "final_model.pkl",
        "classifier.pkl",
        "regressor.pkl",
        "embeddings.pkl",
        "tokenizer.pkl",
        "vocab.pkl",
        "config.json",
        "model_config.json",
        "training_args.bin",
    ]

    # HuggingFace specific paths
    HUGGINGFACE_PATHS = [
        "/config.json",
        "/tokenizer.json",
        "/tokenizer_config.json",
        "/special_tokens_map.json",
        "/vocab.txt",
        "/merges.txt",
        "/model.safetensors",
        "/pytorch_model.bin",
        "/tf_model.h5",
        "/flax_model.msgpack",
    ]

    def __init__(
        self,
        timeout: int = 20,
        max_concurrent: int = 15,
        download_limit: int = 10 * 1024 * 1024,  # 10MB download limit for analysis
        deep_analysis: bool = True
    ):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_concurrent = max_concurrent
        self.download_limit = download_limit
        self.deep_analysis = deep_analysis
        self.semaphore = asyncio.Semaphore(max_concurrent)

        # Initialize analyzers
        self.pickle_analyzer = PickleAnalyzer()
        self.pytorch_analyzer = PyTorchAnalyzer()
        self.safetensors_analyzer = SafetensorsAnalyzer()

    async def scan(
        self,
        target: str,
        session: Optional[aiohttp.ClientSession] = None
    ) -> MLScanResult:
        """
        Perform comprehensive ML model exposure scan.
        
        Args:
            target: Base URL to scan
            session: Optional aiohttp session
            
        Returns:
            MLScanResult with findings
        """
        import time
        start_time = time.time()

        own_session = session is None
        if own_session:
            connector = aiohttp.TCPConnector(ssl=False, limit=self.max_concurrent)
            session = aiohttp.ClientSession(connector=connector, timeout=self.timeout)

        try:
            target = self._normalize_url(target)

            # Stage 1: Discover model directories
            found_directories = await self._discover_directories(target, session)

            # Stage 2: Scan for model files
            exposed_models = await self._scan_for_models(target, session, found_directories)

            # Stage 3: Deep analysis of discovered models
            if self.deep_analysis:
                exposed_models = await self._analyze_models(exposed_models, session)

            # Generate result
            total_risk = self._calculate_total_risk(exposed_models)
            recommendations = self._generate_recommendations(exposed_models)

            return MLScanResult(
                target=target,
                exposed_models=exposed_models,
                model_directories=found_directories,
                total_risk_score=total_risk,
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

    async def _discover_directories(
        self,
        target: str,
        session: aiohttp.ClientSession
    ) -> List[str]:
        """Discover accessible model directories"""
        found = []

        tasks = []
        for directory in self.MODEL_DIRECTORIES:
            tasks.append(self._check_directory(target, directory, session))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for directory, result in zip(self.MODEL_DIRECTORIES, results):
            if result is True:
                found.append(directory)

        return found

    async def _check_directory(
        self,
        target: str,
        directory: str,
        session: aiohttp.ClientSession
    ) -> bool:
        """Check if a directory is accessible"""
        url = urljoin(target, directory)

        try:
            async with self.semaphore:
                async with session.get(url) as resp:
                    if resp.status in [200, 403]:  # 403 = exists but forbidden
                        return True
                    # Check for directory listing indicators
                    if resp.status == 200:
                        content = await resp.text()
                        if 'Index of' in content or '<title>Directory' in content:
                            return True
        except Exception:
            pass

        return False

    async def _scan_for_models(
        self,
        target: str,
        session: aiohttp.ClientSession,
        directories: List[str]
    ) -> List[ExposedModel]:
        """Scan for model files"""
        exposed = []

        # Build paths to check
        paths_to_check = []

        # Add common filenames at root and known directories
        for filename in self.MODEL_FILENAMES:
            paths_to_check.append(f"/{filename}")
            for directory in directories:
                paths_to_check.append(f"{directory}{filename}")

        # Add HuggingFace paths
        for hf_path in self.HUGGINGFACE_PATHS:
            paths_to_check.append(hf_path)
            for directory in directories:
                paths_to_check.append(f"{directory.rstrip('/')}{hf_path}")

        # Scan paths
        tasks = []
        for path in set(paths_to_check):
            tasks.append(self._check_model_file(target, path, session))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, ExposedModel):
                exposed.append(result)

        return exposed

    async def _check_model_file(
        self,
        target: str,
        path: str,
        session: aiohttp.ClientSession
    ) -> Optional[ExposedModel]:
        """Check if a model file exists and get metadata"""
        url = urljoin(target, path)

        try:
            async with self.semaphore:
                # Use HEAD first to check existence and size
                async with session.head(url) as resp:
                    if resp.status != 200:
                        return None

                    content_length = int(resp.headers.get('content-length', 0))
                    content_type = resp.headers.get('content-type', '')

                # Determine format from extension
                ext = Path(path).suffix.lower()
                model_format = self.MODEL_EXTENSIONS.get(ext, ModelFormat.UNKNOWN)

                # Calculate base risk
                risk_level = self._assess_base_risk(model_format, path)

                return ExposedModel(
                    url=url,
                    path=path,
                    format=model_format,
                    size=content_length,
                    risk_level=risk_level,
                    metadata={
                        'content_type': content_type,
                        'extension': ext,
                    }
                )
        except Exception:
            pass

        return None

    def _assess_base_risk(self, model_format: ModelFormat, path: str) -> ModelRisk:
        """Assess base risk level for a model format"""
        # Formats with RCE potential
        if model_format in [ModelFormat.PICKLE, ModelFormat.PYTORCH, ModelFormat.JOBLIB]:
            return ModelRisk.CRITICAL

        # Formats that could have embedded code
        if model_format in [ModelFormat.KERAS, ModelFormat.TENSORFLOW]:
            return ModelRisk.HIGH

        # Safer formats
        if model_format == ModelFormat.SAFETENSORS:
            return ModelRisk.LOW

        if model_format == ModelFormat.ONNX:
            return ModelRisk.MEDIUM

        return ModelRisk.MEDIUM

    async def _analyze_models(
        self,
        models: List[ExposedModel],
        session: aiohttp.ClientSession
    ) -> List[ExposedModel]:
        """Deep analysis of model files"""
        tasks = []
        for model in models:
            if model.size <= self.download_limit:
                tasks.append(self._analyze_single_model(model, session))
            else:
                # For large files, only analyze header
                tasks.append(self._analyze_model_header(model, session))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        analyzed = []
        for model, result in zip(models, results):
            if isinstance(result, list):
                model.indicators = result
                # Upgrade risk if malicious indicators found
                if any(ind.confidence >= 0.8 for ind in result):
                    model.risk_level = ModelRisk.CRITICAL
                elif any(ind.confidence >= 0.6 for ind in result):
                    if model.risk_level != ModelRisk.CRITICAL:
                        model.risk_level = ModelRisk.HIGH
            analyzed.append(model)

        return analyzed

    async def _analyze_single_model(
        self,
        model: ExposedModel,
        session: aiohttp.ClientSession
    ) -> List[MaliciousIndicator]:
        """Download and analyze a model file"""
        indicators = []

        try:
            async with self.semaphore:
                async with session.get(model.url) as resp:
                    if resp.status == 200:
                        content = await resp.read()

                        # Hash the content
                        model.content_hash = hashlib.sha256(content).hexdigest()

                        # Analyze based on format
                        if model.format == ModelFormat.PICKLE:
                            indicators = self.pickle_analyzer.analyze(content)
                        elif model.format == ModelFormat.PYTORCH:
                            indicators = self.pytorch_analyzer.analyze(content)
                        elif model.format == ModelFormat.SAFETENSORS:
                            indicators = self.safetensors_analyzer.analyze(content)
                        elif model.format in [ModelFormat.KERAS, ModelFormat.TENSORFLOW]:
                            # H5 files can contain pickled data
                            if b'\x80\x02' in content or b'\x80\x04' in content:
                                indicators = self.pickle_analyzer.analyze(content)
                        else:
                            # Generic pickle check
                            indicators = self.pickle_analyzer.analyze(content)
        except Exception as e:
            indicators.append(MaliciousIndicator(
                indicator_type="analysis_error",
                description=f"Could not analyze: {str(e)}",
                confidence=0.0
            ))

        return indicators

    async def _analyze_model_header(
        self,
        model: ExposedModel,
        session: aiohttp.ClientSession
    ) -> List[MaliciousIndicator]:
        """Analyze only the header of large files"""
        indicators = []

        try:
            headers = {'Range': 'bytes=0-10240'}  # First 10KB
            async with self.semaphore:
                async with session.get(model.url, headers=headers) as resp:
                    if resp.status in [200, 206]:
                        content = await resp.read()

                        # Quick check for dangerous patterns
                        if model.format in [ModelFormat.PICKLE, ModelFormat.PYTORCH]:
                            # Check for dangerous opcodes in header
                            for opcode in [b'\x63', b'\x52', b'\x81']:
                                if opcode in content:
                                    indicators.append(MaliciousIndicator(
                                        indicator_type="dangerous_opcode_header",
                                        description="Dangerous pickle opcode in file header",
                                        confidence=0.7
                                    ))
                                    break
        except Exception:
            pass

        return indicators

    def _calculate_total_risk(self, models: List[ExposedModel]) -> float:
        """Calculate aggregate risk score"""
        if not models:
            return 0.0

        risk_values = {
            ModelRisk.CRITICAL: 10.0,
            ModelRisk.HIGH: 7.0,
            ModelRisk.MEDIUM: 4.0,
            ModelRisk.LOW: 2.0,
            ModelRisk.INFO: 0.5,
        }

        # Weighted sum with diminishing returns
        total = 0.0
        for i, model in enumerate(sorted(models, key=lambda m: risk_values.get(m.risk_level, 0), reverse=True)):
            weight = 1.0 / (1 + i * 0.3)  # Diminishing weight for subsequent findings
            total += risk_values.get(model.risk_level, 0) * weight

        return min(total, 10.0)

    def _generate_recommendations(self, models: List[ExposedModel]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        if not models:
            return ["No exposed ML models found - maintain current security posture"]

        has_pickle = any(m.format in [ModelFormat.PICKLE, ModelFormat.PYTORCH, ModelFormat.JOBLIB] for m in models)
        has_critical = any(m.risk_level == ModelRisk.CRITICAL for m in models)
        has_hf = any('huggingface' in m.path.lower() or 'transformers' in m.path.lower() for m in models)

        if has_critical:
            recommendations.append("CRITICAL: Remove exposed pickle/PyTorch model files immediately - they can execute arbitrary code on load")

        if has_pickle:
            recommendations.extend([
                "Migrate from pickle to safetensors format for model serialization",
                "Implement model signing and verification before loading",
                "Never load models from untrusted sources using torch.load() or pickle.load()",
            ])

        if has_hf:
            recommendations.extend([
                "Restrict access to HuggingFace cache directories",
                "Use private model repositories with access controls",
                "Verify model integrity using HuggingFace Hub's commit hashes",
            ])

        recommendations.extend([
            "Configure web server to deny access to model directories",
            "Implement Content-Security-Policy to prevent unauthorized model downloads",
            "Audit model provenance and maintain SBOM for ML dependencies",
        ])

        return recommendations

    def generate_report(self, result: MLScanResult) -> str:
        """Generate human-readable report"""
        lines = [
            "=" * 70,
            "ML MODEL SUPPLY CHAIN SECURITY SCAN",
            f"Target: {result.target}",
            f"Duration: {result.scan_duration:.2f}s",
            "=" * 70,
            "",
            f"Total Risk Score: {result.total_risk_score:.1f}/10.0",
            f"Exposed Models: {len(result.exposed_models)}",
            f"Model Directories Found: {len(result.model_directories)}",
            "",
        ]

        if result.model_directories:
            lines.append("ACCESSIBLE DIRECTORIES:")
            for directory in result.model_directories:
                lines.append(f"  📁 {directory}")
            lines.append("")

        if result.exposed_models:
            lines.append("EXPOSED MODELS:")
            for model in sorted(result.exposed_models, key=lambda m: m.risk_level.value):
                risk_emoji = {
                    ModelRisk.CRITICAL: "🔴",
                    ModelRisk.HIGH: "🟠",
                    ModelRisk.MEDIUM: "🟡",
                    ModelRisk.LOW: "🟢",
                    ModelRisk.INFO: "⚪",
                }.get(model.risk_level, "⚪")

                lines.append(f"  {risk_emoji} [{model.risk_level.value.upper()}] {model.path}")
                lines.append(f"     Format: {model.format.value} | Size: {model.size:,} bytes")

                if model.indicators:
                    lines.append("     Indicators:")
                    for ind in model.indicators[:3]:
                        lines.append(f"       ⚠ {ind.description} (confidence: {ind.confidence:.0%})")
                lines.append("")

        if result.recommendations:
            lines.append("RECOMMENDATIONS:")
            for rec in result.recommendations:
                lines.append(f"  → {rec}")
            lines.append("")

        lines.append("=" * 70)
        return "\n".join(lines)


async def main():
    """CLI entry point"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python ml_model_scanner.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    scanner = MLModelScanner(deep_analysis=True)

    print(f"[*] Scanning {target} for exposed ML models...")
    result = await scanner.scan(target)
    print(scanner.generate_report(result))


if __name__ == "__main__":
    asyncio.run(main())
