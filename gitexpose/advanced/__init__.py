"""
GitExpose Advanced Security Modules

Cutting-edge security scanning capabilities addressing the 2025 threat landscape:
- React2Shell Detection (CVE-2025-55182)
- ML Model Supply Chain Scanning
- LLM/RAG Infrastructure Exposure
- Invisible Unicode Detection (GlassWorm patterns)
- Cloud Asset Scanning
- Source Map Analysis
- CI/CD Pipeline Exposure
- Infrastructure as Code Security
- API Discovery
- Stealth/WAF Evasion
- MCP Server for AI Agent Integration
"""

from .api_discovery import APIDiscovery
from .cicd_scanner import CICDScanner
from .cloud_scanner import CloudScanner
from .iac_scanner import IaCScanner
from .invisible_unicode_detector import InvisibleUnicodeAnalyzer, InvisibleUnicodeScanner
from .llm_exposure_scanner import LLMExposureScanner, LLMScanResult
from .mcp_server import GitExposeMCPServer
from .ml_model_scanner import MLModelScanner, MLScanResult, PickleAnalyzer
from .react2shell_detector import React2ShellDetector, React2ShellFinding
from .sourcemap_analyzer import SourceMapAnalyzer
from .stealth_scanner import StealthScanner

__all__ = [
    # React2Shell
    'React2ShellDetector',
    'React2ShellFinding',

    # ML Model Security
    'MLModelScanner',
    'MLScanResult',
    'PickleAnalyzer',

    # LLM/RAG Security
    'LLMExposureScanner',
    'LLMScanResult',

    # Unicode Detection
    'InvisibleUnicodeScanner',
    'InvisibleUnicodeAnalyzer',

    # Cloud Security
    'CloudScanner',

    # Source Maps
    'SourceMapAnalyzer',

    # CI/CD Security
    'CICDScanner',

    # Infrastructure as Code
    'IaCScanner',

    # API Discovery
    'APIDiscovery',

    # Stealth Operations
    'StealthScanner',

    # MCP Server
    'GitExposeMCPServer',
]
