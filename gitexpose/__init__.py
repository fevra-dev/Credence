"""
GitExpose - Exposure intelligence for AI and dev infrastructure

A comprehensive, high-performance security scanner that detects exposed sensitive
files, vulnerable frameworks, AI/ML infrastructure, and supply chain threats.

Core Capabilities:
- Sensitive file detection (.git, .env, configs, backups)
- React2Shell vulnerability detection (CVE-2025-55182)
- ML model supply chain scanning
- LLM/RAG infrastructure exposure
- Invisible Unicode detection (GlassWorm patterns)
- Cloud asset scanning
- CI/CD pipeline exposure
- API discovery and analysis
- Source map recovery
- WAF evasion capabilities
- MCP server for AI agent integration

Usage:
    from gitexpose import GitExposeScanner
    
    scanner = GitExposeScanner()
    report = scanner.scan_sync(['example.com'])
    
    # Advanced modules
    from gitexpose.advanced import React2ShellDetector, MLModelScanner
    from gitexpose.git import GitDumper
    from gitexpose.secrets import SecretExtractor
"""

__version__ = "0.6.1"
__author__ = "GitExpose Contributors"
__license__ = "MIT"

# Core scanner
# Models
from .models import ScanReport, ScanResult, TargetReport
from .scanner import GitExposeScanner


# Submodule exports (lazy import to avoid circular dependencies)
def __getattr__(name):
    """Lazy import for submodules."""
    if name == 'advanced':
        from . import advanced
        return advanced
    elif name == 'git':
        from . import git
        return git
    elif name == 'secrets':
        from . import secrets
        return secrets
    elif name == 'reporters':
        from . import reporters
        return reporters
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    # Version info
    '__version__',
    '__author__',
    '__license__',
    # Core
    'GitExposeScanner',
    # Models
    'ScanReport',
    'TargetReport',
    'ScanResult',
    # Submodules (accessed via gitexpose.advanced, etc.)
    'advanced',
    'git',
    'secrets',
    'reporters',
]
