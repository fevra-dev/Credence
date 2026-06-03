"""
Credence Git Repository Analysis Module

Tools for downloading and analyzing exposed .git repositories:
- Git Dumper: Reconstruct exposed repositories
- Git Analyzer: Scan commit history for secrets
"""

from .git_analyzer import GitSecretAnalyzer
from .git_dumper import GitDumper

__all__ = [
    'GitDumper',
    'GitSecretAnalyzer',
]
