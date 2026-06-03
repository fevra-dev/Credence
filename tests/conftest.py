"""pytest fixtures."""

import pytest
from credence.scanner import CredenceScanner
from credence.paths import get_all_paths


@pytest.fixture
def scanner():
    """Create a scanner instance for testing."""
    return CredenceScanner(timeout=5, concurrency=10)


@pytest.fixture
def sample_paths():
    """Get sample paths for testing."""
    return get_all_paths()[:5]  # First 5 paths

