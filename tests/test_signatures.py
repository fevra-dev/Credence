"""Test signature matching."""

import pytest
from credence.signatures import match_signatures, check_false_positive
from credence.models import PathDefinition, Category, Severity


class TestFalsePositiveDetection:
    """Test false positive filtering."""

    def test_404_status_is_false_positive(self):
        assert check_false_positive("Not Found", 404) is True

    def test_403_status_is_false_positive(self):
        assert check_false_positive("Forbidden", 403) is True

    def test_200_with_404_text_is_false_positive(self):
        body = "<html><title>404 Not Found</title></html>"
        assert check_false_positive(body, 200) is True

    def test_200_with_valid_content_is_not_false_positive(self):
        body = "[core]\n\trepositoryformatversion = 0"
        assert check_false_positive(body, 200) is False


class TestSignatureMatching:
    """Test signature matching logic."""

    def test_git_config_signature_match(self):
        path_def = PathDefinition(
            path=".git/config",
            category=Category.GIT,
            severity=Severity.CRITICAL,
            description="Test",
            signatures=["[core]", "[remote"],
            content_types=["text/plain"],
        )

        body = "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]"
        is_vuln, evidence = match_signatures(body, path_def, 200, "text/plain")

        assert is_vuln is True
        assert "[core]" in evidence

    def test_no_match_on_404(self):
        path_def = PathDefinition(
            path=".git/config",
            category=Category.GIT,
            severity=Severity.CRITICAL,
            description="Test",
            signatures=["[core]"],
            content_types=["text/plain"],
        )

        is_vuln, evidence = match_signatures("[core]", path_def, 404, "text/plain")
        assert is_vuln is False

    def test_env_file_credential_detection(self):
        path_def = PathDefinition(
            path=".env",
            category=Category.ENV,
            severity=Severity.CRITICAL,
            description="Test",
            signatures=["DB_PASSWORD"],
            content_types=["text/plain"],
        )

        body = "APP_NAME=Test\nDB_PASSWORD=secret123\n"
        is_vuln, evidence = match_signatures(body, path_def, 200, "text/plain")

        assert is_vuln is True

