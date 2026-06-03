"""
Response signature matching for vulnerability confirmation.

This module validates HTTP responses to confirm real vulnerabilities
and filter out false positives (custom 404 pages, WAF blocks, etc).
"""

import logging
from typing import Optional, Tuple
from urllib.parse import urlparse

from .models import PathDefinition, ScanResult

logger = logging.getLogger(__name__)


# Common false positive indicators
FALSE_POSITIVE_SIGNATURES = [
    "404 Not Found",
    "Page Not Found",
    "File Not Found",
    "The page you requested",
    "does not exist",
    "could not be found",
    "Error 404",
    "Not Found</title>",
    "<title>404</title>",
    "Access Denied",
    "403 Forbidden",
    "You don't have permission",
    "Unauthorized",
    "Login Required",
    "Please log in",
    "blocked",
    "firewall",
    "security",
]


def check_false_positive(body: str, status_code: int) -> bool:
    """
    Check if response is likely a false positive.

    Args:
        body: Response body text
        status_code: HTTP status code

    Returns:
        True if likely false positive, False otherwise
    """
    # Status codes that indicate no vulnerability
    if status_code in (403, 404, 500, 502, 503, 504):
        return True

    # Empty response on non-200
    if status_code != 200 and len(body.strip()) == 0:
        return True

    # Check for false positive signatures in body
    body_lower = body.lower()
    for signature in FALSE_POSITIVE_SIGNATURES:
        if signature.lower() in body_lower:
            logger.debug(f"False positive detected: '{signature}'")
            return True

    return False


def match_signatures(
    body: str,
    path_def: PathDefinition,
    status_code: int,
    content_type: str,
) -> Tuple[bool, str]:
    """
    Match response against path signatures to confirm vulnerability.

    Args:
        body: Response body text
        path_def: Path definition with expected signatures
        status_code: HTTP status code
        content_type: Response Content-Type header

    Returns:
        Tuple of (is_vulnerable, evidence_string)
    """
    logger.debug(f"Checking signatures for {path_def.path}")

    # Must be a successful response
    if status_code not in (200, 301, 302):
        return False, ""

    # Check for false positives first
    if check_false_positive(body, status_code):
        return False, ""

    # For paths with no signatures, any non-404 response with content is suspicious
    if not path_def.signatures:
        if status_code == 200 and len(body) > 0:
            # Check content type if specified
            if path_def.content_types:
                ct_lower = content_type.lower()
                if any(ct in ct_lower for ct in path_def.content_types):
                    return (
                        True,
                        f"File exists (Status: {status_code}, Content-Type: {content_type})",
                    )
            else:
                return True, f"File exists (Status: {status_code})"
        return False, ""

    # Check each signature
    body_content = body[:50000]  # Limit search to first 50KB

    for signature in path_def.signatures:
        if signature in body_content:
            evidence = f"Found signature: {signature[:50]}"
            logger.info(f"Signature matched: {signature[:30]}... in {path_def.path}")
            return True, evidence

    # Check for generic credential patterns if this is a config/env file
    if path_def.category.value in ("environment", "configuration"):
        credential_patterns = [
            "password",
            "passwd",
            "pwd",
            "secret",
            "api_key",
            "apikey",
            "access_key",
            "private_key",
            "token",
            "auth",
            "credential",
        ]
        body_lower = body_content.lower()
        for pattern in credential_patterns:
            if pattern in body_lower:
                return True, f"Contains: {pattern}"

    return False, ""


def validate_response(
    url: str,
    path_def: PathDefinition,
    status_code: int,
    body: str,
    content_type: str,
    error: Optional[str],
) -> ScanResult:
    """
    Validate a response and create a ScanResult.

    Args:
        url: Full URL that was scanned
        path_def: Path definition
        status_code: HTTP status code (0 if error)
        body: Response body
        content_type: Content-Type header
        error: Error message if request failed

    Returns:
        ScanResult object
    """
    # Extract target from URL
    parsed = urlparse(url)
    target = f"{parsed.scheme}://{parsed.netloc}"

    # Handle request errors
    if error:
        return ScanResult(
            url=url,
            path=path_def.path,
            target=target,
            status_code=status_code,
            vulnerable=False,
            severity=path_def.severity,
            category=path_def.category,
            description=path_def.description,
            evidence="",
            response_length=0,
            content_type="",
            error=error,
        )

    # Validate response
    is_vulnerable, evidence = match_signatures(body, path_def, status_code, content_type)

    return ScanResult(
        url=url,
        path=path_def.path,
        target=target,
        status_code=status_code,
        vulnerable=is_vulnerable,
        severity=path_def.severity,
        category=path_def.category,
        description=path_def.description,
        evidence=evidence,
        response_length=len(body),
        content_type=content_type,
        error=None,
    )

