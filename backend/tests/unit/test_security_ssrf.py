"""
Unit tests for SSRF prevention and target URL validation
"""

from app.core.security import validate_target_url


def test_validate_target_url_permits_authorized_targets():
    """Verify that allowed hosts, localhost, and private IPs are permitted."""
    valid_targets = [
        "http://localhost:8001",
        "http://127.0.0.1:8000",
        "http://vulnerable-api:8000",
        "http://192.168.1.50:8000",
        "http://10.0.0.5:8080",
    ]
    for url in valid_targets:
        is_valid, msg = validate_target_url(url)
        assert is_valid is True, f"Expected {url} to be allowed, but got error: {msg}"


def test_validate_target_url_blocks_unauthorized_public_targets():
    """Verify that unauthorized public domains/IPs are rejected (SSRF protection)."""
    blocked_targets = [
        "http://example.com",
        "https://google.com/api",
        "http://8.8.8.8",
        "ftp://localhost",
        "",
    ]
    for url in blocked_targets:
        is_valid, msg = validate_target_url(url)
        assert is_valid is False, f"Expected {url} to be blocked by SSRF validation"
