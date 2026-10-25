"""
SentinelX Security Controls
---------------------------
Defensive security controls:
1. Target URL validation and SSRF prevention
2. Request timeout and rate limit enforcement
"""

import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple

from app.config import settings


class SecurityValidationError(Exception):
    """Raised when target URL fails security validation."""
    pass


def is_ip_private_or_loopback(ip_str: str) -> bool:
    """Check if an IP address string is loopback or private."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return False


def validate_target_url(target_url: str) -> Tuple[bool, str]:
    """
    Validate that target URL is authorized for scanning.
    Enforces SSRF prevention and target containment.

    Returns:
        (is_valid: bool, error_message: str)
    """
    if not target_url:
        return False, "Target URL cannot be empty"

    try:
        parsed = urlparse(target_url)
    except Exception as e:
        return False, f"Invalid URL format: {str(e)}"

    if parsed.scheme not in ("http", "https"):
        return False, f"Invalid URL scheme '{parsed.scheme}'. Only http and https are allowed."

    hostname = parsed.hostname
    if not hostname:
        return False, "Target URL must contain a valid hostname or IP address"

    allowed_hosts = settings.allowed_target_hosts

    # 1. Exact match with allowed targets (e.g. vulnerable-api, localhost)
    if hostname.lower() in [h.lower() for h in allowed_hosts]:
        return True, ""

    # 2. Check if hostname is an IP and is loopback/private
    if is_ip_private_or_loopback(hostname):
        return True, ""

    # 3. Resolve hostname to check if it resolves to private IP
    try:
        resolved_ips = socket.gethostbyname_ex(hostname)[2]
        for ip in resolved_ips:
            if is_ip_private_or_loopback(ip):
                return True, ""
    except Exception:
        pass

    return (
        False,
        f"Target host '{hostname}' is not authorized. Scanner is restricted to local/private authorized targets.",
    )
