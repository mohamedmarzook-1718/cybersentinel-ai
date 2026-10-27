"""
SSRF Protection and URL Validator for CyberSentinel Web Security Scanner.

Guarantees:
- Strict scheme enforcement (http/https only)
- Hostname and DNS resolution
- Complete prohibition of private, loopback, link-local, multicast, and cloud metadata addresses
- Safe URL normalization
"""
from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse
from typing import Tuple, List


class SecurityValidationError(ValueError):
    """Raised when a target URL fails safety or SSRF protection rules."""
    pass


PROHIBITED_HOSTNAMES = {
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "metadata.google.internal",
    "instance-data",
}

CLOUD_METADATA_IPS = {
    "169.254.169.254",   # AWS, GCP, Azure, OpenStack, DigitalOcean
    "100.100.100.200",   # Alibaba Cloud
    "169.254.169.250",
    "169.254.169.251",
}


def validate_target_url(raw_url: str) -> Tuple[str, str, str]:
    """
    Validate, sanitize, and verify a target URL for passive scanning.

    Returns:
        (normalized_url, hostname, primary_ip)

    Raises:
        SecurityValidationError: If the URL violates SSRF guards or safety constraints.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise SecurityValidationError("Target URL must not be empty.")

    cleaned = raw_url.strip()

    # Prepend https:// if no scheme is provided
    if not cleaned.startswith(("http://", "https://")):
        if "://" in cleaned:
            scheme = cleaned.split("://")[0]
            raise SecurityValidationError(f"Unsupported protocol scheme '{scheme}'. Only HTTP and HTTPS are permitted.")
        cleaned = "https://" + cleaned

    try:
        parsed = urlparse(cleaned)
    except Exception as e:
        raise SecurityValidationError(f"Invalid URL structure: {str(e)}")

    if parsed.scheme not in ("http", "https"):
        raise SecurityValidationError(f"Invalid scheme '{parsed.scheme}'. Only HTTP and HTTPS are supported.")

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise SecurityValidationError("Target URL does not specify a valid hostname.")

    # Reject credentials in URL (e.g. https://user:pass@example.com)
    if parsed.username or parsed.password:
        raise SecurityValidationError("URLs containing embedded user credentials are prohibited.")

    # Check prohibited hostnames and suffixes
    if hostname in PROHIBITED_HOSTNAMES or any(
        hostname.endswith(sfx)
        for sfx in (".local", ".localhost", ".internal", ".lan", ".home.arpa", ".onion", ".invalid")
    ):
        raise SecurityValidationError(
            f"Scanning internal or local hostname '{hostname}' is strictly prohibited for security safety."
        )

    # Resolve hostname via DNS and check all returned IP addresses
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    resolved_ips: List[str] = []

    try:
        addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        for entry in addr_info:
            ip_str = entry[4][0]
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)
    except socket.gaierror as e:
        raise SecurityValidationError(f"DNS resolution failed for hostname '{hostname}': {str(e)}")
    except Exception as e:
        raise SecurityValidationError(f"Unable to resolve host '{hostname}': {str(e)}")

    if not resolved_ips:
        raise SecurityValidationError(f"No IP addresses could be resolved for '{hostname}'.")

    # Audit each resolved IP against SSRF rules
    for ip_str in resolved_ips:
        if ip_str in CLOUD_METADATA_IPS:
            raise SecurityValidationError(
                f"Target resolves to a restricted cloud metadata address ({ip_str}). Scanning blocked."
            )

        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise SecurityValidationError(f"Invalid IP address representation encountered: {ip_str}")

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            raise SecurityValidationError(
                f"Target resolves to a non-public or reserved IP address ({ip_str}). "
                "Scanning private network infrastructure is strictly prohibited."
            )

    # Reconstruct normalized URL with standard casing
    path = parsed.path or "/"
    normalized = f"{parsed.scheme}://{hostname}"
    if parsed.port and (
        (parsed.scheme == "http" and parsed.port != 80)
        or (parsed.scheme == "https" and parsed.port != 443)
    ):
        normalized += f":{parsed.port}"
    normalized += path
    if parsed.query:
        normalized += f"?{parsed.query}"

    return normalized, hostname, resolved_ips[0]
