"""
TLS and SSL Certificate Inspector for CyberSentinel Web Security Scanner.

Safely checks:
- HTTPS availability
- Certificate validity and expiration date
- Issuer identification
- Protocol version (TLS 1.2 / 1.3 vs deprecated)
- Hostname matching
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


def inspect_tls(
    hostname: str,
    port: int = 443,
    timeout: float = 6.0,
) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
    """
    Connect to the target hostname on the specified TLS port and inspect the certificate.

    Returns:
        (metadata_dict, findings_list)
    """
    findings: List[Dict[str, str]] = []
    meta: Dict[str, Any] = {
        "tls_version": None,
        "cert_valid": False,
        "cert_issuer": None,
        "cert_expires_at": None,
        "days_until_expiry": None,
        "cipher": None,
    }

    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                meta["tls_version"] = ssock.version()
                cipher_info = ssock.cipher()
                if cipher_info:
                    meta["cipher"] = cipher_info[0]

                # Parse issuer
                issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                issuer_name = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown CA"
                meta["cert_issuer"] = issuer_name

                # Parse expiration date
                not_after_str = cert.get("notAfter")
                if not_after_str:
                    # Format: 'May 12 12:00:00 2026 GMT'
                    try:
                        expire_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        meta["cert_expires_at"] = expire_dt
                        now = datetime.now(timezone.utc)
                        days_left = (expire_dt - now).days
                        meta["days_until_expiry"] = days_left

                        if days_left < 0:
                            meta["cert_valid"] = False
                            findings.append({
                                "id": "TLS-CERT-EXPIRED",
                                "severity": "Critical",
                                "category": "TLS/SSL",
                                "title": "TLS Certificate Has Expired",
                                "evidence": f"Certificate expired on {expire_dt.strftime('%Y-%m-%d')} ({abs(days_left)} days ago).",
                                "affected_url": f"https://{hostname}:{port}",
                                "explanation": "Browsers reject connections with expired certificates, displaying severe security warnings to users.",
                                "recommendation": "Renew and re-deploy your TLS certificate immediately via your Certificate Authority (or Let's Encrypt).",
                            })
                        elif days_left <= 14:
                            meta["cert_valid"] = True
                            findings.append({
                                "id": "TLS-CERT-EXPIRING-SOON",
                                "severity": "Medium",
                                "category": "TLS/SSL",
                                "title": f"TLS Certificate Expiring in {days_left} Days",
                                "evidence": f"Certificate expiration date is {expire_dt.strftime('%Y-%m-%d')} ({days_left} days remaining).",
                                "affected_url": f"https://{hostname}:{port}",
                                "explanation": "If the certificate is not renewed before expiry, visitors will encounter broken SSL warning screens.",
                                "recommendation": "Verify automated renewal or issue a replacement certificate before the expiration window closes.",
                            })
                        else:
                            meta["cert_valid"] = True
                            findings.append({
                                "id": "TLS-CERT-VALID",
                                "severity": "Informational",
                                "category": "TLS/SSL",
                                "title": "Valid TLS Certificate Installed",
                                "evidence": f"Verified by {issuer_name}; valid until {expire_dt.strftime('%Y-%m-%d')} ({days_left} days remaining).",
                                "affected_url": f"https://{hostname}:{port}",
                                "explanation": "The web server provides authentic identity verification and robust transport-layer confidentiality.",
                                "recommendation": "Maintain automated certificate lifecycle monitoring.",
                            })
                    except Exception as e:
                        meta["cert_valid"] = True
                        meta["cert_expires_at"] = None

                # Protocol version check
                version = meta["tls_version"] or ""
                if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    findings.append({
                        "id": "TLS-DEPRECATED-PROTOCOL",
                        "severity": "High",
                        "category": "TLS/SSL",
                        "title": f"Deprecated TLS Protocol Enabled ({version})",
                        "evidence": f"Negotiated protocol version is {version}.",
                        "affected_url": f"https://{hostname}:{port}",
                        "explanation": "TLS 1.0 and 1.1 have known cryptographic weaknesses and have been deprecated by major browsers and standards bodies (RFC 8996).",
                        "recommendation": "Disable TLS 1.0 and 1.1 in web server configuration; require TLS 1.2 and TLS 1.3 only.",
                    })

    except ssl.SSLCertVerificationError as e:
        meta["cert_valid"] = False
        err_msg = str(e)
        if "expired" in err_msg.lower():
            findings.append({
                "id": "TLS-CERT-EXPIRED",
                "severity": "Critical",
                "category": "TLS/SSL",
                "title": "TLS Certificate Expired",
                "evidence": f"Verification error: {err_msg}",
                "affected_url": f"https://{hostname}:{port}",
                "explanation": "The TLS certificate timestamp has lapsed. Browsers will block connections.",
                "recommendation": "Renew and install an up-to-date certificate immediately.",
            })
        elif "self signed" in err_msg.lower() or "unable to get local issuer" in err_msg.lower():
            findings.append({
                "id": "TLS-CERT-UNTRUSTED",
                "severity": "High",
                "category": "TLS/SSL",
                "title": "Self-Signed or Untrusted Root Certificate",
                "evidence": f"Certificate verification failed: {err_msg}",
                "affected_url": f"https://{hostname}:{port}",
                "explanation": "The server's certificate is not signed by a recognized Certificate Authority in browser trust stores.",
                "recommendation": "Acquire and configure a certificate signed by a publicly trusted CA (e.g., Let's Encrypt).",
            })
        else:
            findings.append({
                "id": "TLS-CERT-MISMATCH",
                "severity": "High",
                "category": "TLS/SSL",
                "title": "TLS Certificate Verification Mismatch",
                "evidence": f"Verification failed: {err_msg}",
                "affected_url": f"https://{hostname}:{port}",
                "explanation": "The presented certificate does not match the requested hostname or CA chain.",
                "recommendation": "Ensure the certificate Common Name (CN) or Subject Alternative Name (SAN) covers this domain.",
            })

    except (socket.timeout, TimeoutError):
        findings.append({
            "id": "TLS-TIMEOUT",
            "severity": "Medium",
            "category": "Availability",
            "title": "TLS Connection Timeout",
            "evidence": f"Handshake timed out after {timeout} seconds on port {port}.",
            "affected_url": f"https://{hostname}:{port}",
            "explanation": "The remote server did not complete the TLS handshake in a reasonable time frame.",
            "recommendation": "Verify firewall rules and web server responsiveness.",
        })

    except Exception as e:
        meta["cert_valid"] = False
        findings.append({
            "id": "TLS-NOT-SUPPORTED",
            "severity": "High",
            "category": "TLS/SSL",
            "title": "HTTPS Not Available / Connection Refused",
            "evidence": f"Unable to establish TLS connection: {str(e)}",
            "affected_url": f"https://{hostname}:{port}",
            "explanation": "Port 443 is not open or not responding to TLS handshakes. Traffic may be transmitted in plaintext.",
            "recommendation": "Enable TLS on the web server and acquire an authorized SSL/TLS certificate.",
        })

    return meta, findings
