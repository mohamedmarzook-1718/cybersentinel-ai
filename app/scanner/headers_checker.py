"""
HTTP Security Headers, Cookies, and Information Disclosure Analyzer.

Audits:
- Security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Information disclosure (Server banner, X-Powered-By, technology versions)
- Cookie flags (Secure, HttpOnly, SameSite)
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple


def audit_headers_and_cookies(
    headers: Dict[str, str],
    raw_cookies: List[str],
    target_url: str,
    is_https: bool = True,
) -> List[Dict[str, str]]:
    """
    Perform passive security analysis on HTTP headers and observable cookies.

    Returns:
        List of findings formatted as dictionaries.
    """
    findings: List[Dict[str, str]] = []

    # Normalize header keys to lowercase
    lower_headers = {k.lower(): v for k, v in headers.items()}

    # ── 1. Strict-Transport-Security (HSTS) ────────────────────────────────────
    hsts = lower_headers.get("strict-transport-security")
    if is_https:
        if not hsts:
            findings.append({
                "id": "SEC-HDR-HSTS-MISSING",
                "severity": "High",
                "category": "Security Headers",
                "title": "Missing Strict-Transport-Security (HSTS) Header",
                "evidence": "Strict-Transport-Security header was not returned in response.",
                "affected_url": target_url,
                "explanation": (
                    "HSTS instructs browsers to strictly communicate over HTTPS, protecting visitors "
                    "from SSL-stripping and man-in-the-middle attacks on public networks."
                ),
                "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to your web server response headers.",
            })
        else:
            # Check max-age
            max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
            if max_age_match:
                max_age_val = int(max_age_match.group(1))
                if max_age_val < 15552000:  # < 180 days
                    findings.append({
                        "id": "SEC-HDR-HSTS-SHORT",
                        "severity": "Low",
                        "category": "Security Headers",
                        "title": "HSTS Max-Age Duration is Under 180 Days",
                        "evidence": f"Strict-Transport-Security: {hsts}",
                        "affected_url": target_url,
                        "explanation": "A short max-age duration limits the long-term effectiveness of HSTS protection.",
                        "recommendation": "Increase max-age to at least 31536000 (1 year) and consider 'includeSubDomains' and 'preload'.",
                    })
                else:
                    findings.append({
                        "id": "SEC-HDR-HSTS-OK",
                        "severity": "Informational",
                        "category": "Security Headers",
                        "title": "Strict-Transport-Security (HSTS) Enabled",
                        "evidence": f"Strict-Transport-Security: {hsts}",
                        "affected_url": target_url,
                        "explanation": "HSTS header is correctly configured with adequate duration.",
                        "recommendation": "Maintain HSTS configuration and verify all subdomains support HTTPS.",
                    })

    # ── 2. Content-Security-Policy (CSP) ───────────────────────────────────────
    csp = lower_headers.get("content-security-policy")
    if not csp:
        findings.append({
            "id": "SEC-HDR-CSP-MISSING",
            "severity": "High",
            "category": "Security Headers",
            "title": "Missing Content-Security-Policy (CSP) Header",
            "evidence": "Content-Security-Policy header was not found in response.",
            "affected_url": target_url,
            "explanation": (
                "Content-Security-Policy is a browser standard that prevents Cross-Site Scripting (XSS), "
                "data injection, and unauthorized resource embedding by whitelisting trusted content sources."
            ),
            "recommendation": "Deploy a restrictive CSP, starting with: default-src 'self'; script-src 'self'; object-src 'none';",
        })
    else:
        # Check for unsafe directives
        has_unsafe_inline = "'unsafe-inline'" in csp.lower()
        has_unsafe_eval = "'unsafe-eval'" in csp.lower()
        if has_unsafe_inline or has_unsafe_eval:
            keywords = []
            if has_unsafe_inline:
                keywords.append("'unsafe-inline'")
            if has_unsafe_eval:
                keywords.append("'unsafe-eval'")
            findings.append({
                "id": "SEC-HDR-CSP-PERMISSIVE",
                "severity": "Medium",
                "category": "Security Headers",
                "title": f"CSP Contains Permissive Directives ({', '.join(keywords)})",
                "evidence": f"Content-Security-Policy: {csp[:120]}...",
                "affected_url": target_url,
                "explanation": (
                    "Using 'unsafe-inline' or 'unsafe-eval' weakens XSS defense by permitting unverified inline "
                    "script execution or dynamic string evaluation."
                ),
                "recommendation": "Refactor scripts to use cryptographic nonces or hashes (e.g. 'nonce-rAnd0m') instead of 'unsafe-inline'.",
            })
        else:
            findings.append({
                "id": "SEC-HDR-CSP-OK",
                "severity": "Informational",
                "category": "Security Headers",
                "title": "Content-Security-Policy (CSP) Deployed",
                "evidence": f"CSP present: {csp[:80]}...",
                "affected_url": target_url,
                "explanation": "Content-Security-Policy header restricts unauthorized resource execution.",
                "recommendation": "Periodically review CSP reports and directives.",
            })

    # ── 3. Clickjacking Protection (X-Frame-Options / frame-ancestors) ─────────
    xfo = lower_headers.get("x-frame-options")
    csp_has_frame_ancestors = csp and "frame-ancestors" in csp.lower()

    if not xfo and not csp_has_frame_ancestors:
        findings.append({
            "id": "SEC-HDR-XFO-MISSING",
            "severity": "Medium",
            "category": "Security Headers",
            "title": "Missing Clickjacking Protection (X-Frame-Options)",
            "evidence": "Neither X-Frame-Options nor CSP frame-ancestors header was provided.",
            "affected_url": target_url,
            "explanation": (
                "Clickjacking attacks trick users into clicking invisible UI elements embedded in an "
                "attacker-controlled iframe overlay."
            ),
            "recommendation": "Configure 'X-Frame-Options: SAMEORIGIN' or 'X-Frame-Options: DENY', or define CSP 'frame-ancestors 'self''.",
        })
    elif xfo:
        if xfo.upper() in ("DENY", "SAMEORIGIN"):
            findings.append({
                "id": "SEC-HDR-XFO-OK",
                "severity": "Informational",
                "category": "Security Headers",
                "title": f"Clickjacking Protection Active (X-Frame-Options: {xfo.upper()})",
                "evidence": f"X-Frame-Options: {xfo}",
                "affected_url": target_url,
                "explanation": "Page embedding is properly restricted to prevent framing abuse.",
                "recommendation": "No action needed.",
            })

    # ── 4. X-Content-Type-Options ──────────────────────────────────────────────
    xcto = lower_headers.get("x-content-type-options")
    if not xcto or "nosniff" not in xcto.lower():
        findings.append({
            "id": "SEC-HDR-XCTO-MISSING",
            "severity": "Medium",
            "category": "Security Headers",
            "title": "Missing X-Content-Type-Options: nosniff Header",
            "evidence": f"X-Content-Type-Options was {repr(xcto) if xcto else 'not present'}.",
            "affected_url": target_url,
            "explanation": (
                "MIME-sniffing allows browsers to execute non-executable files (like user-uploaded images or text) "
                "as HTML/JavaScript if they contain script-like signatures."
            ),
            "recommendation": "Add 'X-Content-Type-Options: nosniff' to all HTTP responses.",
        })
    else:
        findings.append({
            "id": "SEC-HDR-XCTO-OK",
            "severity": "Informational",
            "category": "Security Headers",
            "title": "MIME-Sniffing Protection Active (X-Content-Type-Options: nosniff)",
            "evidence": "X-Content-Type-Options: nosniff",
            "affected_url": target_url,
            "explanation": "Prevents MIME-confusion attacks.",
            "recommendation": "No action needed.",
        })

    # ── 5. Referrer-Policy ─────────────────────────────────────────────────────
    rp = lower_headers.get("referrer-policy")
    if not rp:
        findings.append({
            "id": "SEC-HDR-RP-MISSING",
            "severity": "Low",
            "category": "Security Headers",
            "title": "Missing Referrer-Policy Header",
            "evidence": "Referrer-Policy header was not provided.",
            "affected_url": target_url,
            "explanation": (
                "Without a defined Referrer-Policy, browsers may expose full URL paths containing "
                "sensitive query parameters, session IDs, or tokens to external sites when clicking links."
            ),
            "recommendation": "Configure 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
        })
    else:
        findings.append({
            "id": "SEC-HDR-RP-OK",
            "severity": "Informational",
            "category": "Security Headers",
            "title": f"Referrer-Policy Configured ({rp})",
            "evidence": f"Referrer-Policy: {rp}",
            "affected_url": target_url,
            "explanation": "Outbound link referrer leakage is governed by policy.",
            "recommendation": "No action needed.",
        })

    # ── 6. Permissions-Policy ──────────────────────────────────────────────────
    pp = lower_headers.get("permissions-policy") or lower_headers.get("feature-policy")
    if not pp:
        findings.append({
            "id": "SEC-HDR-PP-MISSING",
            "severity": "Low",
            "category": "Security Headers",
            "title": "Missing Permissions-Policy Header",
            "evidence": "Neither Permissions-Policy nor Feature-Policy header was found.",
            "affected_url": target_url,
            "explanation": (
                "Permissions-Policy allows developers to explicitly restrict browser hardware APIs "
                "(geolocation, microphone, camera, payment) from unauthorized execution."
            ),
            "recommendation": "Specify 'Permissions-Policy: camera=(), microphone=(), geolocation=()' to lock down unused browser features.",
        })

    # ── 7. Information Disclosure (Server & Technology Banners) ────────────────
    server = lower_headers.get("server")
    if server:
        # Check if version numbers or OS signatures are disclosed (e.g. Apache/2.4.41, nginx/1.18.0)
        has_version = bool(re.search(r"[\d\.]+", server))
        if has_version:
            findings.append({
                "id": "INFO-SERVER-VERSION",
                "severity": "Low",
                "category": "Information Disclosure",
                "title": "Web Server Software Version Disclosed",
                "evidence": f"Server: {server}",
                "affected_url": target_url,
                "explanation": (
                    f"The server reveals exact version information ('{server}'). "
                    "This accelerates adversary reconnaissance by pinpointing exact unpatched CVEs."
                ),
                "recommendation": "Disable detailed server banners (e.g., 'ServerTokens Prod' in Apache, 'server_tokens off;' in nginx).",
            })

    x_powered_by = lower_headers.get("x-powered-by")
    if x_powered_by:
        findings.append({
            "id": "INFO-POWERED-BY",
            "severity": "Low",
            "category": "Information Disclosure",
            "title": "Backend Framework/Runtime Disclosed (X-Powered-By)",
            "evidence": f"X-Powered-By: {x_powered_by}",
            "affected_url": target_url,
            "explanation": (
                f"The response exposes backend framework technology ('{x_powered_by}'), "
                "giving attackers insight into the application runtime."
            ),
            "recommendation": "Remove the X-Powered-By header in web server or application middleware (e.g. app.disable('x-powered-by') in Express).",
        })

    # ── 8. Observable Cookies Security Attributes ──────────────────────────────
    if raw_cookies:
        for cookie_str in raw_cookies:
            # Format: 'session_id=abc123; Path=/; Secure; HttpOnly; SameSite=Lax'
            parts = [p.strip() for p in cookie_str.split(";")]
            c_name = parts[0].split("=")[0] if "=" in parts[0] else parts[0]
            c_attrs = [p.lower() for p in parts[1:]]

            has_secure = "secure" in c_attrs
            has_httponly = "httponly" in c_attrs
            has_samesite = any(p.startswith("samesite") for p in c_attrs)

            # Check Secure flag
            if is_https and not has_secure:
                findings.append({
                    "id": f"COOKIE-NOT-SECURE-{c_name.upper()}",
                    "severity": "High",
                    "category": "Cookies",
                    "title": f"Cookie '{c_name}' Missing 'Secure' Attribute",
                    "evidence": f"Set-Cookie: {cookie_str[:100]}...",
                    "affected_url": target_url,
                    "explanation": "Without the 'Secure' flag, the browser will transmit this cookie over unencrypted HTTP channels if requested.",
                    "recommendation": f"Add the 'Secure' attribute to cookie '{c_name}'.",
                })

            # Check HttpOnly flag on session/auth cookies
            is_session_cookie = any(
                kw in c_name.lower()
                for kw in ("sess", "auth", "token", "jwt", "id", "login", "key")
            )
            if not has_httponly and is_session_cookie:
                findings.append({
                    "id": f"COOKIE-NOT-HTTPONLY-{c_name.upper()}",
                    "severity": "Medium",
                    "category": "Cookies",
                    "title": f"Session Cookie '{c_name}' Missing 'HttpOnly' Attribute",
                    "evidence": f"Set-Cookie: {cookie_str[:100]}...",
                    "affected_url": target_url,
                    "explanation": (
                        f"The cookie '{c_name}' appears to hold session state but lacks 'HttpOnly', "
                        "enabling malicious scripts (XSS) to read and steal the cookie via document.cookie."
                    ),
                    "recommendation": f"Ensure cookie '{c_name}' is set with the 'HttpOnly' attribute.",
                })

            # Check SameSite attribute
            if not has_samesite:
                findings.append({
                    "id": f"COOKIE-NO-SAMESITE-{c_name.upper()}",
                    "severity": "Medium",
                    "category": "Cookies",
                    "title": f"Cookie '{c_name}' Missing 'SameSite' Attribute",
                    "evidence": f"Set-Cookie: {cookie_str[:100]}...",
                    "affected_url": target_url,
                    "explanation": (
                        f"Cookie '{c_name}' does not specify SameSite behavior. Without SameSite, "
                        "the cookie may be sent with cross-site requests, increasing Cross-Site Request Forgery (CSRF) risk."
                    ),
                    "recommendation": f"Set 'SameSite=Lax' or 'SameSite=Strict' on cookie '{c_name}'.",
                })

    return findings
