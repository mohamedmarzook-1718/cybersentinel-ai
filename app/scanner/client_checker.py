"""
Client-Side & JavaScript Security Module for CyberSentinel AI.

Implements:
- Secret & Token Scanner with automatic evidence redaction (AWS, GitHub, Google, Stripe, Slack, Private Keys)
- DOM XSS Sink Detection (eval, innerHTML, document.write)
- Insecure Mixed-Content External Script Detection
- JavaScript Source Map (.map) Exposure Auditing
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
import httpx

from app.scanner.ssrf import validate_target_url, SecurityValidationError


SECRET_PATTERNS = [
    (r"(AKIA[0-9A-Z]{16})", "AWS Access Key ID", "High", "CWE-798"),
    (r"(ghp_[a-zA-Z0-9]{36})", "GitHub Personal Access Token", "Critical", "CWE-798"),
    (r"(AIza[0-9A-Za-z\-_]{35})", "Google API Key", "Medium", "CWE-798"),
    (r"(sk_live_[0-9a-zA-Z]{24})", "Stripe Live Secret Key", "Critical", "CWE-798"),
    (r"(xox[baprs]-[0-9a-zA-Z]{10,48})", "Slack Bot / User Token", "High", "CWE-798"),
    (r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)", "Private RSA/EC Cryptographic Key", "Critical", "CWE-312"),
    (r"(eyJ[a-zA-Z0-9_\-]{15,}\.eyJ[a-zA-Z0-9_\-]{15,}\.[a-zA-Z0-9_\-]+)", "Hardcoded JWT Token", "Medium", "CWE-798"),
    (r"((postgres|mysql|mongodb)://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9_\-\.]+)", "Hardcoded Database Connection URI", "Critical", "CWE-312"),
]

DOM_XSS_SINKS = [
    (r"\beval\(", "eval() execution"),
    (r"\.innerHTML\s*=", "innerHTML property assignment"),
    (r"document\.write\(", "document.write() direct DOM injection"),
    (r"\.outerHTML\s*=", "outerHTML assignment"),
    (r"setTimeout\s*\(\s*['\"][^'\"]+['\"]", "setTimeout() string execution"),
]


def redact_secret(secret_str: str) -> str:
    """Mask the middle of a secret to prevent exposing credentials in reports."""
    s = secret_str.strip()
    if len(s) <= 8:
        return "****"
    prefix = s[:4]
    suffix = s[-4:]
    return f"{prefix}{'*' * (len(s) - 8)}{suffix}"


class ClientSideAuditor:
    """Audits client-side scripts for secret leaks, DOM XSS sinks, and source map exposure."""

    def __init__(self, base_url: str, timeout: float = 5.0):
        self.base_url = base_url
        self.timeout = timeout

    def audit_client_security(
        self,
        crawled_pages: List[Dict],
        discovered_scripts: List[str],
    ) -> List[Dict]:
        """
        Scan page HTML and crawled JavaScript assets for client-side vulnerabilities.

        Returns:
            List of findings with redacted evidence.
        """
        findings: List[Dict] = []
        seen_keys = set()

        def add_finding(f: Dict):
            key = (f["id"], f["affected_url"])
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append(f)

        headers = {
            "User-Agent": "CyberSentinel-SecurityScanner/2.0 (+https://cybersentinel.ai/bot; passive-audit)",
            "Accept": "*/*",
        }

        # 1. Scan crawled HTML bodies for inline secrets and DOM sinks
        for page in crawled_pages:
            body = page.get("body_sample", "")
            page_url = page.get("url", "")

            # Check secrets in HTML
            for pattern, name, sev, cwe in SECRET_PATTERNS:
                for match in re.finditer(pattern, body):
                    raw_secret = match.group(1)
                    redacted = redact_secret(raw_secret)
                    add_finding({
                        "id": f"CLIENT-SECRET-{name.replace(' ', '-').upper()}",
                        "title": f"Accidentally Exposed {name} in Client Page",
                        "severity": sev,
                        "category": "Client-Side",
                        "confidence": "Confirmed",
                        "status": "Confirmed",
                        "evidence": f"Pattern matched in page source: {redacted}",
                        "affected_url": page_url,
                        "explanation": f"Public exposure of {name} in client-side HTML allows unauthorized third parties to authenticate against cloud services with organizational privileges.",
                        "recommendation": f"Immediately rotate the exposed {name}. Remove credentials from frontend code and migrate secrets to backend environment variables.",
                        "reproduction_steps": f"Inspect page source at {page_url} for credential string.",
                        "cwe_id": cwe,
                        "owasp_category": "A05:2021-Security Misconfiguration"
                    })

            # Check DOM XSS sinks in HTML
            for pattern, sink_desc in DOM_XSS_SINKS:
                match = re.search(pattern, body)
                if match:
                    snippet = match.group(0)[:60]
                    add_finding({
                        "id": "CLIENT-DOM-XSS-SINK",
                        "title": f"Dangerous Client-Side DOM XSS Sink Detected ({sink_desc})",
                        "severity": "Low",
                        "category": "Client-Side",
                        "confidence": "Suspected",
                        "status": "Potential Risk",
                        "evidence": f"Observable DOM sink pattern: '{snippet}'",
                        "affected_url": page_url,
                        "explanation": f"Using {sink_desc} with unvalidated user input or URL hashes can lead to client-side DOM Cross-Site Scripting.",
                        "recommendation": "Use safe DOM APIs such as 'textContent', 'setAttribute', or framework-provided sanitization instead of direct innerHTML or eval.",
                        "reproduction_steps": f"Search script tags at {page_url} for '{snippet}'",
                        "cwe_id": "CWE-79",
                        "owasp_category": "A03:2021-Injection"
                    })

        # 2. Inspect external script URLs for mixed content and source maps
        is_https_origin = self.base_url.lower().startswith("https://")

        with httpx.Client(
            verify=False,
            timeout=self.timeout,
            headers=headers,
            follow_redirects=True,
        ) as client:
            # Audit top 10 discovered scripts
            for script_url in discovered_scripts[:10]:
                # Mixed content check
                if is_https_origin and script_url.lower().startswith("http://"):
                    add_finding({
                        "id": "CLIENT-INSECURE-SCRIPT-HTTP",
                        "title": "Insecure Script Resource Loaded over Plain HTTP (Mixed Content)",
                        "severity": "High",
                        "category": "Client-Side",
                        "confidence": "Confirmed",
                        "status": "Confirmed",
                        "evidence": f"Script source uses unencrypted HTTP: '{script_url}'",
                        "affected_url": script_url,
                        "explanation": "Loading executable scripts over unencrypted HTTP permits Man-in-the-Middle (MitM) attackers to modify script contents and execute malicious code in user browsers.",
                        "recommendation": "Update the script src to HTTPS or host the script on your own origin.",
                        "reproduction_steps": f"Check <script src='{script_url}'> in page source.",
                        "cwe_id": "CWE-311",
                        "owasp_category": "A02:2021-Cryptographic Failures"
                    })

                # Source map exposure check
                map_url = f"{script_url}.map"
                try:
                    validate_target_url(map_url)
                    res = client.head(map_url)
                    if res.status_code == 200 and "json" in res.headers.get("content-type", ""):
                        add_finding({
                            "id": "CLIENT-SOURCEMAP-EXPOSED",
                            "title": "Publicly Accessible JavaScript Source Map (.map)",
                            "severity": "Low",
                            "category": "Client-Side",
                            "confidence": "Confirmed",
                            "status": "Confirmed",
                            "evidence": f"Source map returned HTTP 200: '{map_url}'",
                            "affected_url": map_url,
                            "explanation": "Source maps recreate unminified original source code including developer comments, internal variable names, and hidden API endpoints.",
                            "recommendation": "Do not deploy .map files to public production web servers or configure web server rules to deny access to *.map files.",
                            "reproduction_steps": f"curl -s -I {map_url}",
                            "cwe_id": "CWE-540",
                            "owasp_category": "A05:2021-Security Misconfiguration"
                        })
                except Exception:
                    pass

        return findings
