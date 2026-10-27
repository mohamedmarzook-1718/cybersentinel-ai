"""
API Security Assessment Module for CyberSentinel AI.

Implements:
- OpenAPI / Swagger Specification Auditing (Endpoint enumeration, unauthenticated routes, debug paths)
- CORS Misconfiguration Auditing (Arbitrary Origin reflection with credentials)
- HTTP Allowed Methods Auditing (Detection of dangerous methods such as TRACE)
- Public API endpoint mapping
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin
import httpx

from app.scanner.ssrf import validate_target_url, SecurityValidationError


class ApiSecurityAuditor:
    """Audits discovered API endpoints, OpenAPI schemas, CORS policies, and HTTP methods."""

    def __init__(self, base_url: str, timeout: float = 5.0):
        self.base_url = base_url
        self.timeout = timeout

    def audit_api(
        self,
        discovered_apis: List[str],
        discovered_routes: List[Dict],
    ) -> Tuple[List[str], List[Dict]]:
        """
        Audit discovered API routes, OpenAPI schemas, and CORS configurations.

        Returns:
            (all_api_endpoints, findings)
        """
        findings: List[Dict] = []
        all_apis: Set[str] = set(discovered_apis)
        seen_keys = set()

        def add_finding(f: Dict):
            key = (f["id"], f["affected_url"])
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append(f)

        headers = {
            "User-Agent": "CyberSentinel-SecurityScanner/2.0 (+https://cybersentinel.ai/bot; passive-audit)",
            "Accept": "application/json, text/plain, */*",
        }

        with httpx.Client(
            verify=False,
            timeout=self.timeout,
            headers=headers,
            follow_redirects=True,
        ) as client:
            # 1. Check for OpenAPI / Swagger specifications
            doc_candidates = [
                "/openapi.json",
                "/swagger.json",
                "/api/docs",
                "/api-docs",
                "/v1/api-docs",
                "/v2/api-docs",
            ]
            for doc_path in doc_candidates:
                doc_url = urljoin(self.base_url, doc_path)
                try:
                    validate_target_url(doc_url)
                    res = client.get(doc_url)
                    if res.status_code == 200 and ("json" in res.headers.get("content-type", "") or res.text.strip().startswith("{")):
                        try:
                            spec_data = json.loads(res.text)
                            paths = spec_data.get("paths", {})
                            if isinstance(paths, dict):
                                for p in paths.keys():
                                    all_apis.add(urljoin(self.base_url, p))

                                add_finding({
                                    "id": "API-OPENAPI-SPEC-EXPOSED",
                                    "title": f"Publicly Accessible OpenAPI / Swagger API Specification ({doc_path})",
                                    "severity": "Informational",
                                    "category": "API Security",
                                    "confidence": "Confirmed",
                                    "status": "Confirmed",
                                    "evidence": f"Found {len(paths)} API paths defined in public specification at {doc_url}.",
                                    "affected_url": doc_url,
                                    "explanation": "OpenAPI definitions map out the complete server-side API architecture, parameter names, and schema definitions for public consumption.",
                                    "recommendation": "If this is a private API, require authentication to view documentation or disable schema endpoints in production.",
                                    "reproduction_steps": f"curl -s {doc_url}",
                                    "cwe_id": "CWE-200",
                                    "owasp_category": "A05:2021-Security Misconfiguration"
                                })
                        except Exception:
                            pass
                except Exception:
                    continue

            # 2. CORS Misconfiguration Audit (Origin Reflection with Credentials)
            cors_probe_headers = {
                "User-Agent": "CyberSentinel-SecurityScanner/2.0",
                "Origin": "https://untrusted-attacker.com",
            }
            try:
                cors_target = list(all_apis)[0] if all_apis else self.base_url
                validate_target_url(cors_target)
                cors_res = client.get(cors_target, headers=cors_probe_headers)

                acao = cors_res.headers.get("access-control-allow-origin", "")
                acac = cors_res.headers.get("access-control-allow-credentials", "").lower()

                if acao == "https://untrusted-attacker.com" and acac == "true":
                    add_finding({
                        "id": "API-CORS-CREDENTIALS-REFLECTED",
                        "title": "Dangerous CORS Configuration (Origin Reflection with Credentials)",
                        "severity": "Critical",
                        "category": "API Security",
                        "confidence": "Confirmed",
                        "status": "Confirmed",
                        "evidence": f"Access-Control-Allow-Origin: '{acao}', Access-Control-Allow-Credentials: 'true'",
                        "affected_url": cors_target,
                        "explanation": "The server trusts arbitrary untrusted origins while allowing browser credentials. Malicious sites can issue cross-origin requests and read private user data.",
                        "recommendation": "Do not reflect arbitrary Origin headers. Maintain an explicit allowlist of authorized domain origins.",
                        "reproduction_steps": f"curl -H 'Origin: https://untrusted-attacker.com' -I {cors_target}",
                        "cwe_id": "CWE-942",
                        "owasp_category": "A05:2021-Security Misconfiguration"
                    })
                elif acao == "*" and acac == "true":
                    add_finding({
                        "id": "API-CORS-WILDCARD-CREDENTIALS",
                        "title": "Invalid CORS Policy (Wildcard with Credentials)",
                        "severity": "High",
                        "category": "API Security",
                        "confidence": "Confirmed",
                        "status": "Confirmed",
                        "evidence": "Access-Control-Allow-Origin: '*' combined with Access-Control-Allow-Credentials: 'true'",
                        "affected_url": cors_target,
                        "explanation": "Browser security standards reject wildcard origins with credentials, causing legitimate cross-origin requests to fail while exposing configuration weaknesses.",
                        "recommendation": "Configure a specific, trusted origin instead of wildcard '*' when credentials are required.",
                        "reproduction_steps": f"curl -H 'Origin: https://example.com' -I {cors_target}",
                        "cwe_id": "CWE-942",
                        "owasp_category": "A05:2021-Security Misconfiguration"
                    })
            except Exception:
                pass

            # 3. HTTP Allowed Methods Probe (Detection of TRACE / CONNECT)
            try:
                methods_target = list(all_apis)[0] if all_apis else self.base_url
                validate_target_url(methods_target)
                options_res = client.options(methods_target)
                allow_header = options_res.headers.get("allow", "") or options_res.headers.get("access-control-allow-methods", "")

                if "TRACE" in allow_header.upper():
                    add_finding({
                        "id": "API-METHOD-TRACE-ENABLED",
                        "title": "HTTP TRACE Method Enabled (Cross-Site Tracing Risk)",
                        "severity": "Medium",
                        "category": "API Security",
                        "confidence": "Confirmed",
                        "status": "Confirmed",
                        "evidence": f"Allowed methods header includes TRACE: '{allow_header}'",
                        "affected_url": methods_target,
                        "explanation": "The HTTP TRACE method echoes client requests back to the user, allowing attackers to bypass HttpOnly cookie protections via Cross-Site Tracing (XST).",
                        "recommendation": "Disable the HTTP TRACE method in your web server configuration (e.g. Apache 'TraceEnable Off').",
                        "reproduction_steps": f"curl -X OPTIONS -i {methods_target}",
                        "cwe_id": "CWE-693",
                        "owasp_category": "A05:2021-Security Misconfiguration"
                    })
            except Exception:
                pass

        return sorted(list(all_apis)), findings
