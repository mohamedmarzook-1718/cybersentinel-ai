"""
CyberSentinel Web Security Scanner Orchestration Engine.

Orchestrates multi-layer website security intelligence:
- SSRF prevention & target validation
- TLS/SSL cryptographic inspection
- Full-Website controlled crawling with same-origin scope enforcement
- Attack surface & DNS discovery (A, AAAA, MX, TXT, SPF, DMARC, subdomains)
- Technology fingerprinting (Server, Framework, CMS, Frontend)
- OWASP Top 10 web security auditing
- Client-side secret scanning with automatic credential redaction & DOM sink detection
- API security auditing (OpenAPI specs, CORS with credentials, HTTP methods)
- Threat intelligence & CVE database cross-checking
- Transparent evidence-based composite scoring (0-100) and prioritized remediation checklist
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import httpx

from app.scanner.ssrf import validate_target_url, SecurityValidationError
from app.scanner.tls_checker import inspect_tls
from app.scanner.headers_checker import audit_headers_and_cookies
from app.scanner.crawler import WebsiteCrawler
from app.scanner.discovery import AttackSurfaceDiscovery
from app.scanner.owasp_checker import audit_owasp_vulnerabilities
from app.scanner.client_checker import ClientSideAuditor
from app.scanner.api_checker import ApiSecurityAuditor
from app.scanner.threat_intel import ThreatIntelligenceAuditor


class WebSecurityScanner:
    """Comprehensive, multi-layer website security intelligence platform engine."""

    def __init__(self, timeout: float = 6.0, max_redirects: int = 5):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.user_agent = (
            "CyberSentinel-SecurityScanner/2.0 (+https://cybersentinel.ai/scanner; "
            "Defensive Posture & Attack Surface Audit)"
        )

    def scan(
        self,
        target_url: str,
        profile: str = "standard",
        allowed_domains: Optional[List[str]] = None,
        excluded_paths: Optional[List[str]] = None,
        max_crawl_pages: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Execute full multi-layer security assessment against target website.
        """
        started_at = datetime.now(timezone.utc)
        clean_profile = (profile or "standard").lower()
        if clean_profile not in ("passive", "quick", "standard", "comprehensive"):
            clean_profile = "standard"

        # 1. SSRF Validation
        try:
            normalized_url, hostname, resolved_ip = validate_target_url(target_url)
        except SecurityValidationError as e:
            completed_at = datetime.now(timezone.utc)
            return {
                "url": target_url,
                "target_host": target_url,
                "target_ip": None,
                "scan_status": "failed",
                "score": 0,
                "risk_level": "Critical",
                "profile": clean_profile,
                "http_status": None,
                "response_time_ms": 0.0,
                "tls_version": None,
                "cert_valid": False,
                "cert_issuer": None,
                "cert_expires_at": None,
                "findings": [{
                    "id": "SEC-SSRF-BLOCKED",
                    "severity": "Critical",
                    "category": "Attack Surface",
                    "confidence": "Confirmed",
                    "status": "Confirmed",
                    "title": "Target Blocked by SSRF Safety Guardrails",
                    "evidence": str(e),
                    "affected_url": target_url,
                    "explanation": "Requests to private, loopback, link-local, or cloud metadata addresses are prohibited to prevent Server-Side Request Forgery.",
                    "recommendation": "Specify a publicly accessible internet domain or authorized IP address.",
                    "reproduction_steps": f"Verify DNS resolution: nslookup {target_url}",
                    "cwe_id": "CWE-918",
                    "owasp_category": "A10:2021-Server-Side Request Forgery",
                }],
                "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0, "informational": 0, "total": 1},
                "headers": {},
                "attack_surface": {},
                "remediation_checklist": [],
                "limitations": ["Scan aborted: Target violated SSRF protection policies."],
                "pages_crawled": 0,
                "pages_discovered": 0,
                "error_message": str(e),
                "started_at": started_at,
                "completed_at": completed_at,
            }

        parsed = urlparse(normalized_url)
        is_https = parsed.scheme == "https"
        port = parsed.port or (443 if is_https else 80)

        all_findings: List[Dict[str, Any]] = []
        tls_meta: Dict[str, Any] = {
            "tls_version": None,
            "cert_valid": None,
            "cert_issuer": None,
            "cert_expires_at": None,
        }

        # 2. TLS/SSL Inspection
        if is_https or port == 443:
            t_meta, t_findings = inspect_tls(hostname, port, timeout=self.timeout)
            tls_meta.update(t_meta)
            for f in t_findings:
                f["category"] = "Infrastructure"
                f["confidence"] = "Confirmed"
                f["status"] = "Confirmed"
                all_findings.append(f)
        else:
            all_findings.append({
                "id": "TLS-CLEARTEXT-HTTP",
                "severity": "High",
                "category": "Infrastructure",
                "confidence": "Confirmed",
                "status": "Confirmed",
                "title": "Unencrypted HTTP Protocol (Cleartext Transmission)",
                "evidence": f"Target communicates over unencrypted {normalized_url}",
                "affected_url": normalized_url,
                "explanation": "Unencrypted HTTP connections expose all request/response data, authentication cookies, and sensitive payload data to eavesdropping or alteration on public Wi-Fi or transit networks.",
                "recommendation": "Obtain an SSL/TLS certificate (e.g., from Let's Encrypt) and redirect all HTTP traffic to HTTPS.",
                "reproduction_steps": f"curl -s -I {normalized_url}",
                "cwe_id": "CWE-319",
                "owasp_category": "A02:2021-Cryptographic Failures",
            })

        # 3. Root HTTP Request & Headers Audit
        http_status = None
        latency_ms = 0.0
        root_headers: Dict[str, str] = {}
        root_body = ""

        try:
            req_headers = {"User-Agent": self.user_agent, "Accept": "text/html,*/*"}
            with httpx.Client(
                verify=False,
                timeout=self.timeout,
                headers=req_headers,
                follow_redirects=True,
                max_redirects=self.max_redirects,
            ) as client:
                t0 = time.perf_counter()
                res = client.get(normalized_url)
                latency_ms = round((time.perf_counter() - t0) * 1000, 2)
                http_status = res.status_code
                root_headers = dict(res.headers)
                root_body = res.text[:100000]

                # Audits security headers & cookie hardening
                hdr_findings = audit_headers_and_cookies(
                    dict(res.headers),
                    res.cookies,
                    is_https=is_https,
                    target_url=str(res.url),
                )
                for f in hdr_findings:
                    f["category"] = "Infrastructure"
                    f["confidence"] = "Confirmed"
                    f["status"] = "Confirmed"
                    all_findings.append(f)

        except Exception as e:
            all_findings.append({
                "id": "HTTP-AVAILABILITY-ERROR",
                "severity": "Medium",
                "category": "Availability",
                "confidence": "Confirmed",
                "status": "Confirmed",
                "title": "Target Website Request Failed or Timed Out",
                "evidence": f"Connection error: {str(e)}",
                "affected_url": normalized_url,
                "explanation": "The target website was unreachable or failed to respond within the configured timeout period.",
                "recommendation": "Verify web server status, network routing, and firewall/DDoS protection configurations.",
                "reproduction_steps": f"curl -s -I {normalized_url}",
                "cwe_id": "CWE-400",
                "owasp_category": "A05:2021-Security Misconfiguration",
            })

        # 4. Website Crawling (Respects profile budget)
        crawler = WebsiteCrawler(
            base_url=normalized_url,
            profile=clean_profile,
            allowed_domains=allowed_domains,
            excluded_paths=excluded_paths,
            max_pages=max_crawl_pages,
            timeout=self.timeout,
        )
        crawl_results = crawler.crawl()
        crawled_pages = crawl_results["crawled_pages"]
        discovered_urls = crawl_results["discovered_urls"]
        discovered_scripts = crawl_results["discovered_scripts"]
        discovered_forms = crawl_results["discovered_forms"]
        discovered_apis = crawl_results["discovered_apis"]
        third_party_resources = crawl_results["third_party_resources"]

        # 5. Attack Surface & DNS Discovery
        discovery = AttackSurfaceDiscovery(base_url=normalized_url, timeout=self.timeout)
        dns_records, dns_findings = discovery.audit_dns()
        all_findings.extend(dns_findings)

        discovered_subdomains = []
        if clean_profile in ("standard", "comprehensive"):
            discovered_subdomains = discovery.discover_subdomains()

        discovered_routes, route_findings = discovery.probe_routes()
        all_findings.extend(route_findings)

        technologies = discovery.fingerprint_technologies(root_headers, root_body)

        # 6. OWASP Top 10 Web Testing
        owasp_findings = audit_owasp_vulnerabilities(
            crawled_pages=crawled_pages,
            discovered_forms=discovered_forms,
            discovered_routes=discovered_routes,
            base_url=normalized_url,
        )
        all_findings.extend(owasp_findings)

        # 7. Client-Side & JavaScript Security
        client_auditor = ClientSideAuditor(base_url=normalized_url, timeout=self.timeout)
        client_findings = client_auditor.audit_client_security(
            crawled_pages=crawled_pages,
            discovered_scripts=discovered_scripts,
        )
        all_findings.extend(client_findings)

        # 8. API Security Assessment
        api_auditor = ApiSecurityAuditor(base_url=normalized_url, timeout=self.timeout)
        all_apis, api_findings = api_auditor.audit_api(
            discovered_apis=discovered_apis,
            discovered_routes=discovered_routes,
        )
        all_findings.extend(api_findings)

        # 9. Threat Intelligence & CVE Database Matching
        threat_auditor = ThreatIntelligenceAuditor(base_url=normalized_url)
        threat_findings, assessment_limitations = threat_auditor.audit_threat_intel(
            technologies=technologies,
            crawled_pages=crawled_pages,
        )
        all_findings.extend(threat_findings)

        # 10. Deduplication & Normalization
        deduped_findings: List[Dict[str, Any]] = []
        seen_keys = set()
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0, "total": 0}

        for f in all_findings:
            key = (f["id"], f["affected_url"])
            if key in seen_keys:
                continue
            seen_keys.add(key)

            # Ensure all required schema fields are populated
            f.setdefault("confidence", "Confirmed")
            f.setdefault("status", "Confirmed")
            f.setdefault("reproduction_steps", f"Inspect response from {f['affected_url']}")
            f.setdefault("cve_id", None)
            f.setdefault("cwe_id", "CWE-693")
            f.setdefault("owasp_category", "A05:2021-Security Misconfiguration")

            sev_key = f["severity"].lower()
            if sev_key in summary:
                summary[sev_key] += 1
            else:
                summary["informational"] += 1
            summary["total"] += 1
            deduped_findings.append(f)

        # 11. Score Calculation (Evidence-based 0-100)
        score = 100
        score -= summary["critical"] * 25
        score -= summary["high"] * 15
        score -= summary["medium"] * 8
        score -= summary["low"] * 3
        score = max(0, min(100, score))

        if summary["critical"] > 0:
            risk_level = "Critical"
        elif summary["high"] > 0 or score < 60:
            risk_level = "High"
        elif summary["medium"] > 0 or score < 80:
            risk_level = "Medium"
        elif summary["low"] > 0 or score < 95:
            risk_level = "Low"
        else:
            risk_level = "Informational"

        # 12. Prioritized Remediation Checklist
        remediation_checklist = self._generate_remediation_checklist(deduped_findings)

        # 13. Attack Surface Data
        attack_surface = {
            "dns_records": dns_records,
            "subdomains": discovered_subdomains,
            "discovered_routes": discovered_routes,
            "api_endpoints": all_apis,
            "technologies": technologies,
            "third_party_resources": third_party_resources,
            "crawled_pages": [
                {"url": p["url"], "status": p["status_code"], "title": p["title"]}
                for p in crawled_pages
            ],
            "discovered_pages_count": len(discovered_urls),
            "crawled_pages_count": len(crawled_pages),
            "robots_disallow": crawl_results.get("robots_disallow", []),
        }

        completed_at = datetime.now(timezone.utc)

        return {
            "url": normalized_url,
            "target_host": hostname,
            "target_ip": resolved_ip,
            "scan_status": "completed",
            "score": score,
            "risk_level": risk_level,
            "profile": clean_profile,
            "http_status": http_status,
            "response_time_ms": latency_ms,
            "tls_version": tls_meta.get("tls_version"),
            "cert_valid": tls_meta.get("cert_valid"),
            "cert_issuer": tls_meta.get("cert_issuer"),
            "cert_expires_at": tls_meta.get("cert_expires_at"),
            "findings": deduped_findings,
            "summary": summary,
            "headers": root_headers,
            "attack_surface": attack_surface,
            "remediation_checklist": remediation_checklist,
            "limitations": assessment_limitations,
            "pages_crawled": len(crawled_pages),
            "pages_discovered": len(discovered_urls),
            "error_message": None,
            "started_at": started_at,
            "completed_at": completed_at,
        }

    def _generate_remediation_checklist(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Group and prioritize findings into an actionable remediation plan."""
        checklist: List[Dict[str, Any]] = []
        priority_map = {
            "Critical": "Immediate",
            "High": "High Priority",
            "Medium": "Medium Priority",
            "Low": "Routine",
            "Informational": "Best Practice",
        }

        grouped_by_title: Dict[str, Dict] = {}
        for f in findings:
            title = f["title"]
            if title not in grouped_by_title:
                grouped_by_title[title] = {
                    "priority": priority_map.get(f["severity"], "Routine"),
                    "title": title,
                    "description": f["recommendation"],
                    "affected_assets": [f["affected_url"]],
                    "effort": "Low" if f["category"] == "Infrastructure" else "Medium",
                }
            else:
                grouped_by_title[title]["affected_assets"].append(f["affected_url"])

        # Order by priority
        order = ["Immediate", "High Priority", "Medium Priority", "Routine", "Best Practice"]
        for p in order:
            for item in grouped_by_title.values():
                if item["priority"] == p:
                    checklist.append(item)

        return checklist


scanner_instance = WebSecurityScanner()
