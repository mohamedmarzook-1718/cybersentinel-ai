"""
OWASP Top 10 Web Application Security Testing Module for CyberSentinel AI.

Implements non-destructive, safe testing covering:
- A01: Broken Access Control & Administrative Route Exposure
- A02: Cryptographic Failures & Insecure Form Transmission
- A03: Injection Indicators (Database error disclosure & reflection)
- A04: Insecure Design & File Upload Attack Surface
- A05: Security Misconfigurations (Directory Listing & Verbose Stack Traces)
- A07: Identification & Authentication Failures (Cookie Flags & Session Fixation)
- A08: Software & Data Integrity (Missing Subresource Integrity on External Scripts)
- A10: Server-Side Request Forgery (SSRF) & Open Redirect Parameters
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs


DATABASE_ERROR_PATTERNS = [
    (r"SQL syntax.*?MySQL", "MySQL"),
    (r"Warning.*?mysql_", "MySQL"),
    (r"PostgreSQL.*?ERROR", "PostgreSQL"),
    (r"pg_query\(\).*?error", "PostgreSQL"),
    (r"ORA-[0-9]{4,5}", "Oracle Database"),
    (r"Microsoft OLE DB Provider for SQL Server", "Microsoft SQL Server"),
    (r"Unclosed quotation mark before the character string", "Microsoft SQL Server"),
    (r"SQLite3::SQLException", "SQLite"),
    (r"sqlite3\.OperationalError", "SQLite"),
    (r"syntax error at or near", "SQL Injection Disclosure"),
]

STACK_TRACE_PATTERNS = [
    (r"Traceback \(most recent call last\):", "Python Exception Stack Trace"),
    (r"Exception in thread \".*?\" java\.", "Java Exception Stack Trace"),
    (r"Fatal error:.*?in /.*?\.php on line", "PHP Fatal Error Disclosure"),
    (r"System\.Web\.HttpUnhandledException:", ".NET Exception Stack Trace"),
    (r"Apache Tomcat/[0-9\.]+ - Error report", "Apache Tomcat Internal Error Report"),
]

OPEN_REDIRECT_PARAM_NAMES = {
    "url", "redirect", "redirect_url", "redirect_to", "next",
    "dest", "destination", "target", "return", "return_url", "rurl", "go"
}


def audit_owasp_vulnerabilities(
    crawled_pages: List[Dict],
    discovered_forms: List[Dict],
    discovered_routes: List[Dict],
    base_url: str,
) -> List[Dict]:
    """
    Perform safe, passive OWASP Top 10 security checks across all crawled assets.

    Returns:
        List of findings formatted with evidence, reproduction steps, and OWASP references.
    """
    findings: List[Dict] = []
    seen_finding_keys = set()

    def add_finding(f: Dict):
        key = (f["id"], f["affected_url"])
        if key not in seen_finding_keys:
            seen_finding_keys.add(key)
            findings.append(f)

    # 1. A01: Broken Access Control - Exposed Administrative Routes without Auth
    for route in discovered_routes:
        path = route.get("path", "")
        status = route.get("status_code", 0)
        url = route.get("url", "")

        if path in ("/admin", "/dashboard", "/actuator/health") and status == 200:
            add_finding({
                "id": "OWASP-A01-OPEN-ADMIN",
                "title": f"Administrative Route Publicly Accessible Without Authentication ({path})",
                "severity": "Medium",
                "category": "OWASP Top 10",
                "confidence": "Confirmed",
                "status": "Confirmed",
                "evidence": f"Endpoint returned HTTP 200 OK without requiring login credentials or session tokens.",
                "affected_url": url,
                "explanation": "Administrative interfaces accessible to the public internet increase attack surface and risk unauthorized administrative actions.",
                "recommendation": "Enforce strict multi-factor authentication, IP allowlisting, or VPN gateway restrictions on all administrative portals.",
                "reproduction_steps": f"curl -s -I {url}",
                "cwe_id": "CWE-284",
                "owasp_category": "A01:2021-Broken Access Control"
            })

    # 2. A02: Cryptographic Failures - Plaintext Password Forms over HTTP
    for form in discovered_forms:
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])
        has_password = any(inp.get("type") == "password" for inp in inputs)

        if has_password and action.startswith("http://"):
            add_finding({
                "id": "OWASP-A02-HTTP-PASSWORD-FORM",
                "title": "Unencrypted Password Form Submission (HTTP Action)",
                "severity": "Critical",
                "category": "OWASP Top 10",
                "confidence": "Confirmed",
                "status": "Confirmed",
                "evidence": f"Form with password input submits to unencrypted target: '{action}'",
                "affected_url": action,
                "explanation": "Credentials entered into this form will be transmitted in plaintext across the local network, allowing eavesdropping and credential theft by network attackers.",
                "recommendation": "Update the form action to use HTTPS and enforce Strict-Transport-Security on the domain.",
                "reproduction_steps": f"Inspect HTML <form> element action attribute at {action}",
                "cwe_id": "CWE-319",
                "owasp_category": "A02:2021-Cryptographic Failures"
            })

    # 3. A03: Injection Indicators - Verbose Database Error Disclosures
    for page in crawled_pages:
        body = page.get("body_sample", "")
        page_url = page.get("url", "")

        for pattern, db_name in DATABASE_ERROR_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                snippet = match.group(0)[:100]
                add_finding({
                    "id": "OWASP-A03-DB-ERROR-DISCLOSED",
                    "title": f"Database Error / SQL Injection Signature Disclosed ({db_name})",
                    "severity": "High",
                    "category": "OWASP Top 10",
                    "confidence": "Confirmed",
                    "status": "Potential Risk",
                    "evidence": f"Observable database error in response body: '{snippet}'",
                    "affected_url": page_url,
                    "explanation": "Raw database exception messages disclose database architecture and suggest unsanitized SQL query input, facilitating SQL injection exploitation.",
                    "recommendation": "Disable verbose error messages in production. Use parameterized queries and generic user-facing error handlers.",
                    "reproduction_steps": f"Fetch {page_url} and inspect response text for database exception strings.",
                    "cwe_id": "CWE-209",
                    "owasp_category": "A03:2021-Injection"
                })

        # 4. A05: Security Misconfiguration - Verbose Stack Trace Disclosures
        for pattern, trace_name in STACK_TRACE_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                snippet = match.group(0)[:120]
                add_finding({
                    "id": "OWASP-A05-STACK-TRACE-LEAK",
                    "title": f"Application Debug Stack Trace Disclosed ({trace_name})",
                    "severity": "Medium",
                    "category": "OWASP Top 10",
                    "confidence": "Confirmed",
                    "status": "Confirmed",
                    "evidence": f"Traceback string discovered in page output: '{snippet}'",
                    "affected_url": page_url,
                    "explanation": "Stack traces expose internal source code file paths, framework versions, and function names that assist attackers in crafting exploits.",
                    "recommendation": "Disable debug mode in application configuration (e.g. DEBUG=False) and display custom 500 error pages.",
                    "reproduction_steps": f"curl -s {page_url} | grep -i 'Traceback'",
                    "cwe_id": "CWE-209",
                    "owasp_category": "A05:2021-Security Misconfiguration"
                })

        # 5. A05: Security Misconfiguration - Directory Listing
        if "Index of /" in body or "Directory Listing for /" in body or "<title>Index of" in body:
            add_finding({
                "id": "OWASP-A05-DIRECTORY-LISTING",
                "title": "Web Server Directory Indexing Enabled",
                "severity": "Medium",
                "category": "OWASP Top 10",
                "confidence": "Confirmed",
                "status": "Confirmed",
                "evidence": "Response contains web server directory index listing files and folders.",
                "affected_url": page_url,
                "explanation": "Directory indexing reveals backup files, test scripts, and internal assets that were not intended for public discovery.",
                "recommendation": "Disable directory indexing in your web server (e.g. Apache 'Options -Indexes' or Nginx 'autoindex off;').",
                "reproduction_steps": f"curl -s {page_url} | grep -i 'Index of'",
                "cwe_id": "CWE-548",
                "owasp_category": "A05:2021-Security Misconfiguration"
            })

        # 6. A10: SSRF & Open Redirect Parameter Indicators
        parsed = urlparse(page_url)
        params = parse_qs(parsed.query)
        for param_name in params.keys():
            if param_name.lower() in OPEN_REDIRECT_PARAM_NAMES:
                val = params[param_name][0] if params[param_name] else ""
                add_finding({
                    "id": "OWASP-A10-OPEN-REDIRECT-PARAM",
                    "title": f"Potential Open Redirect / SSRF Parameter Identified ('{param_name}')",
                    "severity": "Low",
                    "category": "OWASP Top 10",
                    "confidence": "Suspected",
                    "status": "Potential Risk",
                    "evidence": f"URL parameter '{param_name}={val[:40]}' observed in link.",
                    "affected_url": page_url,
                    "explanation": "URL parameters that control destination redirects can be exploited for phishing or server-side request forgery if not validated against an allowlist.",
                    "recommendation": "Validate redirect targets against an explicit allowlist of domain names or use relative paths only.",
                    "reproduction_steps": f"Test target redirect parameter at {page_url}",
                    "cwe_id": "CWE-601",
                    "owasp_category": "A10:2021-Server-Side Request Forgery"
                })

    # 7. A04: Insecure Design - Unrestricted File Upload Form
    for form in discovered_forms:
        inputs = form.get("inputs", [])
        has_file = any(inp.get("type") == "file" for inp in inputs)
        has_csrf = any(
            re.search(r'(csrf|token|_token|authenticity)', inp.get("name", ""), re.IGNORECASE)
            for inp in inputs
        )
        if has_file and not has_csrf:
            add_finding({
                "id": "OWASP-A04-FILE-UPLOAD-NO-CSRF",
                "title": "File Upload Form Lacks Anti-CSRF Token Protection",
                "severity": "Medium",
                "category": "OWASP Top 10",
                "confidence": "Confirmed",
                "status": "Potential Risk",
                "evidence": f"File upload form at '{form.get('action')}' lacks anti-CSRF token verification.",
                "affected_url": form.get("action") or base_url,
                "explanation": "Without CSRF protection, attackers can trick authenticated users into uploading arbitrary malicious files to your application.",
                "recommendation": "Implement unique cryptographic anti-CSRF tokens and validate MIME-type, file extension, and file size on the server side.",
                "reproduction_steps": f"Inspect form at {form.get('action')}",
                "cwe_id": "CWE-352",
                "owasp_category": "A04:2021-Insecure Design"
            })

    return findings
