"""
Comprehensive Automated Test Suite for CyberSentinel Web Security Scanner.

Covers:
- SSRF prevention (localhost, private IP ranges, cloud metadata, invalid schemes)
- Header auditing (HSTS, CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy)
- Cookie security attributes (Secure, HttpOnly, SameSite)
- Information disclosure (Server banner, X-Powered-By)
- REST API endpoints: POST /api/scans, GET /api/scans, GET /api/scans/{id}, export CSV/JSON, compare
- Database persistence and audit logging
"""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.scanner.ssrf import validate_target_url, SecurityValidationError
from app.scanner.headers_checker import audit_headers_and_cookies
from app.scanner.engine import WebSecurityScanner
from app.database import SessionLocal
from app.models.scan import WebScan

client = TestClient(app)
 
 
@pytest.fixture(scope="session", autouse=True)
def setup_scanner_suite():
    """Ensure DB tables exist and demo users are present."""
    from app.database import init_db, SessionLocal
    from app.routers.auth import seed_demo_users_internal
    init_db()
    with SessionLocal() as db:
        seed_demo_users_internal(db)


# ── SECTION 1: SSRF AND URL SAFETY VALIDATION ────────────────────────────────

def test_ssrf_blocks_localhost():
    """Verify that localhost and loopback hostnames are blocked immediately."""
    with pytest.raises(SecurityValidationError) as exc:
        validate_target_url("http://localhost")
    assert "prohibited" in str(exc.value).lower()

    with pytest.raises(SecurityValidationError) as exc:
        validate_target_url("http://127.0.0.1:8080")
    assert "private" in str(exc.value).lower() or "prohibited" in str(exc.value).lower()


def test_ssrf_blocks_private_subnets():
    """Verify that RFC 1918 private subnets are blocked."""
    private_targets = [
        "http://10.0.0.1",
        "http://192.168.1.254",
        "http://172.16.0.5",
        "http://172.31.255.255",
    ]
    for url in private_targets:
        with pytest.raises(SecurityValidationError) as exc:
            validate_target_url(url)
        assert "private" in str(exc.value).lower() or "reserved" in str(exc.value).lower()


def test_ssrf_blocks_cloud_metadata():
    """Verify that cloud metadata IPs (AWS, GCP, Azure 169.254.169.254) are rejected."""
    with pytest.raises(SecurityValidationError) as exc:
        validate_target_url("http://169.254.169.254/latest/meta-data/")
    assert "metadata" in str(exc.value).lower() or "link_local" in str(exc.value).lower() or "prohibited" in str(exc.value).lower()


def test_ssrf_rejects_invalid_schemes():
    """Verify non-HTTP schemes are rejected."""
    invalid_urls = [
        "ftp://example.com/file.txt",
        "file:///etc/passwd",
        "gopher://example.com",
        "ldap://example.com",
    ]
    for url in invalid_urls:
        with pytest.raises(SecurityValidationError) as exc:
            validate_target_url(url)
        assert "unsupported" in str(exc.value).lower() or "invalid scheme" in str(exc.value).lower()


def test_ssrf_rejects_credentials_in_url():
    """Verify URLs with embedded credentials are prohibited."""
    with pytest.raises(SecurityValidationError) as exc:
        validate_target_url("https://admin:secret@example.com")
    assert "credentials" in str(exc.value).lower()


# ── SECTION 2: PASSIVE SECURITY AUDITING ENGINE ──────────────────────────────

def test_headers_audit_detects_missing_protections():
    """Verify detection of missing HSTS, CSP, XFO, XCTO, and Referrer-Policy."""
    empty_headers = {
        "content-type": "text/html",
        "content-length": "1024",
    }
    findings = audit_headers_and_cookies(empty_headers, [], "https://example.com", is_https=True)
    finding_ids = [f["id"] for f in findings]

    assert "SEC-HDR-HSTS-MISSING" in finding_ids
    assert "SEC-HDR-CSP-MISSING" in finding_ids
    assert "SEC-HDR-XFO-MISSING" in finding_ids
    assert "SEC-HDR-XCTO-MISSING" in finding_ids
    assert "SEC-HDR-RP-MISSING" in finding_ids


def test_headers_audit_detects_unsafe_directives():
    """Verify detection of permissive CSP directives ('unsafe-inline')."""
    permissive_headers = {
        "content-type": "text/html",
        "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval';",
        "strict-transport-security": "max-age=300",  # short
        "x-frame-options": "SAMEORIGIN",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
    }
    findings = audit_headers_and_cookies(permissive_headers, [], "https://example.com", is_https=True)
    finding_ids = [f["id"] for f in findings]

    assert "SEC-HDR-CSP-PERMISSIVE" in finding_ids
    assert "SEC-HDR-HSTS-SHORT" in finding_ids
    assert "SEC-HDR-XFO-OK" in finding_ids
    assert "SEC-HDR-XCTO-OK" in finding_ids


def test_info_disclosure_detection():
    """Verify detection of server software versions and technology banners."""
    disclosure_headers = {
        "server": "Apache/2.4.41 (Ubuntu)",
        "x-powered-by": "PHP/7.4.3",
    }
    findings = audit_headers_and_cookies(disclosure_headers, [], "https://example.com")
    finding_ids = [f["id"] for f in findings]

    assert "INFO-SERVER-VERSION" in finding_ids
    assert "INFO-POWERED-BY" in finding_ids
    apache_finding = next(f for f in findings if f["id"] == "INFO-SERVER-VERSION")
    assert "Apache/2.4.41" in apache_finding["evidence"]


def test_cookie_security_audit():
    """Verify detection of missing Secure, HttpOnly, and SameSite attributes."""
    cookies = [
        "session_id=abc123xyz; Path=/; Domain=example.com",  # Missing Secure, HttpOnly, SameSite
        "tracking=1; Path=/; Secure; SameSite=Lax",         # Non-session, missing HttpOnly is fine
    ]
    findings = audit_headers_and_cookies({}, cookies, "https://example.com", is_https=True)
    finding_ids = [f["id"] for f in findings]

    assert any("COOKIE-NOT-SECURE" in fid for fid in finding_ids)
    assert any("COOKIE-NOT-HTTPONLY" in fid for fid in finding_ids)
    assert any("COOKIE-NO-SAMESITE" in fid for fid in finding_ids)


# ── SECTION 3: REST API & DATABASE INTEGRATION ───────────────────────────────

def test_api_scan_ssrf_blocked():
    """Verify POST /api/scans blocks internal IP targets and records SSRF finding."""
    res = client.post("/api/scans", json={"url": "http://127.0.0.1"})
    assert res.status_code == 201
    data = res.json()
    assert data["scan_status"] == "failed"
    assert data["risk_level"] == "Critical"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["id"] == "SEC-SSRF-BLOCKED"


def test_api_scan_public_target_or_mock():
    """Verify POST /api/scans completes, calculates score, and saves to database."""
    # Test with standard RFC 2606 reserved public domain example.com
    res = client.post("/api/scans", json={"url": "https://example.com"})
    assert res.status_code == 201
    data = res.json()
    assert data["id"] > 0
    assert data["target_host"] == "example.com"
    assert data["score"] >= 0 and data["score"] <= 100
    assert data["risk_level"] in ("Critical", "High", "Medium", "Low", "Informational")
    assert "findings" in data
    assert "summary" in data
    assert data["summary"]["total"] == len(data["findings"])

    # Verify scan is in database
    with SessionLocal() as db:
        scan_record = db.query(WebScan).filter(WebScan.id == data["id"]).first()
        assert scan_record is not None
        assert scan_record.url == "https://example.com/"


def test_api_list_scans_and_pagination():
    """Verify GET /api/scans returns paginated scan history."""
    res = client.get("/api/scans?page=1&page_size=10")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert data["total"] >= 1
    assert len(data["items"]) >= 1
    assert data["items"][0]["url"] is not None


def test_api_get_scan_detail():
    """Verify GET /api/scans/{id} retrieves full findings."""
    # First get list to find an ID
    list_res = client.get("/api/scans?page_size=1").json()
    assert len(list_res["items"]) > 0
    scan_id = list_res["items"][0]["id"]

    res = client.get(f"/api/scans/{scan_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == scan_id
    assert isinstance(data["findings"], list)


def test_api_export_csv_and_json():
    """Verify GET /api/scans/{id}/export downloads valid CSV and JSON."""
    list_res = client.get("/api/scans?page_size=1").json()
    scan_id = list_res["items"][0]["id"]

    # Export CSV
    res_csv = client.get(f"/api/scans/{scan_id}/export?format=csv")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]
    assert "attachment;" in res_csv.headers["content-disposition"]
    csv_text = res_csv.text
    assert "Severity,Category,Confidence,Status,Finding ID,Finding Title" in csv_text

    # Export JSON
    res_json = client.get(f"/api/scans/{scan_id}/export?format=json")
    assert res_json.status_code == 200
    assert "application/json" in res_json.headers["content-type"]
    assert res_json.json()["id"] == scan_id


def test_api_compare_scans():
    """Verify GET /api/scans/{id}/compare/{other_id} computes diff between scans."""
    # Ingest two scans to compare
    res1 = client.post("/api/scans", json={"url": "https://example.com"}).json()
    res2 = client.post("/api/scans", json={"url": "http://127.0.0.1"}).json()

    comp_res = client.get(f"/api/scans/{res1['id']}/compare/{res2['id']}")
    assert comp_res.status_code == 200
    diff = comp_res.json()
    assert "score_diff" in diff
    assert "new_findings" in diff
    assert "resolved_findings" in diff
    assert "retained_findings" in diff


# ── SECTION 4: MULTI-LAYER MODULE TESTS ──────────────────────────────────────

def test_crawler_link_extraction():
    """Verify crawler HTML parser extracts links, forms, and scripts safely."""
    from app.scanner.crawler import WebContentParser
    html = """
    <html>
      <head><title>Test App</title></head>
      <body>
        <a href="/about">About</a>
        <a href="https://evil.com/out">Out</a>
        <form action="/login" method="POST">
          <input type="text" name="user">
          <input type="password" name="pass">
        </form>
        <script src="/static/app.js"></script>
      </body>
    </html>
    """
    parser = WebContentParser("https://example.com")
    parser.feed(html)
    assert "https://example.com/about" in parser.links
    assert len(parser.forms) == 1
    assert parser.forms[0]["action"] == "https://example.com/login"
    assert parser.forms[0]["method"] == "POST"
    assert "https://example.com/static/app.js" in parser.scripts


def test_client_secret_scanner_redaction():
    """Verify secret scanner redacts credentials in evidence."""
    from app.scanner.client_checker import ClientSideAuditor, redact_secret
    assert redact_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA************MPLE"

    auditor = ClientSideAuditor("https://example.com")
    mock_pages = [{
        "url": "https://example.com/config.js",
        "body_sample": "const awsKey = 'AKIAIOSFODNN7EXAMPLE'; const pat = 'ghp_123456789012345678901234567890123456';",
    }]
    findings = auditor.audit_client_security(mock_pages, [])
    assert len(findings) >= 2
    # Ensure raw secret is never present in evidence
    assert "AKIAIOSFODNN7EXAMPLE" not in findings[0]["evidence"]
    assert "AKIA" in findings[0]["evidence"]
    assert "****" in findings[0]["evidence"]


def test_owasp_audit_checks():
    """Verify OWASP auditor identifies database errors and cleartext forms."""
    from app.scanner.owasp_checker import audit_owasp_vulnerabilities

    mock_pages = [{
        "url": "https://example.com/search?q=test",
        "body_sample": "Warning: mysql_fetch_array(): supplied argument is not a valid MySQL result resource",
    }]
    mock_forms = [{
        "action": "http://example.com/login",
        "method": "POST",
        "inputs": [{"name": "password", "type": "password"}],
    }]
    mock_routes = [{"path": "/admin", "status_code": 200, "url": "https://example.com/admin"}]

    findings = audit_owasp_vulnerabilities(mock_pages, mock_forms, mock_routes, "https://example.com")
    f_ids = [f["id"] for f in findings]
    assert "OWASP-A03-DB-ERROR-DISCLOSED" in f_ids
    assert "OWASP-A02-HTTP-PASSWORD-FORM" in f_ids
    assert "OWASP-A01-OPEN-ADMIN" in f_ids


def test_threat_intel_cve_matching():
    """Verify CVE database matches vulnerable software versions accurately."""
    from app.scanner.threat_intel import ThreatIntelligenceAuditor

    auditor = ThreatIntelligenceAuditor("https://example.com")
    techs = [
        {"name": "Apache", "category": "Web Server", "version": "2.4.49"},
        {"name": "jQuery", "category": "JavaScript Library", "version": "3.4.1"},
        {"name": "Nginx", "category": "Web Server", "version": "1.24.0"},  # Safe version
    ]
    findings, limits = auditor.audit_threat_intel(techs, [])
    cve_ids = [f.get("cve_id") for f in findings]

    assert "CVE-2021-41773" in cve_ids  # Apache 2.4.49 Path Traversal
    assert "CVE-2020-11022" in cve_ids  # jQuery < 3.5.0 XSS
    assert "CVE-2021-23017" not in cve_ids  # Nginx 1.24.0 is not vulnerable
    assert len(limits) > 0


def test_scan_profiles_parameter():
    """Verify scan profiles (passive, quick, standard, comprehensive) are accepted."""
    for prof in ["passive", "quick", "standard"]:
        res = client.post("/api/scans", json={"url": "https://example.com", "profile": prof})
        assert res.status_code == 201
        data = res.json()
        assert data["profile"] == prof
        assert "attack_surface" in data
        assert "remediation_checklist" in data

