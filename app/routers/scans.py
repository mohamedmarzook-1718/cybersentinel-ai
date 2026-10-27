"""Web Security Scanner API Router."""
from __future__ import annotations

import csv
import io
import json
import math
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import WebScan
from app.models.audit import AuditLog
from app.models.user import User
from app.schemas import (
    WebScanCreate,
    WebScanOut,
    WebScanListItem,
    WebScanSummary,
    ScanFinding,
    RemediationItem,
    PaginatedWebScans,
    WebScanCompareResult,
)
from app.scanner.engine import WebSecurityScanner
from app.core.deps import get_current_user

router = APIRouter(tags=["scans"])
scanner_instance = WebSecurityScanner(timeout=8.0, max_redirects=5)


def _scan_to_out(scan: WebScan) -> WebScanOut:
    """Helper to convert ORM WebScan to Pydantic WebScanOut."""
    try:
        findings_data = json.loads(scan.findings_json) if scan.findings_json else []
    except Exception:
        findings_data = []

    try:
        summary_data = json.loads(scan.summary_json) if scan.summary_json else {}
    except Exception:
        summary_data = {}

    try:
        headers_data = json.loads(scan.headers_json) if scan.headers_json else {}
    except Exception:
        headers_data = {}

    try:
        attack_surface_data = json.loads(scan.attack_surface_json) if getattr(scan, "attack_surface_json", None) else {}
    except Exception:
        attack_surface_data = {}

    try:
        remediation_data = json.loads(scan.remediation_json) if getattr(scan, "remediation_json", None) else []
    except Exception:
        remediation_data = []

    try:
        limitations_data = json.loads(scan.limitations_json) if getattr(scan, "limitations_json", None) else []
    except Exception:
        limitations_data = []

    return WebScanOut(
        id=scan.id,
        url=scan.url,
        target_host=scan.target_host,
        target_ip=scan.target_ip,
        scan_status=scan.scan_status,
        score=scan.score,
        risk_level=scan.risk_level,
        profile=getattr(scan, "profile", "standard") or "standard",
        http_status=scan.http_status,
        response_time_ms=scan.response_time_ms,
        tls_version=scan.tls_version,
        cert_valid=scan.cert_valid,
        cert_issuer=scan.cert_issuer,
        cert_expires_at=scan.cert_expires_at,
        findings=[ScanFinding(**f) for f in findings_data],
        summary=WebScanSummary(**summary_data),
        headers=headers_data,
        attack_surface=attack_surface_data,
        remediation_checklist=[RemediationItem(**r) for r in remediation_data],
        limitations=limitations_data,
        pages_crawled=getattr(scan, "pages_crawled", 1) or 1,
        pages_discovered=getattr(scan, "pages_discovered", 1) or 1,
        error_message=scan.error_message,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
    )


def _scan_to_list_item(scan: WebScan) -> WebScanListItem:
    """Helper to convert ORM WebScan to list item."""
    try:
        summary_data = json.loads(scan.summary_json) if scan.summary_json else {}
    except Exception:
        summary_data = {}

    return WebScanListItem(
        id=scan.id,
        url=scan.url,
        target_host=scan.target_host,
        target_ip=scan.target_ip,
        scan_status=scan.scan_status,
        score=scan.score,
        risk_level=scan.risk_level,
        profile=getattr(scan, "profile", "standard") or "standard",
        http_status=scan.http_status,
        pages_crawled=getattr(scan, "pages_crawled", 1) or 1,
        summary=WebScanSummary(**summary_data),
        started_at=scan.started_at,
        completed_at=scan.completed_at,
    )


@router.post("", response_model=WebScanOut, status_code=status.HTTP_201_CREATED)
def execute_scan(
    payload: WebScanCreate,
    db: Session = Depends(get_db),
):
    """
    Perform a comprehensive multi-layer website security assessment.
    Enforces SSRF prevention, checks TLS/SSL, security headers, cookies, OWASP Top 10,
    client secrets, API security, and threat intelligence.
    """
    scan_res = scanner_instance.scan(
        target_url=payload.url,
        profile=payload.profile,
        allowed_domains=payload.allowed_domains,
        excluded_paths=payload.excluded_paths,
        max_crawl_pages=payload.max_crawl_pages,
    )

    # Persist to database
    db_scan = WebScan(
        url=scan_res["url"],
        target_host=scan_res["target_host"],
        target_ip=scan_res["target_ip"],
        scan_status=scan_res["scan_status"],
        score=scan_res["score"],
        risk_level=scan_res["risk_level"],
        profile=scan_res.get("profile", "standard"),
        http_status=scan_res["http_status"],
        response_time_ms=scan_res["response_time_ms"],
        tls_version=scan_res["tls_version"],
        cert_valid=scan_res["cert_valid"],
        cert_issuer=scan_res["cert_issuer"],
        cert_expires_at=scan_res["cert_expires_at"],
        findings_json=json.dumps(scan_res["findings"]),
        summary_json=json.dumps(scan_res["summary"]),
        headers_json=json.dumps(scan_res["headers"]),
        scope_config_json=json.dumps({
            "allowed_domains": payload.allowed_domains,
            "excluded_paths": payload.excluded_paths,
        }),
        attack_surface_json=json.dumps(scan_res.get("attack_surface", {})),
        remediation_json=json.dumps(scan_res.get("remediation_checklist", [])),
        limitations_json=json.dumps(scan_res.get("limitations", [])),
        pages_crawled=scan_res.get("pages_crawled", 1),
        pages_discovered=scan_res.get("pages_discovered", 1),
        error_message=scan_res["error_message"],
        started_at=scan_res["started_at"],
        completed_at=scan_res["completed_at"],
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    # Record audit log
    audit = AuditLog(
        action="web_scan_performed",
        resource_type="scan",
        resource_id=db_scan.id,
        detail=f"Scanned {db_scan.url} [{payload.profile.upper()}] (Score: {db_scan.score}/100, Risk: {db_scan.risk_level}, Findings: {len(scan_res['findings'])}, Crawled: {scan_res.get('pages_crawled', 1)})",
    )
    db.add(audit)
    db.commit()

    return _scan_to_out(db_scan)


@router.get("", response_model=PaginatedWebScans)
def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Retrieve historical website scans with pagination."""
    query = db.query(WebScan)
    if search:
        query = query.filter(
            (WebScan.url.contains(search)) | (WebScan.target_host.contains(search))
        )

    total = query.count()
    pages = math.ceil(total / page_size) if total > 0 else 1
    scans = (
        query.order_by(desc(WebScan.started_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    items = []
    for s in scans:
        try:
            sum_data = json.loads(s.summary_json) if s.summary_json else {}
        except Exception:
            sum_data = {}

        items.append(
            WebScanListItem(
                id=s.id,
                url=s.url,
                target_host=s.target_host,
                target_ip=s.target_ip,
                scan_status=s.scan_status,
                score=s.score,
                risk_level=s.risk_level,
                http_status=s.http_status,
                summary=WebScanSummary(**sum_data),
                started_at=s.started_at,
                completed_at=s.completed_at,
            )
        )

    return PaginatedWebScans(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/{scan_id}", response_model=WebScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Retrieve complete findings for a specific scan."""
    scan = db.query(WebScan).filter(WebScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")
    return _scan_to_out(scan)


@router.get("/{scan_id}/export")
def export_scan_report(
    scan_id: int,
    format: str = Query("csv", pattern="^(csv|json)$"),
    db: Session = Depends(get_db),
):
    """Download scan findings report as CSV or JSON."""
    scan = db.query(WebScan).filter(WebScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")

    scan_out = _scan_to_out(scan)

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Severity",
            "Category",
            "Confidence",
            "Status",
            "Finding ID",
            "Finding Title",
            "CVE ID",
            "CWE ID",
            "OWASP Category",
            "Observed Evidence",
            "Explanation",
            "Remediation Advice",
            "Reproduction Steps",
            "Affected URL",
        ])

        for f in scan_out.findings:
            writer.writerow([
                f.severity,
                f.category,
                f.confidence,
                f.status,
                f.id,
                f.title,
                f.cve_id or "N/A",
                f.cwe_id or "N/A",
                f.owasp_category or "N/A",
                f.evidence,
                f.explanation,
                f.recommendation,
                f.reproduction_steps or "N/A",
                f.affected_url,
            ])

        csv_content = output.getvalue()
        filename = f"cybersentinel_scan_{scan.target_host}_{scan_id}.csv"
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    # Format JSON
    json_content = scan_out.model_dump_json(indent=2)
    filename = f"cybersentinel_scan_{scan.target_host}_{scan_id}.json"
    return Response(
        content=json_content,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/{scan_id}/compare/{other_scan_id}", response_model=WebScanCompareResult)
def compare_scans(scan_id: int, other_scan_id: int, db: Session = Depends(get_db)):
    """Compare two scans side-by-side to track security posture drift or remediation progress."""
    scan_a = db.query(WebScan).filter(WebScan.id == scan_id).first()
    scan_b = db.query(WebScan).filter(WebScan.id == other_scan_id).first()

    if not scan_a or not scan_b:
        raise HTTPException(status_code=404, detail="One or both scan records were not found")

    out_a = _scan_to_out(scan_a)
    out_b = _scan_to_out(scan_b)

    map_a = {f.id: f for f in out_a.findings}
    map_b = {f.id: f for f in out_b.findings}

    new_findings = [f for fid, f in map_b.items() if fid not in map_a]
    resolved_findings = [f for fid, f in map_a.items() if fid not in map_b]
    retained_findings = [f for fid, f in map_b.items() if fid in map_a]

    return WebScanCompareResult(
        scan_a=out_a,
        scan_b=out_b,
        score_diff=out_b.score - out_a.score,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        retained_findings=retained_findings,
    )
