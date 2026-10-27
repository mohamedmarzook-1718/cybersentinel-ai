"""Alerts router – incident triage, status workflows, and XAI explanations."""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.alert import Alert
from app.models.event import SecurityEvent
from app.models.audit import AuditLog
from app.schemas import (
    AlertCreate,
    AlertUpdate,
    AlertOut,
    PaginatedAlerts,
)
from app.ml.explainer import generate_explanation
from app.ml.model_manager import model_manager

router = APIRouter(tags=["alerts"])


@router.get("", response_model=PaginatedAlerts)
def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    attack_category: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Alert)

    if status:
        query = query.filter(Alert.status == status)
    if severity:
        query = query.filter(Alert.severity == severity)
    if attack_category:
        query = query.filter(Alert.attack_category == attack_category)

    total = query.count()
    pages = math.ceil(total / page_size) if total > 0 else 1
    items = (
        query.order_by(desc(Alert.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return PaginatedAlerts(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


from app.core.deps import require_analyst_or_admin
from app.models.user import User

@router.post("", response_model=AlertOut, status_code=status.HTTP_201_CREATED)
def create_alert(
    payload: AlertCreate,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db),
):
    alert = Alert(
        event_id=payload.event_id,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        status="open",
        attack_category=payload.attack_category,
        source_ip=payload.source_ip,
        risk_score=payload.risk_score,
        explanation=payload.explanation,
        recommended_actions=payload.recommended_actions,
        created_by=current_user.id,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    audit = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="alert_created",
        resource_type="alert",
        resource_id=alert.id,
        detail=f"Created alert: {alert.title}",
    )
    db.add(audit)
    db.commit()

    return alert


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert(
    alert_id: int,
    payload: AlertUpdate,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db),
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    old_status = alert.status
    update_data = payload.model_dump(exclude_unset=True)

    for field, val in update_data.items():
        setattr(alert, field, val)

    if payload.status == "resolved" and old_status != "resolved":
        alert.resolved_at = datetime.now(timezone.utc)
    elif payload.status and payload.status != "resolved":
        alert.resolved_at = None

    alert.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(alert)

    audit = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="alert_updated",
        resource_type="alert",
        resource_id=alert.id,
        detail=f"Updated alert status from {old_status} to {alert.status}",
    )
    db.add(audit)
    db.commit()

    return alert


@router.get("/{alert_id}/explanation", response_model=dict)
def get_alert_explanation(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    event = None
    if alert.event_id:
        event = db.query(SecurityEvent).filter(SecurityEvent.id == alert.event_id).first()

    if event:
        event_dict = {
            "timestamp": event.timestamp,
            "user_identifier": event.user_identifier,
            "source_ip": event.source_ip,
            "login_result": event.login_result,
            "event_type": event.event_type,
            "failed_attempts_window": event.failed_attempts_window,
            "distinct_accounts_targeted": event.distinct_accounts_targeted,
            "request_frequency": event.request_frequency,
            "hour_of_day": event.hour_of_day,
            "geo_country": event.geo_country,
            "duration": event.duration,
            "bytes_sent": event.bytes_sent,
            "bytes_received": event.bytes_received,
            "packets": event.packets,
            "protocol": event.protocol,
            "destination_port": event.destination_port,
        }
        pred = model_manager.predict(event_dict) if model_manager.is_loaded else {}
        xai = generate_explanation(
            event=event_dict,
            anomaly_score=event.anomaly_score or 0.0,
            risk_score=event.risk_score or float(alert.risk_score or 50),
            risk_level=event.risk_level or alert.severity,
            attack_category=event.attack_category or alert.attack_category,
            attack_probability=event.attack_probability,
            feature_contributions=pred.get("feature_contributions", {}),
            is_synthetic=event.is_synthetic,
            model_version=event.model_version or "v1",
        )
        return xai

    # Fallback explanation if no event attached
    return {
        "summary": alert.description or alert.title,
        "observed_facts": [f"Alert triggered with severity: {alert.severity}"],
        "model_inferences": [f"Identified attack pattern: {alert.attack_category or 'General'}"],
        "recommendations": (
            alert.recommended_actions.split("\n")
            if alert.recommended_actions
            else ["Review source IP and enforce MFA"]
        ),
        "confidence_note": "Alert managed via standard SOC triage workflow.",
        "is_synthetic": False,
        "model_version": "v1.0",
    }
