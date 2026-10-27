"""Dashboard statistics and threat aggregation router."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.alert import Alert
from app.models.event import SecurityEvent
from app.schemas import DashboardStats, AlertOut
from app.ml.model_manager import model_manager

router = APIRouter(tags=["dashboard"])


@router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db)):
    total_events = db.query(SecurityEvent).count()

    high_critical_alerts = (
        db.query(Alert).filter(Alert.severity.in_(["High", "Critical"])).count()
    )

    suspicious_logins = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.login_result.in_(["failure", "lockout"]))
        .count()
    )

    anomalies_detected = (
        db.query(SecurityEvent)
        .filter(
            (SecurityEvent.anomaly_score < 0.0)
            | (SecurityEvent.risk_level.in_(["High", "Critical"]))
        )
        .count()
    )

    open_alerts = db.query(Alert).filter(Alert.status != "resolved").count()

    # Risk level distribution
    risk_rows = (
        db.query(SecurityEvent.risk_level, func.count(SecurityEvent.id))
        .group_by(SecurityEvent.risk_level)
        .all()
    )
    risk_distribution = {
        "Low": 0,
        "Medium": 0,
        "High": 0,
        "Critical": 0,
    }
    for level, count in risk_rows:
        if level in risk_distribution:
            risk_distribution[level] = count
        elif level:
            risk_distribution[level] = count

    # Category distribution
    cat_rows = (
        db.query(SecurityEvent.attack_category, func.count(SecurityEvent.id))
        .group_by(SecurityEvent.attack_category)
        .all()
    )
    category_distribution = {
        "normal": 0,
        "brute_force": 0,
        "credential_stuffing": 0,
        "port_scan": 0,
        "anomalous_traffic": 0,
    }
    for cat, count in cat_rows:
        key = cat or "normal"
        category_distribution[key] = category_distribution.get(key, 0) + count

    # Anomaly trend: group events by hour or day
    now = datetime.now(timezone.utc)
    trend_data = []
    # Build 7 time buckets (past 7 days or past 7 time segments)
    for i in range(6, -1, -1):
        bucket_date = now - timedelta(days=i)
        date_str = bucket_date.strftime("%b %d")
        # Count anomalies on this day
        start_day = bucket_date.replace(hour=0, minute=0, second=0, microsecond=0)
        end_day = bucket_date.replace(hour=23, minute=59, second=59, microsecond=999999)

        count = (
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.timestamp >= start_day,
                SecurityEvent.timestamp <= end_day,
                (SecurityEvent.anomaly_score < 0.0) | (SecurityEvent.risk_level.in_(["High", "Critical"])),
            )
            .count()
        )
        total_bucket = (
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.timestamp >= start_day,
                SecurityEvent.timestamp <= end_day,
            )
            .count()
        )
        trend_data.append({
            "date": date_str,
            "anomalies": count,
            "total_events": total_bucket,
        })

    # Recent alerts
    recent_alerts = (
        db.query(Alert)
        .order_by(desc(Alert.created_at))
        .limit(6)
        .all()
    )

    # Model status
    if not model_manager.is_loaded:
        model_manager.load()

    model_status = {
        "is_loaded": model_manager.is_loaded,
        "version": model_manager.metadata.get("version", "untrained"),
        "trained_at": model_manager.metadata.get("trained_at"),
        "training_samples": model_manager.metadata.get("training_samples", 0),
        "accuracy": model_manager.metadata.get("metrics", {}).get("accuracy"),
        "f1_macro": model_manager.metadata.get("metrics", {}).get("f1_macro"),
        "anomaly_model": model_manager.metadata.get("anomaly_model", "IsolationForest"),
        "classifier_model": model_manager.metadata.get("classifier_model", "RandomForestClassifier"),
    }

    return DashboardStats(
        total_events=total_events,
        high_critical_alerts=high_critical_alerts,
        suspicious_logins=suspicious_logins,
        anomalies_detected=anomalies_detected,
        open_alerts=open_alerts,
        risk_distribution=risk_distribution,
        category_distribution=category_distribution,
        anomaly_trend=trend_data,
        recent_alerts=recent_alerts,
        model_status=model_status,
    )
