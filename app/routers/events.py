"""Security Events router – ingestion, pagination, ML inference, CSV upload."""
from __future__ import annotations

import csv
import io
import math
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, status
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.event import SecurityEvent
from app.models.alert import Alert
from app.models.audit import AuditLog
from app.core.deps import require_analyst_or_admin
from app.models.user import User
from app.schemas import (
    EventCreate,
    EventOut,
    PaginatedEvents,
    PredictionResult,
    CSVUploadResult,
)
from app.ml.features import engineer_features, compute_risk_score
from app.ml.model_manager import model_manager
from app.ml.explainer import generate_explanation
from app.ml.early_warning import correlate_event_history
from app.ml.data_generator import generate_dataset
from app.core.config import get_settings

router = APIRouter(tags=["events"])
settings = get_settings()


def _ensure_models_loaded():
    if not model_manager.is_loaded:
        model_manager.load()


@router.get("", response_model=PaginatedEvents)
def list_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    event_type: Optional[str] = None,
    risk_level: Optional[str] = None,
    attack_category: Optional[str] = None,
    source_ip: Optional[str] = None,
    user_identifier: Optional[str] = None,
    is_synthetic: Optional[bool] = None,
    db: Session = Depends(get_db),
):
    query = db.query(SecurityEvent)

    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)
    if risk_level:
        query = query.filter(SecurityEvent.risk_level == risk_level)
    if attack_category:
        query = query.filter(SecurityEvent.attack_category == attack_category)
    if source_ip:
        query = query.filter(SecurityEvent.source_ip.contains(source_ip))
    if user_identifier:
        query = query.filter(SecurityEvent.user_identifier.contains(user_identifier))
    if is_synthetic is not None:
        query = query.filter(SecurityEvent.is_synthetic == is_synthetic)

    total = query.count()
    pages = math.ceil(total / page_size) if total > 0 else 1
    items = (
        query.order_by(desc(SecurityEvent.timestamp))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return PaginatedEvents(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/{event_id}", response_model=EventOut)
def get_event(event_id: int, db: Session = Depends(get_db)):
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.post("", response_model=EventOut, status_code=status.HTTP_201_CREATED)
def create_event(payload: EventCreate, db: Session = Depends(get_db)):
    _ensure_models_loaded()
    event_dict = payload.model_dump()

    # Reconstruct sequence history from past telemetry in DB if not manually provided
    event_dict = correlate_event_history(db, event_dict)

    # Model inference
    pred = model_manager.predict(event_dict)
    anomaly_score = pred["anomaly_score"]
    attack_category = pred.get("attack_category")
    attack_probability = pred.get("attack_probability")

    # Risk score calculation
    risk_score, risk_level = compute_risk_score(
        anomaly_score=anomaly_score,
        attack_probability=attack_probability,
        event=event_dict,
        thresholds={
            "low": settings.risk_threshold_low,
            "medium": settings.risk_threshold_medium,
            "high": settings.risk_threshold_high,
        },
        attack_category=attack_category,
    )

    db_event = SecurityEvent(
        timestamp=payload.timestamp,
        user_identifier=payload.user_identifier,
        source_ip=payload.source_ip,
        login_result=payload.login_result,
        event_type=payload.event_type,
        failed_attempts_window=event_dict.get("failed_attempts_window", payload.failed_attempts_window),
        distinct_accounts_targeted=event_dict.get("distinct_accounts_targeted", payload.distinct_accounts_targeted),
        request_frequency=event_dict.get("request_frequency", payload.request_frequency),
        hour_of_day=payload.hour_of_day,
        geo_country=payload.geo_country,
        anonymized_source_attr=payload.anonymized_source_attr,
        duration=payload.duration,
        bytes_sent=payload.bytes_sent,
        bytes_received=payload.bytes_received,
        packets=payload.packets,
        protocol=payload.protocol,
        destination_port=payload.destination_port,
        anomaly_score=anomaly_score,
        risk_score=risk_score,
        risk_level=risk_level,
        attack_category=attack_category,
        attack_probability=attack_probability,
        model_version=pred.get("model_version"),
        is_synthetic=payload.is_synthetic,
        source=payload.source,
        raw_notes=payload.raw_notes,
    )
    db.add(db_event)
    db.commit()
    db.refresh(db_event)

    # Automatically generate alert if High or Critical
    if risk_level in ("High", "Critical"):
        xai = generate_explanation(
            event=event_dict,
            anomaly_score=anomaly_score,
            risk_score=risk_score,
            risk_level=risk_level,
            attack_category=attack_category,
            attack_probability=attack_probability,
            feature_contributions=pred.get("feature_contributions", {}),
            is_synthetic=payload.is_synthetic,
            model_version=pred.get("model_version", "unknown"),
        )
        cat_title = (attack_category or "Suspicious Anomaly").replace("_", " ").title()
        alert = Alert(
            event_id=db_event.id,
            title=f"{risk_level} Risk: {cat_title} from {payload.source_ip or 'Unknown IP'}",
            description=xai["summary"],
            severity=risk_level,
            status="open",
            attack_category=attack_category,
            source_ip=payload.source_ip,
            risk_score=int(risk_score),
            explanation=xai["summary"] + "\n\nFacts:\n- " + "\n- ".join(xai["observed_facts"]),
            recommended_actions="\n".join(f"• {a}" for a in xai["recommendations"]),
        )
        db.add(alert)
        db.commit()

    return db_event


@router.post("/predict", response_model=PredictionResult)
def predict_event(payload: EventCreate):
    """Run real-time ML inference and XAI explanation on an event without saving."""
    _ensure_models_loaded()
    event_dict = payload.model_dump()

    pred = model_manager.predict(event_dict)
    anomaly_score = pred["anomaly_score"]
    attack_category = pred.get("attack_category")
    attack_probability = pred.get("attack_probability")

    risk_score, risk_level = compute_risk_score(
        anomaly_score=anomaly_score,
        attack_probability=attack_probability,
        event=event_dict,
        thresholds={
            "low": settings.risk_threshold_low,
            "medium": settings.risk_threshold_medium,
            "high": settings.risk_threshold_high,
        },
        attack_category=attack_category,
    )

    xai = generate_explanation(
        event=event_dict,
        anomaly_score=anomaly_score,
        risk_score=risk_score,
        risk_level=risk_level,
        attack_category=attack_category,
        attack_probability=attack_probability,
        feature_contributions=pred.get("feature_contributions", {}),
        is_synthetic=payload.is_synthetic,
        model_version=pred.get("model_version", "unknown"),
    )

    return PredictionResult(
        event_id=None,
        anomaly_score=round(anomaly_score, 4),
        risk_score=round(risk_score, 2),
        risk_level=risk_level,
        attack_category=attack_category,
        attack_probability=round(attack_probability, 4) if attack_probability is not None else None,
        model_version=pred.get("model_version", "heuristic"),
        is_synthetic=payload.is_synthetic,
        explanation=xai["summary"],
        feature_contributions=pred.get("feature_contributions", {}),
        recommended_actions=xai["recommendations"],
        confidence_note=xai["confidence_note"],
        early_warning_stage=xai.get("early_warning_stage"),
        early_warning_indicators=xai.get("early_warning_indicators", []),
        escalation_potential=xai.get("escalation_potential"),
    )


@router.post("/upload-csv", response_model=CSVUploadResult)
async def upload_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
):
    """Upload CSV log file for batch event ingestion and ML threat detection."""
    _ensure_models_loaded()

    contents = await file.read()
    if len(contents) > settings.max_upload_size:
        raise HTTPException(status_code=400, detail="File size exceeds maximum upload limit")

    try:
        text = contents.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = contents.decode("latin-1")
        except Exception:
            raise HTTPException(status_code=400, detail="Unable to decode CSV file format")

    reader = csv.DictReader(io.StringIO(text))
    accepted = 0
    rejected = 0
    errors: List[str] = []
    created_ids: List[int] = []

    for idx, row in enumerate(reader, start=1):
        try:
            # Parse timestamp
            ts_str = row.get("timestamp")
            if ts_str:
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except Exception:
                    ts = datetime.now(timezone.utc)
            else:
                ts = datetime.now(timezone.utc)

            event_dict = {
                "timestamp": ts,
                "user_identifier": row.get("user_identifier") or row.get("user"),
                "source_ip": row.get("source_ip") or row.get("ip"),
                "login_result": row.get("login_result") or "success",
                "event_type": row.get("event_type") or "auth",
                "failed_attempts_window": int(row.get("failed_attempts_window") or 0),
                "distinct_accounts_targeted": int(row.get("distinct_accounts_targeted") or 1),
                "request_frequency": float(row.get("request_frequency") or 1.0),
                "hour_of_day": int(row.get("hour_of_day")) if row.get("hour_of_day") else ts.hour,
                "geo_country": row.get("geo_country"),
                "duration": float(row.get("duration")) if row.get("duration") else None,
                "bytes_sent": float(row.get("bytes_sent")) if row.get("bytes_sent") else None,
                "bytes_received": float(row.get("bytes_received")) if row.get("bytes_received") else None,
                "packets": int(row.get("packets")) if row.get("packets") else None,
                "protocol": row.get("protocol") or "TCP",
                "destination_port": int(row.get("destination_port")) if row.get("destination_port") else None,
                "is_synthetic": False,
                "source": "csv",
            }

            pred = model_manager.predict(event_dict)
            anomaly_score = pred["anomaly_score"]
            attack_category = pred.get("attack_category")
            attack_probability = pred.get("attack_probability")

            risk_score, risk_level = compute_risk_score(
                anomaly_score=anomaly_score,
                attack_probability=attack_probability,
                event=event_dict,
                thresholds={
                    "low": settings.risk_threshold_low,
                    "medium": settings.risk_threshold_medium,
                    "high": settings.risk_threshold_high,
                },
                attack_category=attack_category,
            )

            db_event = SecurityEvent(
                **event_dict,
                anomaly_score=anomaly_score,
                risk_score=risk_score,
                risk_level=risk_level,
                attack_category=attack_category,
                attack_probability=attack_probability,
                model_version=pred.get("model_version"),
            )
            db.add(db_event)
            db.flush()

            if risk_level in ("High", "Critical"):
                xai = generate_explanation(
                    event=event_dict,
                    anomaly_score=anomaly_score,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    attack_category=attack_category,
                    attack_probability=attack_probability,
                    feature_contributions=pred.get("feature_contributions", {}),
                    is_synthetic=False,
                    model_version=pred.get("model_version", "unknown"),
                )
                alert = Alert(
                    event_id=db_event.id,
                    title=f"{risk_level} Risk: {(attack_category or 'Anomaly').replace('_', ' ').title()} from {db_event.source_ip}",
                    description=xai["summary"],
                    severity=risk_level,
                    status="open",
                    attack_category=attack_category,
                    source_ip=db_event.source_ip,
                    risk_score=int(risk_score),
                    explanation=xai["summary"],
                    recommended_actions="\n".join(f"• {a}" for a in xai["recommendations"]),
                )
                db.add(alert)

            accepted += 1
            created_ids.append(db_event.id)

        except Exception as e:
            rejected += 1
            if len(errors) < 10:
                errors.append(f"Row {idx}: {str(e)}")

    db.commit()

    # Log audit entry
    audit = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="csv_upload",
        resource_type="event",
        detail=f"Uploaded CSV with {accepted} accepted, {rejected} rejected",
    )
    db.add(audit)
    db.commit()

    return CSVUploadResult(
        accepted=accepted,
        rejected=rejected,
        errors=errors,
        event_ids=created_ids[:50],
    )


@router.post("/seed-synthetic", response_model=dict)
def seed_synthetic_events(
    n_normal: int = Query(50, ge=1, le=500),
    n_per_attack: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
):
    """Seed synthetic events with real-time ML scoring and alerts."""
    _ensure_models_loaded()
    dataset = generate_dataset(n_normal=n_normal, n_per_attack=n_per_attack)

    created_events = 0
    created_alerts = 0

    for rec in dataset:
        event_dict = dict(rec)
        attack_label = event_dict.pop("attack_label", None)

        pred = model_manager.predict(event_dict)
        anomaly_score = pred["anomaly_score"]
        attack_category = pred.get("attack_category") or (attack_label if attack_label != "normal" else None)
        attack_probability = pred.get("attack_probability") or (0.95 if attack_category else None)

        risk_score, risk_level = compute_risk_score(
            anomaly_score=anomaly_score,
            attack_probability=attack_probability,
            event=event_dict,
            thresholds={
                "low": settings.risk_threshold_low,
                "medium": settings.risk_threshold_medium,
                "high": settings.risk_threshold_high,
            },
            attack_category=attack_category,
        )

        db_event = SecurityEvent(
            **event_dict,
            anomaly_score=anomaly_score,
            risk_score=risk_score,
            risk_level=risk_level,
            attack_category=attack_category,
            attack_probability=attack_probability,
            model_version=pred.get("model_version"),
        )
        db.add(db_event)
        db.flush()
        created_events += 1

        if risk_level in ("High", "Critical"):
            xai = generate_explanation(
                event=event_dict,
                anomaly_score=anomaly_score,
                risk_score=risk_score,
                risk_level=risk_level,
                attack_category=attack_category,
                attack_probability=attack_probability,
                feature_contributions=pred.get("feature_contributions", {}),
                is_synthetic=True,
                model_version=pred.get("model_version", "unknown"),
            )
            cat_name = (attack_category or "Anomaly").replace("_", " ").title()
            alert = Alert(
                event_id=db_event.id,
                title=f"{risk_level} Risk: {cat_name} from {db_event.source_ip or 'Network'}",
                description=xai["summary"],
                severity=risk_level,
                status="open",
                attack_category=attack_category,
                source_ip=db_event.source_ip,
                risk_score=int(risk_score),
                explanation=xai["summary"] + "\n\nFacts:\n- " + "\n- ".join(xai["observed_facts"]),
                recommended_actions="\n".join(f"• {a}" for a in xai["recommendations"]),
            )
            db.add(alert)
            created_alerts += 1

    db.commit()
    return {
        "status": "success",
        "events_created": created_events,
        "alerts_created": created_alerts,
    }
