"""Application and risk threshold settings router."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.audit import AuditLog
from app.schemas import SettingsOut, SettingsUpdate
from app.core.config import get_settings

router = APIRouter(tags=["settings"])
settings = get_settings()


@router.get("", response_model=SettingsOut)
def get_current_settings():
    return SettingsOut(
        risk_threshold_low=settings.risk_threshold_low,
        risk_threshold_medium=settings.risk_threshold_medium,
        risk_threshold_high=settings.risk_threshold_high,
        anomaly_contamination=settings.anomaly_contamination,
        model_random_seed=settings.model_random_seed,
        access_token_expire_minutes=settings.access_token_expire_minutes,
    )


from app.core.deps import require_admin
from app.models.user import User

@router.patch("", response_model=SettingsOut)
def update_settings(
    payload: SettingsUpdate,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if payload.risk_threshold_low is not None:
        settings.risk_threshold_low = payload.risk_threshold_low
    if payload.risk_threshold_medium is not None:
        settings.risk_threshold_medium = payload.risk_threshold_medium
    if payload.risk_threshold_high is not None:
        settings.risk_threshold_high = payload.risk_threshold_high
    if payload.anomaly_contamination is not None:
        settings.anomaly_contamination = payload.anomaly_contamination

    audit = AuditLog(
        user_id=admin.id,
        username=admin.username,
        action="settings_updated",
        resource_type="settings",
        detail=f"Updated risk thresholds: low={settings.risk_threshold_low}, med={settings.risk_threshold_medium}, high={settings.risk_threshold_high}",
    )
    db.add(audit)
    db.commit()

    return SettingsOut(
        risk_threshold_low=settings.risk_threshold_low,
        risk_threshold_medium=settings.risk_threshold_medium,
        risk_threshold_high=settings.risk_threshold_high,
        anomaly_contamination=settings.anomaly_contamination,
        model_random_seed=settings.model_random_seed,
        access_token_expire_minutes=settings.access_token_expire_minutes,
    )
