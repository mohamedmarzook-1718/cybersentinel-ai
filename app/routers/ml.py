"""Machine Learning model management, training, and metrics router."""
from __future__ import annotations

from typing import List, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.event import SecurityEvent
from app.models.audit import AuditLog
from app.schemas import ModelMetadata
from app.ml.model_manager import model_manager
from app.ml.data_generator import generate_dataset
from app.ml.features import FEATURE_COLUMNS

router = APIRouter(tags=["ml"])


@router.get("/status", response_model=ModelMetadata)
def get_model_status():
    if not model_manager.is_loaded:
        model_manager.load()

    meta = model_manager.metadata
    if not meta:
        return ModelMetadata(
            version="not_trained",
            trained_at=None,
            training_samples=0,
            anomaly_model="IsolationForest (uninitialized)",
            classifier_model=None,
            features=FEATURE_COLUMNS,
            metrics=None,
        )

    return ModelMetadata(
        version=meta.get("version", "v1"),
        trained_at=meta.get("trained_at"),
        training_samples=meta.get("training_samples"),
        anomaly_model=meta.get("anomaly_model", "IsolationForest"),
        classifier_model=meta.get("classifier_model"),
        features=meta.get("features", FEATURE_COLUMNS),
        metrics=meta.get("metrics"),
    )


from app.core.deps import require_admin
from app.models.user import User

@router.post("/train", response_model=ModelMetadata)
def train_models(
    use_synthetic_data: bool = Query(True),
    n_samples: int = Query(320, ge=50, le=2000),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Train Isolation Forest & Random Forest models.
    Can train on historical database events or generate fresh benchmark synthetic data.
    Requires admin privileges.
    """
    events_for_training: List[Dict[str, Any]] = []

    if not use_synthetic_data:
        db_events = db.query(SecurityEvent).all()
        for e in db_events:
            events_for_training.append({
                "failed_attempts_window": e.failed_attempts_window,
                "distinct_accounts_targeted": e.distinct_accounts_targeted,
                "request_frequency": e.request_frequency,
                "hour_of_day": e.hour_of_day or 12,
                "login_result": e.login_result,
                "bytes_sent": e.bytes_sent or 0,
                "bytes_received": e.bytes_received or 0,
                "duration": e.duration or 0,
                "attack_label": e.attack_category or "normal",
            })

    if len(events_for_training) < 40:
        # Not enough DB events, supplement with high-fidelity synthetic benchmark
        normal_count = int(n_samples * 0.6)
        attack_count = int((n_samples - normal_count) / 4)
        events_for_training = generate_dataset(
            n_normal=normal_count,
            n_per_attack=attack_count,
        )

    meta = model_manager.train(events_for_training)

    audit = AuditLog(
        user_id=admin.id,
        username=admin.username,
        action="model_trained",
        resource_type="model",
        detail=f"Trained IsolationForest & RandomForest on {len(events_for_training)} samples. Accuracy: {meta.get('metrics', {}).get('accuracy')}",
    )
    db.add(audit)
    db.commit()

    return ModelMetadata(
        version=meta.get("version", "v1"),
        trained_at=meta.get("trained_at"),
        training_samples=meta.get("training_samples"),
        anomaly_model=meta.get("anomaly_model", "IsolationForest"),
        classifier_model=meta.get("classifier_model"),
        features=meta.get("features", FEATURE_COLUMNS),
        metrics=meta.get("metrics"),
    )


@router.get("/features", response_model=dict)
def get_features_info():
    """Return feature definitions and importance scores if available."""
    if not model_manager.is_loaded:
        model_manager.load()

    importances = {}
    if model_manager._classifier is not None:
        try:
            raw_imps = model_manager._classifier["clf"].feature_importances_
            importances = {
                FEATURE_COLUMNS[i]: round(float(raw_imps[i]), 4)
                for i in range(len(FEATURE_COLUMNS))
            }
        except Exception:
            pass

    return {
        "features": FEATURE_COLUMNS,
        "importances": importances,
    }
