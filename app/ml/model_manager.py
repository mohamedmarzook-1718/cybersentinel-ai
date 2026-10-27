"""
ML model manager: Isolation Forest anomaly detector +
Random Forest attack classifier + preprocessing pipeline.
Handles training, persistence, versioning and inference.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_score, recall_score
)

from app.ml.features import engineer_features, events_to_dataframe, FEATURE_COLUMNS
from app.core.config import get_settings

settings = get_settings()

MODELS_DIR = Path(__file__).parent.parent.parent / "models_store"
MODELS_DIR.mkdir(exist_ok=True)

ANOMALY_MODEL_PATH = MODELS_DIR / "isolation_forest.joblib"
CLASSIFIER_MODEL_PATH = MODELS_DIR / "random_forest.joblib"
SCALER_PATH = MODELS_DIR / "scaler.joblib"
METADATA_PATH = MODELS_DIR / "model_metadata.json"

LABEL_MAP = {
    "normal": 0,
    "brute_force": 1,
    "credential_stuffing": 2,
    "port_scan": 3,
    "anomalous_traffic": 4,
}
LABEL_MAP_INV = {v: k for k, v in LABEL_MAP.items()}


class ModelManager:
    """Singleton-like model manager loaded once and cached."""

    def __init__(self):
        self._anomaly_model: Optional[IsolationForest] = None
        self._classifier: Optional[Pipeline] = None
        self._scaler: Optional[StandardScaler] = None
        self._metadata: Dict[str, Any] = {}
        self._loaded = False

    def load(self) -> bool:
        """Load persisted models if they exist. Returns True if both loaded."""
        try:
            if ANOMALY_MODEL_PATH.exists():
                self._anomaly_model = joblib.load(ANOMALY_MODEL_PATH)
            if CLASSIFIER_MODEL_PATH.exists():
                self._classifier = joblib.load(CLASSIFIER_MODEL_PATH)
            if SCALER_PATH.exists():
                self._scaler = joblib.load(SCALER_PATH)
            if METADATA_PATH.exists():
                with open(METADATA_PATH) as f:
                    self._metadata = json.load(f)
            self._loaded = bool(self._anomaly_model)
            return self._loaded
        except Exception as e:
            print(f"[ModelManager] Load error: {e}")
            return False

    def train(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Train anomaly detector on all events (unsupervised).
        Train classifier on labeled attack events (supervised, if labels present).
        Uses a chronological-friendly random split with fixed seed.
        """
        seed = settings.model_random_seed

        # Build feature matrix
        df = events_to_dataframe(events)
        X = df[FEATURE_COLUMNS].values

        # ── Supervised classifier (split before scaling to prevent data leakage) ──
        metrics: Dict[str, Any] = {}
        has_labels = any("attack_label" in e for e in events)
        labels = [e.get("attack_label", "normal") for e in events]
        y = np.array([LABEL_MAP.get(l, 0) for l in labels])

        n_classes = len(set(y))
        classifier_info = None

        scaler = StandardScaler()

        if has_labels and n_classes > 1 and len(X) >= 20:
            # Split raw features first to eliminate data leakage
            X_train_raw, X_test_raw, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=seed, stratify=y
            )
            # Fit scaler ONLY on training data
            X_train = scaler.fit_transform(X_train_raw)
            X_test = scaler.transform(X_test_raw)

            rf = RandomForestClassifier(
                n_estimators=200,
                random_state=seed,
                class_weight="balanced",
            )
            rf.fit(X_train, y_train)
            y_pred = rf.predict(X_test)

            metrics = {
                "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
                "f1_macro": round(float(f1_score(y_test, y_pred, average="macro", zero_division=0)), 4),
                "precision_macro": round(float(precision_score(y_test, y_pred, average="macro", zero_division=0)), 4),
                "recall_macro": round(float(recall_score(y_test, y_pred, average="macro", zero_division=0)), 4),
                "classification_report": classification_report(
                    y_test, y_pred,
                    target_names=[LABEL_MAP_INV.get(i, str(i)) for i in sorted(set(y))],
                    zero_division=0,
                ),
                "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
                "n_train": int(len(X_train)),
                "n_test": int(len(X_test)),
                "class_distribution": {
                    LABEL_MAP_INV.get(int(k), str(k)): int(v)
                    for k, v in zip(*np.unique(y, return_counts=True))
                },
            }

            pipeline = Pipeline([("clf", rf)])
            self._classifier = pipeline
            joblib.dump(pipeline, CLASSIFIER_MODEL_PATH)
            classifier_info = "RandomForestClassifier"
        else:
            scaler.fit(X)

        # ── Anomaly detection (unsupervised) ──
        X_scaled = scaler.transform(X)
        iso = IsolationForest(
            contamination=settings.anomaly_contamination,
            random_state=seed,
            n_estimators=200,
        )
        iso.fit(X_scaled)

        self._anomaly_model = iso
        self._scaler = scaler
        joblib.dump(iso, ANOMALY_MODEL_PATH)
        joblib.dump(scaler, SCALER_PATH)

        version = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self._metadata = {
            "version": version,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "training_samples": len(events),
            "anomaly_model": "IsolationForest",
            "classifier_model": classifier_info,
            "features": FEATURE_COLUMNS,
            "metrics": metrics,
            "random_seed": seed,
        }
        with open(METADATA_PATH, "w") as f:
            json.dump(self._metadata, f, indent=2)

        self._loaded = True
        return self._metadata

    def predict(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run inference on a single event dict.
        Returns anomaly_score, attack_category, attack_probability, feature_contributions.
        """
        if not self._loaded or self._anomaly_model is None:
            # Return a heuristic-only result when model is not available
            return self._heuristic_only(event)

        feats = engineer_features(event)
        X = np.array([[feats[c] for c in FEATURE_COLUMNS]])

        if self._scaler:
            X_scaled = self._scaler.transform(X)
        else:
            X_scaled = X

        # Anomaly score: more negative = more anomalous
        anomaly_score = float(self._anomaly_model.score_samples(X_scaled)[0])

        # Classifier
        attack_category = None
        attack_probability = None
        if self._classifier is not None:
            proba = self._classifier["clf"].predict_proba(X_scaled)[0]
            best_idx = int(np.argmax(proba))
            classes = self._classifier["clf"].classes_
            pred_class = int(classes[best_idx])
            attack_probability = float(proba[best_idx])
            if pred_class != 0:  # not 'normal'
                attack_category = LABEL_MAP_INV.get(pred_class, "unknown")
            else:
                attack_category = "normal"

        # Feature contributions (importance × standardized feature deviation)
        feature_contributions = self._compute_feature_contributions(feats)

        return {
            "anomaly_score": anomaly_score,
            "attack_category": attack_category,
            "attack_probability": attack_probability,
            "feature_contributions": feature_contributions,
            "model_version": self._metadata.get("version", "untrained"),
        }

    def _heuristic_only(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback when model files are not yet trained."""
        feats = engineer_features(event)
        anomaly_score = 0.1 - (
            feats["failed_attempts_window"] * 0.005
            + feats["multi_account"] * 0.1
            + feats["high_frequency"] * 0.1
            + feats["unusual_hour"] * 0.05
        )
        return {
            "anomaly_score": max(-0.5, anomaly_score),
            "attack_category": None,
            "attack_probability": None,
            "feature_contributions": self._compute_feature_contributions(feats),
            "model_version": "heuristic_v0",
        }

    def _compute_feature_contributions(self, feats: Dict[str, float]) -> Dict[str, float]:
        """
        Compute interpretable per-feature contributions.
        Uses RF feature importances weighted by standardized deviation from mean.
        """
        if self._classifier is not None:
            importances = self._classifier["clf"].feature_importances_
            scale = getattr(self._scaler, "scale_", None)
            mean = getattr(self._scaler, "mean_", None)
            contributions = {}
            for i, col in enumerate(FEATURE_COLUMNS):
                val = feats.get(col, 0.0)
                if scale is not None and mean is not None and scale[i] > 1e-6:
                    z = abs((val - mean[i]) / scale[i])
                else:
                    z = abs(val)
                contributions[col] = round(float(importances[i] * z), 4)
        else:
            contributions = {k: round(float(abs(v)), 4) for k, v in feats.items()}
        return contributions

    @property
    def metadata(self) -> Dict[str, Any]:
        return self._metadata

    @property
    def is_loaded(self) -> bool:
        return self._loaded


# Module-level singleton
model_manager = ModelManager()
