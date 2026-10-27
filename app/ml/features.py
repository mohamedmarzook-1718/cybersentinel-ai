"""
Feature engineering for security events.
Computes ML-ready features from raw event data.
No future information is used (no look-ahead).
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from typing import List, Dict, Any


FEATURE_COLUMNS = [
    "failed_attempts_window",
    "distinct_accounts_targeted",
    "request_frequency",
    "hour_of_day",
    "is_failure",
    "is_success",
    "is_lockout",
    "failure_rate_proxy",
    "high_frequency",
    "unusual_hour",
    "multi_account",
    "bytes_ratio",
    "duration_norm",
]


def _safe_float(val, default=0.0) -> float:
    try:
        v = float(val)
        return v if np.isfinite(v) else default
    except (TypeError, ValueError):
        return default


def engineer_features(event: Dict[str, Any]) -> Dict[str, float]:
    """
    Compute feature vector from a single event dict.
    Returns a dict with keys matching FEATURE_COLUMNS.
    """
    failed = _safe_float(event.get("failed_attempts_window"), 0)
    distinct = _safe_float(event.get("distinct_accounts_targeted"), 1)
    freq = _safe_float(event.get("request_frequency"), 1.0)
    hour = _safe_float(event.get("hour_of_day"), 12)

    login_result = str(event.get("login_result") or "").lower()
    is_failure = 1.0 if login_result == "failure" else 0.0
    is_success = 1.0 if login_result == "success" else 0.0
    is_lockout = 1.0 if login_result == "lockout" else 0.0

    # Failure rate proxy: ratio of failures to total attempts in window
    total_attempts = failed + 1  # +1 for current event
    failure_rate_proxy = min(failed / total_attempts, 1.0)

    # Boolean indicator features
    high_frequency = 1.0 if freq > 10.0 else 0.0
    unusual_hour = 1.0 if hour < 6 or hour > 22 else 0.0
    multi_account = 1.0 if distinct > 3 else 0.0

    # Network features (optional)
    bytes_sent = _safe_float(event.get("bytes_sent"), 0)
    bytes_recv = _safe_float(event.get("bytes_received"), 0)
    total_bytes = bytes_sent + bytes_recv
    bytes_ratio = bytes_sent / total_bytes if total_bytes > 0 else 0.5
    duration = _safe_float(event.get("duration"), 0)
    duration_norm = min(duration / 3600.0, 1.0)  # normalise to 1h cap

    return {
        "failed_attempts_window": failed,
        "distinct_accounts_targeted": distinct,
        "request_frequency": freq,
        "hour_of_day": hour,
        "is_failure": is_failure,
        "is_success": is_success,
        "is_lockout": is_lockout,
        "failure_rate_proxy": failure_rate_proxy,
        "high_frequency": high_frequency,
        "unusual_hour": unusual_hour,
        "multi_account": multi_account,
        "bytes_ratio": bytes_ratio,
        "duration_norm": duration_norm,
    }


def events_to_dataframe(events: List[Dict[str, Any]]) -> pd.DataFrame:
    """Convert a list of event dicts to a feature DataFrame."""
    rows = [engineer_features(e) for e in events]
    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    df.fillna(0.0, inplace=True)
    return df


def compute_risk_score(
    anomaly_score: float,
    attack_probability: float | None,
    event: Dict[str, Any],
    thresholds: Dict[str, int] | None = None,
    attack_category: str | None = None,
) -> tuple[float, str]:
    """
    Compute an interpretable risk score (0-100) by combining:
    - Anomaly score from Isolation Forest (normalized deviation from baseline)
    - Attack classification probability (if classified as attack)
    - Heuristic rule contributions

    Returns (risk_score, risk_level).
    These three components are clearly distinct; do not conflate them.
    """
    thresholds = thresholds or {"low": 25, "medium": 50, "high": 75}

    # Anomaly contribution (0-40 pts)
    # IF score is typically negative; more negative = more anomalous.
    # Normal baseline events score around >= -0.42.
    if anomaly_score < -0.42:
        anomaly_contrib = min(40.0, (-0.42 - anomaly_score) / 0.20 * 40.0)
    else:
        anomaly_contrib = 0.0

    # Classifier contribution (0-35 pts)
    # Only award points if classified as an attack vector
    if attack_category and attack_category != "normal" and attack_probability is not None:
        clf_contrib = min(35.0, attack_probability * 35.0)
    else:
        clf_contrib = 0.0

    # Heuristic & Early Warning progression contribution (0-25 pts)
    rule_pts = 0.0
    feats = engineer_features(event)
    failed = feats["failed_attempts_window"]
    distinct = feats["distinct_accounts_targeted"]
    freq = feats["request_frequency"]

    if failed >= 10:
        rule_pts += 10.0
    elif failed >= 5:
        rule_pts += 6.0
    elif failed >= 2:
        rule_pts += 3.0  # Early warning: preliminary failure accumulation

    if feats["multi_account"] or distinct >= 5:
        rule_pts += 6.0
    elif distinct >= 2:
        rule_pts += 3.0  # Early warning: horizontal account probing

    if feats["high_frequency"] or freq > 15.0:
        rule_pts += 5.0
    elif freq >= 3.0 and feats["is_failure"]:
        rule_pts += 2.0  # Early warning: elevated auth velocity

    if feats["unusual_hour"] and feats["is_failure"]:
        rule_pts += 3.0
    if feats["is_lockout"]:
        rule_pts += 3.0
    rule_contrib = min(25.0, rule_pts)

    risk_score = anomaly_contrib + clf_contrib + rule_contrib

    # Early Warning Floor:
    # If 2+ failures or 2+ distinct targets are observed with a failed attempt,
    # elevate to at least Medium / Early Warning (>= 30.0) to prevent silent probing.
    if (failed >= 2 or distinct >= 2) and feats["is_failure"]:
        risk_score = max(risk_score, 30.0)

    risk_score = max(0.0, min(100.0, risk_score))

    if risk_score >= thresholds["high"]:
        level = "Critical"
    elif risk_score >= thresholds["medium"]:
        level = "High"
    elif risk_score >= thresholds["low"]:
        level = "Medium"
    else:
        level = "Low"

    return round(risk_score, 2), level
