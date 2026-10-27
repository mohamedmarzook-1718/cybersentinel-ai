"""
Early Warning and Threat Escalation Assessment Engine.

Provides:
- Rolling sequence correlation from database telemetry
- Multi-stage threat progression analysis (Baseline -> Recon/Probing -> Active Escalation -> Critical)
- Early warning indicator detection to identify threats before threshold saturation
- Separation of proactive non-disruptive safeguards from authorized disruptive actions
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func

# Progression Stages
STAGE_0_BASELINE = "Stage 0: Normal Baseline"
STAGE_1_RECON_PROBING = "Stage 1: Early Warning / Probing"
STAGE_2_ACTIVE_ESCALATION = "Stage 2: Active Escalation"
STAGE_3_CRITICAL_SATURATION = "Stage 3: Critical Threat"


def correlate_event_history(
    db: Session,
    event_dict: Dict[str, Any],
    window_minutes: int = 15,
) -> Dict[str, Any]:
    """
    Query recent event telemetry from the database to augment point-in-time events
    with true rolling sequence history (failure velocity, distinct targets).

    Prevents individual single-event logs from hiding cumulative attack progression.
    """
    from app.models.event import SecurityEvent

    source_ip = event_dict.get("source_ip")
    user_id = event_dict.get("user_identifier")
    ts = event_dict.get("timestamp")

    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            ts = datetime.now(timezone.utc)
    elif not isinstance(ts, datetime):
        ts = datetime.now(timezone.utc)

    window_start = ts - timedelta(minutes=window_minutes)

    rolling_failures = 0
    rolling_distinct_users = 1
    recent_event_count = 0

    if source_ip and db:
        try:
            # Query count of failed attempts in rolling window
            fail_query = (
                db.query(func.count(SecurityEvent.id))
                .filter(SecurityEvent.source_ip == source_ip)
                .filter(SecurityEvent.timestamp >= window_start)
                .filter(SecurityEvent.timestamp <= ts)
                .filter(SecurityEvent.login_result.in_(["failure", "lockout"]))
            )
            rolling_failures = fail_query.scalar() or 0

            # Query count of distinct accounts targeted in rolling window
            user_query = (
                db.query(func.count(func.distinct(SecurityEvent.user_identifier)))
                .filter(SecurityEvent.source_ip == source_ip)
                .filter(SecurityEvent.timestamp >= window_start)
                .filter(SecurityEvent.timestamp <= ts)
                .filter(SecurityEvent.user_identifier.isnot(None))
            )
            rolling_distinct_users = max(1, user_query.scalar() or 1)

            # Query total events for frequency calculation
            total_events_query = (
                db.query(func.count(SecurityEvent.id))
                .filter(SecurityEvent.source_ip == source_ip)
                .filter(SecurityEvent.timestamp >= window_start)
                .filter(SecurityEvent.timestamp <= ts)
            )
            recent_event_count = total_events_query.scalar() or 0
        except Exception:
            # Fall back to payload values if DB query is unavailable
            pass

    # Augment current event with historical sequence context
    current_result = str(event_dict.get("login_result") or "").lower()
    if current_result in ("failure", "lockout"):
        rolling_failures += 1

    payload_failed = int(event_dict.get("failed_attempts_window") or 0)
    payload_distinct = int(event_dict.get("distinct_accounts_targeted") or 1)
    payload_freq = float(event_dict.get("request_frequency") or 1.0)

    computed_freq = max(payload_freq, round(recent_event_count / max(1.0, window_minutes), 2))

    augmented = dict(event_dict)
    augmented["failed_attempts_window"] = max(payload_failed, rolling_failures)
    augmented["distinct_accounts_targeted"] = max(payload_distinct, rolling_distinct_users)
    augmented["request_frequency"] = max(payload_freq, computed_freq)
    augmented["historical_window_minutes"] = window_minutes
    augmented["historical_event_count"] = recent_event_count

    return augmented


def evaluate_early_warning(
    event: Dict[str, Any],
    anomaly_score: float,
    attack_category: Optional[str] = None,
    attack_probability: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Perform multi-stage early warning risk assessment.

    Evaluates whether the event sequence exhibits early reconnaissance or probing
    before escalating to full threshold saturation.
    """
    failed = int(event.get("failed_attempts_window") or 0)
    distinct = int(event.get("distinct_accounts_targeted") or 1)
    freq = float(event.get("request_frequency") or 1.0)
    hour = event.get("hour_of_day")
    login_result = str(event.get("login_result") or "").lower()
    bytes_sent = float(event.get("bytes_sent") or 0.0)

    early_indicators: List[str] = []
    active_indicators: List[str] = []

    # Early Warning Signals (Stage 1)
    if 2 <= failed <= 4:
        early_indicators.append(
            f"Early failure accumulation: {failed} failed login attempt(s) within the rolling window."
        )
    if 2 <= distinct <= 4:
        early_indicators.append(
            f"Horizontal account probing: {distinct} distinct usernames targeted from this source."
        )
    if hour is not None and (int(hour) < 6 or int(hour) > 22) and login_result in ("failure", "lockout"):
        early_indicators.append(
            f"Off-hours authentication failure at hour {int(hour):02d}:xx (unusual operational time)."
        )
    if 3.0 <= freq <= 15.0 and login_result in ("failure", "lockout"):
        early_indicators.append(
            f"Elevated authentication velocity: {freq:.1f} requests/min observed."
        )

    # Escalated Signals (Stage 2 & 3)
    if failed >= 5:
        active_indicators.append(
            f"Active credential assault: {failed} failed attempts exceeds brute-force thresholds."
        )
    if distinct >= 5:
        active_indicators.append(
            f"Credential stuffing in progress: {distinct} accounts systematically targeted."
        )
    if freq > 15.0:
        active_indicators.append(
            f"High-frequency request surge: {freq:.1f} req/min indicates automated tool execution."
        )
    if bytes_sent >= 1_000_000:
        active_indicators.append(
            f"Elevated outbound data transfer: {bytes_sent / 1_000_000:.2f} MB exfiltration potential."
        )
    if login_result == "lockout":
        active_indicators.append(
            "Account lockout triggered by excessive sequential failures."
        )

    # Determine Threat Stage and Escalation Potential
    if (
        failed >= 15
        or distinct >= 10
        or bytes_sent >= 5_000_000
        or login_result == "lockout"
        or (attack_category in ("brute_force", "anomalous_traffic") and (attack_probability or 0) >= 0.85 and failed >= 10)
    ):
        stage = STAGE_3_CRITICAL_SATURATION
        escalation_potential = "Critical"
        lead_time = "Imminent saturation / compromise: immediate containment required"
        early_warning_risk_bonus = 0.0  # Already captured in high severity
    elif (
        failed >= 5
        or distinct >= 5
        or freq > 15.0
        or (attack_category not in (None, "normal") and (attack_probability or 0) >= 0.70)
    ):
        stage = STAGE_2_ACTIVE_ESCALATION
        escalation_potential = "High"
        lead_time = "Active attack escalation in progress: prevent service disruption"
        early_warning_risk_bonus = 5.0
    elif len(early_indicators) > 0 or (anomaly_score < -0.42 and login_result in ("failure", "lockout")):
        stage = STAGE_1_RECON_PROBING
        escalation_potential = "Moderate"
        lead_time = "Early intervention available: apply proactive safeguards before threshold breach"
        early_warning_risk_bonus = 12.0
    else:
        stage = STAGE_0_BASELINE
        escalation_potential = "Low"
        lead_time = "Routine operational traffic: standard continuous monitoring"
        early_warning_risk_bonus = 0.0

    # Safeguards: Proactive vs Disruptive
    proactive_safeguards = [
        "Present progressive CAPTCHA or cryptographic proof-of-work on subsequent authentication requests.",
        "Trigger step-up Multi-Factor Authentication (MFA) challenge for the targeted identity.",
        "Apply adaptive per-IP rate-limiting to throttle request velocity.",
        "Enable high-fidelity security logging and prioritize event in SOC triage queue.",
    ]

    disruptive_actions = [
        "[REQUIRES AUTHORIZATION] Temporarily suspend user account credentials (requires analyst confirmation).",
        "[REQUIRES AUTHORIZATION] Block source IP at perimeter edge firewall (requires analyst confirmation).",
        "[REQUIRES AUTHORIZATION] Quarantine network interface or host segment (requires analyst confirmation).",
    ]

    return {
        "stage": stage,
        "escalation_potential": escalation_potential,
        "lead_time": lead_time,
        "early_indicators": early_indicators,
        "active_indicators": active_indicators,
        "early_warning_risk_bonus": early_warning_risk_bonus,
        "proactive_safeguards": proactive_safeguards,
        "disruptive_actions": disruptive_actions,
    }
