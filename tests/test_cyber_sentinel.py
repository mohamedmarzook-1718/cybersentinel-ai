"""Comprehensive test suite for CyberSentinel AI platform.

Covers:
- All 6 core test scenarios specified in project audit
- ML model training without data leakage
- Inference, feature engineering, and Explainable AI (XAI)
- REST API endpoints: Auth, Events, Alerts, Dashboard, ML, Chat, CSV, Settings
- Database transactions, alert triage, and audit logging
"""
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.ml.model_manager import model_manager
from app.ml.features import engineer_features, compute_risk_score, FEATURE_COLUMNS
from app.ml.explainer import generate_explanation, answer_faq
from app.ml.data_generator import generate_dataset

client = TestClient(app)


@pytest.fixture(scope="session", autouse=True)
def setup_models():
    """Ensure database schema is ready and models are trained before running tests."""
    from app.database import init_db, SessionLocal
    from app.routers.auth import seed_demo_users_internal
    init_db()
    with SessionLocal() as db:
        seed_demo_users_internal(db)
    data = generate_dataset(n_normal=250, n_per_attack=35)
    model_manager.train(data)
    assert model_manager.is_loaded


# ── SECTION 1: CORE AI/ML SPECIFICATION TEST CASES ────────────────────────────

def test_case_1_normal_login():
    """Test Case 1: 1 failed login followed by a successful login.

    Expected: Normal / benign behavior, Low risk, no false attack detection.
    """
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_identifier": "test_employee",
        "source_ip": "192.168.1.50",
        "login_result": "success",
        "event_type": "auth",
        "failed_attempts_window": 1,
        "distinct_accounts_targeted": 1,
        "request_frequency": 1.2,
        "hour_of_day": 10,
    }
    response = client.post("/api/events/predict", json=event)
    assert response.status_code == 200
    data = response.json()

    assert data["risk_level"] == "Low"
    assert data["risk_score"] < 25.0
    assert data["attack_category"] in (None, "normal")


def test_case_2_repeated_failed_logins():
    """Test Case 2: Multiple failed login attempts within a short time.

    Expected: Brute force detection, High or Critical risk level, actionable mitigation.
    """
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_identifier": "admin",
        "source_ip": "198.51.100.88",
        "login_result": "failure",
        "event_type": "auth",
        "failed_attempts_window": 35,
        "distinct_accounts_targeted": 1,
        "request_frequency": 45.0,
        "hour_of_day": 2,
    }
    response = client.post("/api/events/predict", json=event)
    assert response.status_code == 200
    data = response.json()

    assert data["risk_level"] in ("High", "Critical")
    assert data["risk_score"] >= 50.0
    assert data["attack_category"] == "brute_force"
    assert data["attack_probability"] is not None
    assert data["attack_probability"] > 0.70
    assert any("lockout" in r.lower() or "mfa" in r.lower() for r in data["recommended_actions"])


def test_case_3_suspicious_login_activity():
    """Test Case 3: Targeting many distinct accounts at unusual hours.

    Expected: Credential stuffing pattern detection with high risk score.
    """
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_identifier": "target_account",
        "source_ip": "203.0.113.45",
        "login_result": "failure",
        "event_type": "auth",
        "failed_attempts_window": 8,
        "distinct_accounts_targeted": 25,
        "request_frequency": 20.0,
        "hour_of_day": 3,
    }
    response = client.post("/api/events/predict", json=event)
    assert response.status_code == 200
    data = response.json()

    assert data["risk_level"] in ("High", "Critical")
    assert data["attack_category"] == "credential_stuffing"
    assert len(data["explanation"]) > 20


def test_case_4_suspicious_network_traffic():
    """Test Case 4: Massive data transfer outside business hours.

    Expected: Anomalous traffic / data exfiltration detection.
    """
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_identifier": "backup_service",
        "source_ip": "10.0.0.99",
        "login_result": "success",
        "event_type": "network",
        "failed_attempts_window": 0,
        "distinct_accounts_targeted": 1,
        "request_frequency": 250.0,
        "hour_of_day": 4,
        "duration": 1800.0,
        "bytes_sent": 35000000.0,
        "packets": 25000,
        "destination_port": 8443,
    }
    response = client.post("/api/events/predict", json=event)
    assert response.status_code == 200
    data = response.json()

    assert data["risk_level"] in ("High", "Critical")
    assert data["attack_category"] == "anomalous_traffic"


def test_case_5_normal_but_unusual_activity():
    """Test Case 5: Legitimate user logging in late at night.

    Expected: False-positive prevention: remains Low or Medium risk, not classified as an attack.
    """
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_identifier": "night_operator",
        "source_ip": "192.168.1.120",
        "login_result": "success",
        "event_type": "auth",
        "failed_attempts_window": 0,
        "distinct_accounts_targeted": 1,
        "request_frequency": 1.0,
        "hour_of_day": 23,
    }
    response = client.post("/api/events/predict", json=event)
    assert response.status_code == 200
    data = response.json()

    assert data["risk_level"] in ("Low", "Medium")
    assert data["attack_category"] in (None, "normal")


def test_case_6_invalid_or_missing_data():
    """Test Case 6: Negative values, malformed inputs, missing required fields.

    Expected: Returns 422 Unprocessable Entity gracefully without crashing.
    """
    # Negative failed attempts window
    invalid_event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "failed_attempts_window": -10,
    }
    res1 = client.post("/api/events/predict", json=invalid_event)
    assert res1.status_code == 422

    # Invalid hour (>23)
    invalid_hour = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hour_of_day": 48,
    }
    res2 = client.post("/api/events/predict", json=invalid_hour)
    assert res2.status_code == 422

    # Completely empty body
    res3 = client.post("/api/events/predict", json={})
    assert res3.status_code == 422


# ── SECTION 2: AI / ML PIPELINE INTEGRITY ─────────────────────────────────────

def test_feature_engineering_consistency():
    """Verify feature vector length, columns, and numeric stability."""
    raw = {
        "failed_attempts_window": "5",
        "distinct_accounts_targeted": 2,
        "request_frequency": "12.5",
        "hour_of_day": 14,
        "login_result": "failure",
        "bytes_sent": 1000,
        "bytes_received": 2000,
        "duration": 120,
    }
    feats = engineer_features(raw)
    assert len(feats) == len(FEATURE_COLUMNS)
    for col in FEATURE_COLUMNS:
        assert col in feats
        assert isinstance(feats[col], (int, float))
    assert feats["is_failure"] == 1.0
    assert feats["is_success"] == 0.0


def test_model_training_and_metrics():
    """Verify model manager trains cleanly, computes metrics, and outputs confusion matrix."""
    meta = model_manager.metadata
    assert meta["anomaly_model"] == "IsolationForest"
    assert meta["classifier_model"] == "RandomForestClassifier"
    assert "metrics" in meta
    metrics = meta["metrics"]
    assert metrics["accuracy"] >= 0.95
    assert metrics["f1_macro"] >= 0.95
    assert len(metrics["confusion_matrix"]) == 5


# ── SECTION 3: API ENDPOINTS & WORKFLOWS ──────────────────────────────────────

def test_auth_login_and_token():
    """Test admin and analyst authentication."""
    res_admin = client.post("/api/auth/token", data={"username": "admin", "password": "Admin@CyberSentinel2024"})
    assert res_admin.status_code == 200
    token_admin = res_admin.json()["access_token"]
    assert res_admin.json()["role"] == "admin"

    res_analyst = client.post("/api/auth/token", data={"username": "analyst", "password": "Analyst@CyberSentinel2024"})
    assert res_analyst.status_code == 200
    assert res_analyst.json()["role"] == "analyst"

    # Profile check with token
    res_me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token_admin}"})
    assert res_me.status_code == 200
    assert res_me.json()["username"] == "admin"


def test_event_ingestion_and_auto_alert():
    """Test submitting an attack event triggers DB persistence and automated alert generation."""
    attack_event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_identifier": "compromised_svc",
        "source_ip": "198.51.100.99",
        "login_result": "failure",
        "event_type": "auth",
        "failed_attempts_window": 40,
        "distinct_accounts_targeted": 1,
        "request_frequency": 50.0,
        "hour_of_day": 2,
        "source": "automated_test",
    }
    res = client.post("/api/events", json=attack_event)
    assert res.status_code == 201
    created_event = res.json()
    assert created_event["risk_level"] in ("High", "Critical")

    # Verify alert was created
    alerts_res = client.get("/api/alerts?severity=Critical")
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()["items"]
    assert len(alerts) > 0


def test_alert_triage_workflow():
    """Test incident triage lifecycle: open -> in_progress -> resolved."""
    # Obtain analyst credentials
    auth_res = client.post("/api/auth/token", data={"username": "analyst", "password": "Analyst@CyberSentinel2024"})
    assert auth_res.status_code == 200
    headers = {"Authorization": f"Bearer {auth_res.json()['access_token']}"}

    alerts = client.get("/api/alerts?page_size=1", headers=headers).json()["items"]
    assert len(alerts) > 0
    alert_id = alerts[0]["id"]

    # 1. Inspect XAI explanation
    xai_res = client.get(f"/api/alerts/{alert_id}/explanation", headers=headers)
    assert xai_res.status_code == 200
    xai = xai_res.json()
    assert "summary" in xai
    assert len(xai["recommendations"]) > 0

    # 2. Update status to in_progress
    patch_res = client.patch(
        f"/api/alerts/{alert_id}",
        json={"status": "in_progress", "notes": "Investigating source IP"},
        headers=headers,
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "in_progress"

    # 3. Resolve alert
    resolve_res = client.patch(
        f"/api/alerts/{alert_id}",
        json={"status": "resolved"},
        headers=headers,
    )
    assert resolve_res.status_code == 200
    assert resolve_res.json()["status"] == "resolved"
    assert resolve_res.json()["resolved_at"] is not None


def test_ai_copilot_bilingual():
    """Test security chatbot in both English and Tamil."""
    # English FAQ query
    res_en = client.post("/api/chat", json={"message": "What is credential stuffing?", "language": "en"})
    assert res_en.status_code == 200
    data_en = res_en.json()
    assert "credential stuffing" in data_en["reply"].lower()
    assert data_en["source"] == "faq"

    # Tamil FAQ query
    res_ta = client.post("/api/chat", json={"message": "brute force என்றால் என்ன?", "language": "ta"})
    assert res_ta.status_code == 200
    data_ta = res_ta.json()
    assert len(data_ta["reply"]) > 20
    assert data_ta["language"] == "ta"


def test_dashboard_stats():
    """Test dashboard aggregation endpoint returns valid schema and counts."""
    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    stats = res.json()
    assert stats["total_events"] >= 0
    assert "risk_distribution" in stats
    assert "category_distribution" in stats
    assert "anomaly_trend" in stats
    assert stats["model_status"]["is_loaded"] is True


def test_settings_threshold_update():
    """Test updating risk engine thresholds with admin credentials."""
    # Obtain admin token
    admin_res = client.post("/api/auth/token", data={"username": "admin", "password": "Admin@CyberSentinel2024"})
    assert admin_res.status_code == 200
    admin_headers = {"Authorization": f"Bearer {admin_res.json()['access_token']}"}

    res = client.patch("/api/settings", json={"risk_threshold_low": 20, "risk_threshold_high": 80}, headers=admin_headers)
    assert res.status_code == 200
    settings = res.json()
    assert settings["risk_threshold_low"] == 20
    assert settings["risk_threshold_high"] == 80

    # Restore default
    client.patch("/api/settings", json={"risk_threshold_low": 25, "risk_threshold_high": 75}, headers=admin_headers)


def test_rbac_access_control():
    """Verify Role-Based Access Control on sensitive endpoints."""
    # Unauthenticated attempts to protected endpoints
    assert client.get("/api/audit").status_code == 401
    assert client.patch("/api/settings", json={"risk_threshold_low": 20}).status_code == 401
    assert client.post("/api/ml/train").status_code == 401

    # Analyst attempt on admin-only endpoints
    analyst_res = client.post("/api/auth/token", data={"username": "analyst", "password": "Analyst@CyberSentinel2024"})
    analyst_headers = {"Authorization": f"Bearer {analyst_res.json()['access_token']}"}

    # Settings PATCH requires admin
    assert client.patch("/api/settings", json={"risk_threshold_low": 20}, headers=analyst_headers).status_code == 403
    # ML retrain requires admin
    assert client.post("/api/ml/train", headers=analyst_headers).status_code == 403
    # Audit log read permitted for analyst
    assert client.get("/api/audit", headers=analyst_headers).status_code == 200


def test_csv_upload_workflow():
    """Verify batch CSV ingestion with threat scoring and audit recording."""
    analyst_res = client.post("/api/auth/token", data={"username": "analyst", "password": "Analyst@CyberSentinel2024"})
    analyst_headers = {"Authorization": f"Bearer {analyst_res.json()['access_token']}"}

    csv_data = (
        "timestamp,user_identifier,source_ip,login_result,event_type,failed_attempts_window,distinct_accounts_targeted,request_frequency,hour_of_day\n"
        "2026-10-27T10:00:00,analyst_test,192.168.1.100,success,auth,0,1,1.0,10\n"
        "2026-10-27T10:01:00,attacker,198.51.100.22,failure,auth,25,1,30.0,2\n"
    )

    files = {"file": ("test_logs.csv", csv_data, "text/csv")}
    upload_res = client.post("/api/events/upload-csv", files=files, headers=analyst_headers)
    assert upload_res.status_code == 200
    result = upload_res.json()
    assert result["accepted"] == 2
    assert result["rejected"] == 0

    # Verify audit log recorded action
    audit_res = client.get("/api/audit", headers=analyst_headers)
    assert audit_res.status_code == 200
    audit_entries = audit_res.json()
    assert any(e["action"] == "csv_upload" for e in audit_entries)


def test_early_warning_probing_detection():
    """Verify early warning detection on subtle reconnaissance before threshold saturation."""
    probe_event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_identifier": "target_recon",
        "source_ip": "198.51.100.80",
        "login_result": "failure",
        "event_type": "auth",
        "failed_attempts_window": 2,
        "distinct_accounts_targeted": 2,
        "request_frequency": 1.5,
        "hour_of_day": 14,
    }
    res = client.post("/api/events/predict", json=probe_event)
    assert res.status_code == 200
    data = res.json()

    assert data["risk_score"] >= 30.0  # Early warning floor
    assert data["risk_level"] == "Medium"
    assert data["early_warning_stage"] == "Stage 1: Early Warning / Probing"
    assert len(data["early_warning_indicators"]) > 0
    assert any("failure" in ind.lower() or "probing" in ind.lower() for ind in data["early_warning_indicators"])


def test_rolling_sequence_db_correlation():
    """Verify database-backed sequence correlation for streaming events with 0 pre-computed window."""
    test_ip = "198.51.100.111"
    now_ts = datetime.now(timezone.utc).isoformat()

    # Ingest 1st failed attempt
    res1 = client.post("/api/events", json={
        "timestamp": now_ts,
        "user_identifier": "emp_01",
        "source_ip": test_ip,
        "login_result": "failure",
        "event_type": "auth",
        "failed_attempts_window": 0,
        "distinct_accounts_targeted": 1,
    })
    assert res1.status_code == 201
    assert res1.json()["failed_attempts_window"] >= 1

    # Ingest 2nd failed attempt from same source IP
    res2 = client.post("/api/events", json={
        "timestamp": now_ts,
        "user_identifier": "emp_02",
        "source_ip": test_ip,
        "login_result": "failure",
        "event_type": "auth",
        "failed_attempts_window": 0,
        "distinct_accounts_targeted": 1,
    })
    assert res2.status_code == 201
    assert res2.json()["failed_attempts_window"] >= 2
    assert res2.json()["distinct_accounts_targeted"] >= 1


def test_prevention_recommendations_safeguards():
    """Verify mitigation recommendations guard disruptive actions behind explicit authorization."""
    from app.ml.explainer import DEFENSIVE_RECOMMENDATIONS

    for category, recommendations in DEFENSIVE_RECOMMENDATIONS.items():
        assert len(recommendations) > 0
        # Check that disruptive actions are guarded
        disruptive = [r for r in recommendations if any(kw in r.lower() for kw in ("block", "lockout", "quarantine", "reset"))]
        for act in disruptive:
            assert "[REQUIRES AUTHORIZATION]" in act, f"Disruptive action '{act}' lacks explicit authorization guard"


def test_realistic_borderline_benchmark():
    """Empirically evaluate model on borderline samples, verifying false-positive resistance and early detection."""
    from app.ml.early_warning import evaluate_early_warning

    # Borderline case: legitimate employee mistyping password once during normal hours
    benign_typo = {
        "failed_attempts_window": 1,
        "distinct_accounts_targeted": 1,
        "request_frequency": 0.5,
        "hour_of_day": 10,
        "login_result": "success",
        "bytes_sent": 2000,
        "packets": 20,
    }
    pred_benign = client.post("/api/events/predict", json={
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **benign_typo
    }).json()
    assert pred_benign["risk_level"] == "Low"
    assert pred_benign["risk_score"] < 25.0

    # Borderline case: Low-and-slow brute force
    low_slow = {
        "failed_attempts_window": 4,
        "distinct_accounts_targeted": 1,
        "request_frequency": 0.5,
        "hour_of_day": 3,
        "login_result": "failure",
    }
    pred_low_slow = client.post("/api/events/predict", json={
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **low_slow
    }).json()
    assert pred_low_slow["early_warning_stage"] in ("Stage 1: Early Warning / Probing", "Stage 2: Active Escalation")
    assert pred_low_slow["risk_score"] >= 30.0


