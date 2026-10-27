"""
Explainable AI module.
Generates plain-language explanations for risk assessments.
Never fabricates feature contributions — only uses model-derived values.
Always provides a fallback explanation even without an LLM API.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


ATTACK_DESCRIPTIONS = {
    "brute_force": "A brute-force attack systematically tries many passwords against one or more accounts.",
    "credential_stuffing": "Credential stuffing uses lists of leaked username/password pairs to attempt logins across many accounts.",
    "port_scan": "Port scanning probes many network ports to identify open services and potential vulnerabilities.",
    "anomalous_traffic": "Anomalous traffic exhibits unusual data volumes, timing, or patterns that deviate from baseline behavior.",
}

DEFENSIVE_RECOMMENDATIONS = {
    "brute_force": [
        "Enforce step-up Multi-Factor Authentication (MFA) challenge on affected accounts.",
        "Present progressive CAPTCHA on subsequent authentication requests from this source IP.",
        "Review rate-limiting rules on authentication endpoints.",
        "[REQUIRES AUTHORIZATION] Enable account lockout after repeated failures (requires analyst confirmation).",
        "[REQUIRES AUTHORIZATION] Block or throttle the source IP after confirmation of attack (requires analyst confirmation).",
        "Alert affected users and advise proactive password change.",
    ],
    "credential_stuffing": [
        "Enable MFA immediately on all targeted accounts.",
        "Audit accounts for successful logins and invalidate compromised sessions.",
        "Implement progressive CAPTCHA or bot fingerprinting on login pages.",
        "[REQUIRES AUTHORIZATION] Force global password reset for targeted accounts (requires analyst confirmation).",
        "[REQUIRES AUTHORIZATION] Null-route suspicious ASN / source subnet at border router (requires analyst confirmation).",
        "Check breach databases (e.g., HaveIBeenPwned) for exposed credentials.",
    ],
    "port_scan": [
        "Review firewall rules and close unnecessary open ports.",
        "Enable port-scan detection on IDS/IPS systems.",
        "Log and investigate the scanning source IP.",
        "Patch any exposed services identified during the scan period.",
        "[REQUIRES AUTHORIZATION] Apply dynamic firewall block rule for scanning source IP (requires analyst confirmation).",
    ],
    "anomalous_traffic": [
        "Review outbound data transfer logs for potential data exfiltration.",
        "Check if the involved account has been compromised.",
        "Enforce data loss prevention (DLP) egress inspection policies.",
        "[REQUIRES AUTHORIZATION] Quarantine host or throttle network interface (requires analyst confirmation).",
        "Escalate to incident response team for forensic capture.",
    ],
    "default": [
        "Review the source IP and user activity across recent audit logs.",
        "Confirm whether the detected behavior matches a known business process.",
        "If suspicious, escalate to the security team for manual investigation.",
        "Ensure logging and alerting is enabled on affected systems.",
        "[REQUIRES AUTHORIZATION] Block or throttle the source IP (requires analyst confirmation).",
    ],
}


def generate_explanation(
    event: Dict[str, Any],
    anomaly_score: float,
    risk_score: float,
    risk_level: str,
    attack_category: Optional[str],
    attack_probability: Optional[float],
    feature_contributions: Dict[str, float],
    is_synthetic: bool,
    model_version: str,
) -> Dict[str, Any]:
    """
    Generate a structured, plain-language explanation.
    Clearly separates observed facts, model inferences, and recommendations.
    """

    # ── Observed facts ────────────────────────────────────────────────────────
    facts: List[str] = []
    failed = event.get("failed_attempts_window", 0)
    distinct = event.get("distinct_accounts_targeted", 1)
    freq = event.get("request_frequency", 1.0)
    hour = event.get("hour_of_day")
    login_result = event.get("login_result", "")

    if failed and int(failed) > 0:
        facts.append(f"Observed {int(failed)} failed login attempt(s) within the time window.")
    if distinct and int(distinct) > 3:
        facts.append(f"{int(distinct)} distinct accounts were targeted from this source.")
    if freq and float(freq) > 10:
        facts.append(f"Request frequency ({float(freq):.1f}/min) is significantly above normal thresholds.")
    if hour is not None and (int(hour) < 6 or int(hour) > 22):
        facts.append(f"Activity occurred at hour {int(hour):02d}:xx, which is outside typical business hours.")
    if login_result == "lockout":
        facts.append("An account lockout was triggered during this event.")
    if not facts:
        facts.append("No individual observable indicator exceeded normal thresholds on its own.")

    # ── Model inferences ──────────────────────────────────────────────────────
    inferences: List[str] = []

    # Anomaly score description
    if anomaly_score < -0.2:
        inferences.append(
            f"The Isolation Forest model assigned an anomaly score of {anomaly_score:.3f}, "
            "indicating the feature profile is significantly unlike typical baseline events."
        )
    elif anomaly_score < 0.0:
        inferences.append(
            f"The anomaly score ({anomaly_score:.3f}) suggests a mild deviation from baseline behavior."
        )
    else:
        inferences.append(
            f"The anomaly score ({anomaly_score:.3f}) is within the normal range; "
            "risk elevation is driven primarily by rule-based heuristics."
        )

    if attack_category and attack_probability is not None:
        inferences.append(
            f"The Random Forest classifier suggests this may be a "
            f"'{attack_category.replace('_', ' ')}' pattern "
            f"(confidence: {attack_probability * 100:.1f}%). "
            f"{ATTACK_DESCRIPTIONS.get(attack_category, '')}"
        )
    elif attack_category is None:
        inferences.append(
            "No attack category was classified. "
            "Either the classifier is not trained or the pattern resembles normal behavior."
        )

    # ── Early warning & threat escalation analysis ────────────────────────────
    from app.ml.early_warning import evaluate_early_warning
    ew = evaluate_early_warning(event, anomaly_score, attack_category, attack_probability)

    for ind in ew.get("early_indicators", []):
        facts.append(f"[Early Warning] {ind}")
    for act in ew.get("active_indicators", []):
        facts.append(f"[Escalation] {act}")

    inferences.append(
        f"Threat Progression: {ew['stage']} — {ew['lead_time']}."
    )

    # ── Top contributing features ─────────────────────────────────────────────
    top_features = sorted((feature_contributions or {}).items(), key=lambda x: abs(x[1]), reverse=True)[:4]
    if top_features:
        feat_str = ", ".join(f"{k.replace('_', ' ')} ({v:.3f})" for k, v in top_features if v != 0)
        if feat_str:
            inferences.append(f"Top contributing features to this assessment: {feat_str}.")

    # Confidence note
    confidence_note = _confidence_note(is_synthetic, model_version or "v1", attack_probability)

    # ── Recommendations ───────────────────────────────────────────────────────
    recommendations = DEFENSIVE_RECOMMENDATIONS.get(
        attack_category or "default", DEFENSIVE_RECOMMENDATIONS["default"]
    )

    # ── Summary sentence ──────────────────────────────────────────────────────
    summary = (
        f"Risk assessed as {risk_level} (score: {risk_score:.1f}/100) at {ew['stage']}. "
        f"This assessment combines anomaly detection, "
        f"{'attack classification, ' if attack_category else ''}"
        "early-warning sequence telemetry, and rule-based heuristics. "
        + confidence_note
    )

    return {
        "summary": summary,
        "observed_facts": facts,
        "model_inferences": inferences,
        "recommendations": recommendations,
        "early_warning_stage": ew["stage"],
        "early_warning_indicators": ew["early_indicators"],
        "escalation_potential": ew["escalation_potential"],
        "confidence_note": confidence_note,
        "is_synthetic": is_synthetic,
        "model_version": model_version or "v1",
    }


def _confidence_note(is_synthetic: bool, model_version: str, attack_probability: Optional[float]) -> str:
    parts = []
    if is_synthetic:
        parts.append("⚠️  This event is SYNTHETIC/demo data — results are for demonstration only.")
    if model_version and str(model_version).startswith("heuristic"):
        parts.append("Model not yet trained; scores are heuristic-only estimates.")
    elif attack_probability is not None and attack_probability < 0.6:
        parts.append(
            f"Classifier confidence is moderate ({attack_probability * 100:.0f}%); "
            "treat classification as an indicative estimate, not a confirmed identification."
        )
    return " ".join(parts) if parts else (
        "These are model-based estimates, not confirmed attack detections. "
        "Always validate findings with additional investigation."
    )


# ── Local FAQ / Chat knowledge base ───────────────────────────────────────────

FAQ_EN = {
    "brute force": (
        "A brute-force attack repeatedly tries different passwords to gain unauthorized access. "
        "Indicators include high failed login counts from a single source in a short window."
    ),
    "credential stuffing": (
        "Credential stuffing uses leaked username/password pairs from data breaches to attempt logins "
        "across many accounts simultaneously. Unlike brute force, it targets many accounts with few attempts each."
    ),
    "port scan": (
        "Port scanning probes a target host's ports to discover open services. "
        "It is often a reconnaissance step before a more targeted attack."
    ),
    "anomaly": (
        "An anomaly is a data point that significantly differs from the baseline pattern. "
        "In CyberSentinel, anomalies are detected by an Isolation Forest model trained on normal traffic."
    ),
    "risk score": (
        "The risk score (0-100) combines three signals: the anomaly score from Isolation Forest, "
        "the attack classification probability from Random Forest, and rule-based heuristics. "
        "Low=0-25, Medium=25-50, High=50-75, Critical=75-100."
    ),
    "mfa": (
        "Multi-factor authentication (MFA) requires users to verify identity with a second factor "
        "(e.g., OTP, hardware key) in addition to a password. It significantly reduces the risk of "
        "account takeover from brute-force or credential stuffing."
    ),
    "false positive": (
        "A false positive is an alert that flags normal activity as suspicious. "
        "All ML models produce some false positives. Always validate alerts before taking action."
    ),
    "isolation forest": (
        "Isolation Forest is an unsupervised anomaly detection algorithm. "
        "It isolates anomalies by randomly partitioning data; anomalies require fewer partitions to isolate."
    ),
    "random forest": (
        "Random Forest is a supervised ensemble learning algorithm that trains many decision trees "
        "and aggregates their predictions. In CyberSentinel it classifies attack categories."
    ),
    "reduce risk": (
        "To reduce cybersecurity risk: enable MFA, enforce strong password policies, apply rate limiting, "
        "keep systems patched, review firewall rules, and monitor logs regularly."
    ),
}

FAQ_TA = {
    "brute force": (
        "Brute-force தாக்குதல் என்பது அங்கீகரிக்கப்படாத அணுகலைப் பெற பல்வேறு கடவுச்சொற்களை "
        "திரும்பத் திரும்ப முயற்சிக்கும் ஒரு முறை. குறுகிய நேரத்தில் ஒரே மூலத்திலிருந்து "
        "அதிக தோல்வியடைந்த உள்நுழைவு முயற்சிகள் இதற்கான அறிகுறிகளாகும்."
    ),
    "credential stuffing": (
        "Credential stuffing என்பது தரவு மீறல்களில் கசிந்த பயனர்பெயர்/கடவுச்சொல் ஜோடிகளைப் பயன்படுத்தி "
        "பல கணக்குகளில் ஒரே நேரத்தில் உள்நுழைய முயற்சிக்கும் முறை."
    ),
    "anomaly": (
        "Anomaly என்பது அடிப்படை வடிவத்திலிருந்து கணிசமாக வேறுபடும் ஒரு தரவு புள்ளி. "
        "CyberSentinel-ல், Isolation Forest மாதிரி மூலம் anomaly-கள் கண்டறியப்படுகின்றன."
    ),
    "risk score": (
        "Risk score (0-100) மூன்று சமிக்ஞைகளை இணைக்கிறது: Isolation Forest இல் இருந்து anomaly score, "
        "Random Forest இல் இருந்து attack வகைப்பாட்டு நம்பிக்கை மற்றும் rule-based heuristics. "
        "Low=0-25, Medium=25-50, High=50-75, Critical=75-100."
    ),
    "mfa": (
        "Multi-factor authentication (MFA) என்பது கடவுச்சொல்லுக்கு கூடுதலாக இரண்டாவது காரணியை "
        "(OTP, hardware key போன்றவை) கொண்டு அடையாளத்தை சரிபார்க்க வேண்டும். "
        "இது brute-force மற்றும் credential stuffing அபாயத்தை கணிசமாக குறைக்கிறது."
    ),
    "reduce risk": (
        "Cybersecurity அபாயத்தை குறைக்க: MFA-ஐ இயக்கவும், வலுவான கடவுச்சொல் கொள்கைகளை செயல்படுத்தவும், "
        "rate limiting பயன்படுத்தவும், கணினிகளை patch செய்யவும், firewall விதிகளை சரிபார்க்கவும் "
        "மற்றும் logs-ஐ தொடர்ந்து கண்காணிக்கவும்."
    ),
}


def answer_faq(question: str, language: str = "en") -> Optional[str]:
    """Search FAQ for a matching answer. Returns None if no match found."""
    q_lower = question.lower()
    faq = FAQ_TA if language == "ta" else FAQ_EN
    for keyword, answer in faq.items():
        if keyword in q_lower:
            return answer
    return None
