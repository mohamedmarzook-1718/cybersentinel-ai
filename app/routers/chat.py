"""AI Security Copilot chat router with bilingual English and Tamil support."""
from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.alert import Alert
from app.schemas import ChatMessage, ChatResponse
from app.ml.explainer import answer_faq, DEFENSIVE_RECOMMENDATIONS, ATTACK_DESCRIPTIONS

router = APIRouter(tags=["chat"])


@router.post("", response_model=ChatResponse)
def handle_chat_message(payload: ChatMessage, db: Session = Depends(get_db)):
    msg = payload.message.strip()
    lang = payload.language or "en"
    alert_context = ""

    # Check if this query refers to a specific alert
    if payload.alert_id:
        alert = db.query(Alert).filter(Alert.id == payload.alert_id).first()
        if alert:
            recs = alert.recommended_actions or ""
            alert_context = (
                f"Regarding Alert #{alert.id} ({alert.title}): "
                f"Severity is {alert.severity}, Category is {alert.attack_category or 'General'}. "
                f"Remediation Guidance:\n{recs}"
            )

    # 1. First check the domain FAQ
    faq_answer = answer_faq(msg, language=lang)
    if faq_answer:
        reply = faq_answer
        if alert_context:
            reply = f"{alert_context}\n\n{faq_answer}"
        return ChatResponse(
            reply=reply,
            source="faq",
            language=lang,
        )

    # 2. If alert context is present but not in FAQ, provide structured SOC guidance
    if alert_context:
        return ChatResponse(
            reply=alert_context,
            source="context",
            language=lang,
        )

    # 3. Fallback security copilot guidance
    if lang == "ta":
        fallback = (
            "CyberSentinel AI பாதுகாப்புக் குழுவிற்கு வருக! "
            "Brute Force, Credential Stuffing, Port Scan, Anomaly Detection, மற்றும் MFA "
            "பற்றி அறிய கேள்விகளைக் கேட்கலாம். மேலும் எச்சரிக்கைகள் (Alerts) விவரங்களைப் பகுப்பாய்வு செய்யவும் உதவ முடியும்."
        )
    else:
        fallback = (
            "Welcome to CyberSentinel AI Security Copilot! "
            "I can assist you with investigating brute-force attempts, credential stuffing, port scans, "
            "anomaly scoring, and incident mitigation playbooks. "
            "You can ask me questions like: 'What is credential stuffing?', 'How to mitigate brute force?', "
            "'Explain risk score', or 'What is an anomaly?'"
        )

    return ChatResponse(
        reply=fallback,
        source="context",
        language=lang,
    )
