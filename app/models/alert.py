"""Alert ORM model."""
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from app.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("security_events.id"), nullable=True, index=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(16), nullable=False, default="Medium")  # Low | Medium | High | Critical
    status = Column(String(16), nullable=False, default="open")      # open | acknowledged | in_progress | resolved
    attack_category = Column(String(64), nullable=True)
    source_ip = Column(String(45), nullable=True)
    risk_score = Column(Integer, nullable=True)

    # Explanation from ML
    explanation = Column(Text, nullable=True)
    recommended_actions = Column(Text, nullable=True)  # JSON list stored as text

    # Analyst management
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    notes = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))
    resolved_at = Column(DateTime(timezone=True), nullable=True)
