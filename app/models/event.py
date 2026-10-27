"""Security Event ORM model."""
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text
from app.database import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)

    # Core event fields
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    user_identifier = Column(String(128), nullable=True, index=True)
    source_ip = Column(String(45), nullable=True, index=True)   # IPv4/IPv6
    login_result = Column(String(16), nullable=True)             # success | failure | lockout
    event_type = Column(String(32), nullable=False, default="auth")  # auth | network

    # Auth-specific features
    failed_attempts_window = Column(Integer, default=0)
    distinct_accounts_targeted = Column(Integer, default=1)
    request_frequency = Column(Float, default=1.0)
    hour_of_day = Column(Integer, nullable=True)
    geo_country = Column(String(64), nullable=True)   # anonymized / optional
    anonymized_source_attr = Column(String(64), nullable=True)

    # Network-flow features (optional)
    duration = Column(Float, nullable=True)
    bytes_sent = Column(Float, nullable=True)
    bytes_received = Column(Float, nullable=True)
    packets = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=True)
    destination_port = Column(Integer, nullable=True)

    # ML outputs
    anomaly_score = Column(Float, nullable=True)
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(16), nullable=True)   # Low | Medium | High | Critical
    attack_category = Column(String(64), nullable=True)
    attack_probability = Column(Float, nullable=True)
    model_version = Column(String(32), nullable=True)
    is_synthetic = Column(Boolean, default=False)

    # Ingestion metadata
    source = Column(String(32), default="manual")  # manual | csv | api | generated
    ingested_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    raw_notes = Column(Text, nullable=True)
