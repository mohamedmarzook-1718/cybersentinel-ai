"""Web Security Scanner ORM model."""
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from app.database import Base


class WebScan(Base):
    __tablename__ = "web_scans"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(512), nullable=False, index=True)
    target_host = Column(String(256), nullable=False, index=True)
    target_ip = Column(String(64), nullable=True)
    scan_status = Column(String(32), nullable=False, default="completed")  # completed | failed | partial
    score = Column(Integer, nullable=False, default=100)                    # 0 - 100
    risk_level = Column(String(32), nullable=False, default="Low")          # Critical | High | Medium | Low | Informational

    # Network & protocol observations
    http_status = Column(Integer, nullable=True)
    response_time_ms = Column(Float, nullable=True)
    tls_version = Column(String(32), nullable=True)
    cert_valid = Column(Boolean, nullable=True)
    cert_issuer = Column(String(256), nullable=True)
    cert_expires_at = Column(DateTime(timezone=True), nullable=True)

    # Detailed findings, counts, and headers stored as JSON
    findings_json = Column(Text, nullable=False, default="[]")
    summary_json = Column(Text, nullable=False, default="{}")
    headers_json = Column(Text, nullable=False, default="{}")
    error_message = Column(Text, nullable=True)

    # Advanced Multi-Layer Assessment fields
    profile = Column(String(32), nullable=False, default="standard")  # passive | quick | standard | comprehensive
    scope_config_json = Column(Text, nullable=False, default="{}")
    attack_surface_json = Column(Text, nullable=False, default="{}")
    remediation_json = Column(Text, nullable=False, default="[]")
    limitations_json = Column(Text, nullable=False, default="[]")
    pages_crawled = Column(Integer, nullable=False, default=1)
    pages_discovered = Column(Integer, nullable=False, default=1)

    # Scanned by user (optional)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Timestamps
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    completed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
