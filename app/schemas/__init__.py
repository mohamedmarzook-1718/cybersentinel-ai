"""Pydantic schemas for request/response validation."""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


# ── Auth ──────────────────────────────────────────────────────────────────────

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


class TokenData(BaseModel):
    sub: Optional[str] = None


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: Optional[str] = None
    password: str = Field(..., min_length=8)
    role: str = "analyst"


class UserOut(BaseModel):
    id: int
    username: str
    email: Optional[str]
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


# ── Security Events ───────────────────────────────────────────────────────────

class EventCreate(BaseModel):
    timestamp: datetime
    user_identifier: Optional[str] = None
    source_ip: Optional[str] = None
    login_result: Optional[str] = None      # success | failure | lockout
    event_type: str = "auth"
    failed_attempts_window: int = Field(0, ge=0)
    distinct_accounts_targeted: int = Field(1, ge=0)
    request_frequency: float = Field(1.0, ge=0.0)
    hour_of_day: Optional[int] = Field(None, ge=0, le=23)
    geo_country: Optional[str] = None
    anonymized_source_attr: Optional[str] = None
    duration: Optional[float] = Field(None, ge=0.0)
    bytes_sent: Optional[float] = Field(None, ge=0.0)
    bytes_received: Optional[float] = Field(None, ge=0.0)
    packets: Optional[int] = Field(None, ge=0)
    protocol: Optional[str] = None
    destination_port: Optional[int] = Field(None, ge=0, le=65535)
    is_synthetic: bool = False
    source: str = "manual"
    raw_notes: Optional[str] = None


class EventOut(BaseModel):
    id: int
    timestamp: datetime
    user_identifier: Optional[str]
    source_ip: Optional[str]
    login_result: Optional[str]
    event_type: str
    failed_attempts_window: int
    distinct_accounts_targeted: int
    request_frequency: float
    hour_of_day: Optional[int]
    geo_country: Optional[str]
    anomaly_score: Optional[float]
    risk_score: Optional[float]
    risk_level: Optional[str]
    attack_category: Optional[str]
    attack_probability: Optional[float]
    model_version: Optional[str]
    is_synthetic: bool
    source: str
    ingested_at: datetime

    model_config = {"from_attributes": True, "protected_namespaces": ()}


class PredictionResult(BaseModel):
    model_config = {"protected_namespaces": ()}

    event_id: Optional[int] = None
    anomaly_score: float
    risk_score: float
    risk_level: str
    attack_category: Optional[str] = None
    attack_probability: Optional[float] = None
    model_version: str
    is_synthetic: bool = False
    explanation: str
    feature_contributions: dict = {}
    recommended_actions: list[str] = []
    confidence_note: str = ""
    early_warning_stage: Optional[str] = None
    early_warning_indicators: list[str] = []
    escalation_potential: Optional[str] = None


# ── Alerts ────────────────────────────────────────────────────────────────────

class AlertCreate(BaseModel):
    event_id: Optional[int] = None
    title: str = Field(..., min_length=3, max_length=256)
    description: Optional[str] = None
    severity: str = "Medium"
    attack_category: Optional[str] = None
    source_ip: Optional[str] = None
    risk_score: Optional[int] = None
    explanation: Optional[str] = None
    recommended_actions: Optional[str] = None


class AlertUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[int] = None
    notes: Optional[str] = None
    severity: Optional[str] = None


class AlertOut(BaseModel):
    id: int
    event_id: Optional[int]
    title: str
    description: Optional[str]
    severity: str
    status: str
    attack_category: Optional[str]
    source_ip: Optional[str]
    risk_score: Optional[int]
    explanation: Optional[str]
    recommended_actions: Optional[str]
    assigned_to: Optional[int]
    notes: Optional[str]
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]

    model_config = {"from_attributes": True}


# ── Audit ─────────────────────────────────────────────────────────────────────

class AuditLogOut(BaseModel):
    id: int
    username: Optional[str]
    action: str
    resource_type: Optional[str]
    resource_id: Optional[int]
    detail: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Dashboard ─────────────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    model_config = {"protected_namespaces": ()}

    total_events: int
    high_critical_alerts: int
    suspicious_logins: int
    anomalies_detected: int
    open_alerts: int
    risk_distribution: dict
    category_distribution: dict
    anomaly_trend: list[dict]
    recent_alerts: list[AlertOut]
    model_status: dict


# ── Chat ──────────────────────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)
    alert_id: Optional[int] = None
    language: str = "en"   # en | ta


class ChatResponse(BaseModel):
    reply: str
    source: str  # "faq" | "llm" | "context"
    language: str


# ── CSV Upload ────────────────────────────────────────────────────────────────

class CSVUploadResult(BaseModel):
    accepted: int
    rejected: int
    errors: list[str]
    event_ids: list[int]


# ── Settings ──────────────────────────────────────────────────────────────────

class SettingsOut(BaseModel):
    model_config = {"protected_namespaces": ()}

    risk_threshold_low: int
    risk_threshold_medium: int
    risk_threshold_high: int
    anomaly_contamination: float
    model_random_seed: int
    access_token_expire_minutes: int


class SettingsUpdate(BaseModel):
    risk_threshold_low: Optional[int] = None
    risk_threshold_medium: Optional[int] = None
    risk_threshold_high: Optional[int] = None
    anomaly_contamination: Optional[float] = None


# ── Model metadata ────────────────────────────────────────────────────────────

class ModelMetadata(BaseModel):
    model_config = {"protected_namespaces": ()}

    version: str
    trained_at: Optional[str]
    training_samples: Optional[int]
    anomaly_model: str
    classifier_model: Optional[str]
    features: list[str]
    metrics: Optional[dict]


# ── Pagination ────────────────────────────────────────────────────────────────

class PaginatedEvents(BaseModel):
    items: list[EventOut]
    total: int
    page: int
    page_size: int
    pages: int


class PaginatedAlerts(BaseModel):
    items: list[AlertOut]
    total: int
    page: int
    page_size: int
    pages: int


# ── Web Security Scanner ──────────────────────────────────────────────────────

class WebScanCreate(BaseModel):
    url: str = Field(..., min_length=4, max_length=512)
    profile: str = Field("standard", pattern="^(passive|quick|standard|comprehensive)$")
    authorized: bool = True
    allowed_domains: list[str] = []
    excluded_paths: list[str] = []
    max_crawl_pages: int = Field(30, ge=1, le=100)


class ScanFinding(BaseModel):
    id: str
    title: str
    severity: str  # Critical | High | Medium | Low | Informational
    category: str  # Attack Surface | OWASP Top 10 | Infrastructure | API Security | Client-Side | Threat Intelligence | Availability
    confidence: str = "Confirmed"  # Confirmed | Suspected | Informational
    status: str = "Confirmed"      # Confirmed | Potential Risk | Not Checked
    evidence: str
    affected_url: str
    explanation: str
    recommendation: str
    reproduction_steps: Optional[str] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None


class RemediationItem(BaseModel):
    priority: str   # Immediate | High | Medium | Routine
    title: str
    description: str
    affected_assets: list[str] = []
    effort: str = "Medium"


class WebScanSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0
    total: int = 0


class WebScanOut(BaseModel):
    id: int
    url: str
    target_host: str
    target_ip: Optional[str] = None
    scan_status: str
    score: int
    risk_level: str
    profile: str = "standard"
    http_status: Optional[int] = None
    response_time_ms: Optional[float] = None
    tls_version: Optional[str] = None
    cert_valid: Optional[bool] = None
    cert_issuer: Optional[str] = None
    cert_expires_at: Optional[datetime] = None
    findings: list[ScanFinding] = []
    summary: WebScanSummary
    headers: dict = {}
    attack_surface: dict = {}
    remediation_checklist: list[RemediationItem] = []
    limitations: list[str] = []
    pages_crawled: int = 1
    pages_discovered: int = 1
    error_message: Optional[str] = None
    started_at: datetime
    completed_at: datetime

    model_config = {"from_attributes": True}


class WebScanListItem(BaseModel):
    id: int
    url: str
    target_host: str
    target_ip: Optional[str] = None
    scan_status: str
    score: int
    risk_level: str
    profile: str = "standard"
    http_status: Optional[int] = None
    pages_crawled: int = 1
    summary: WebScanSummary
    started_at: datetime
    completed_at: datetime

    model_config = {"from_attributes": True}


class WebScanCompareResult(BaseModel):
    scan_a: WebScanOut
    scan_b: WebScanOut
    score_diff: int
    new_findings: list[ScanFinding]
    resolved_findings: list[ScanFinding]
    retained_findings: list[ScanFinding]


class PaginatedWebScans(BaseModel):
    items: list[WebScanListItem]
    total: int
    page: int
    page_size: int
    pages: int


