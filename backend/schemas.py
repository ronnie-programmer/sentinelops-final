from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


# ----- Asset Schemas -----

class AssetBase(BaseModel):
    hostname: str
    ip_address: str
    os: str
    asset_type: str = "Server"
    status: str = "Online"
    owner: Optional[str] = None
    location: Optional[str] = None


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os: Optional[str] = None
    asset_type: Optional[str] = None
    status: Optional[str] = None
    owner: Optional[str] = None
    location: Optional[str] = None


class AssetOut(AssetBase):
    id: int
    vulnerability_count: int = 0
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ----- Threat Schemas -----

class ThreatBase(BaseModel):
    title: str
    description: str
    severity: str = "MEDIUM"
    status: str = "Open"
    threat_type: str
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    affected_system: Optional[str] = None
    asset_id: Optional[int] = None


class ThreatCreate(ThreatBase):
    pass


class ThreatUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    threat_type: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    affected_system: Optional[str] = None
    asset_id: Optional[int] = None


class ThreatOut(ThreatBase):
    id: int
    mitre_techniques: Optional[str] = None
    ai_analysis: Optional[str] = None
    ai_analyzed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AIAnalysisOut(BaseModel):
    threat_id: int
    analysis: str
    analyzed_at: datetime
    model: str = "SentinelAI v3.1"


# ----- Alert Schemas -----

class AlertLogOut(BaseModel):
    id: int
    threat_id: int
    severity: str
    message: str
    recipient: Optional[str] = None
    source: Optional[str] = None
    status: str
    summary: Optional[str] = None
    mitre_techniques: Optional[str] = None
    created_at: datetime
    acknowledged_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AlertAcknowledge(BaseModel):
    alert_id: int


# ----- Threat Intel Schemas -----

class ThreatIntelBase(BaseModel):
    title: str
    intel_type: str
    value: str
    description: str
    severity: str = "MEDIUM"
    source: Optional[str] = None
    tags: Optional[str] = None
    confidence: int = 75


class ThreatIntelCreate(ThreatIntelBase):
    pass


class ThreatIntelOut(ThreatIntelBase):
    id: int
    is_imported: int = 0
    created_at: datetime

    class Config:
        from_attributes = True


# ----- Compliance Schemas -----

class ComplianceControl(BaseModel):
    id: str
    name: str
    framework: str
    category: str
    status: str
    description: str
    last_assessed: str
    owner: str


class ComplianceSummary(BaseModel):
    framework: str
    passing: int
    failing: int
    in_review: int
    total: int
    score: float
    controls: List[ComplianceControl]


# ----- Dashboard Schemas -----

class DashboardStats(BaseModel):
    total_threats: int
    open_threats: int
    critical_threats: int
    high_threats: int
    medium_threats: int
    low_threats: int
    resolved_threats: int
    total_assets: int
    vulnerable_assets: int
    unread_alerts: int
    threats_by_type: dict
    threats_by_day: list


# ----- Notification Schemas -----

class NotificationOut(BaseModel):
    id: int
    threat_id: Optional[int] = None
    channel: str
    status: str
    error_message: Optional[str] = None
    attempted_at: datetime

    class Config:
        from_attributes = True


class NotificationSettings(BaseModel):
    slack_enabled: bool = False
    slack_webhook_url: str = ""
    pagerduty_enabled: bool = False
    pagerduty_integration_key: str = ""
    pagerduty_severity_threshold: str = "HIGH"


# ----- Integration Schemas -----

class IntegrationOut(BaseModel):
    id: int
    provider: str
    enabled: bool
    is_mock: bool
    last_polled_at: Optional[datetime] = None
    last_poll_count: int = 0
    status: str

    class Config:
        from_attributes = True

    @classmethod
    def from_orm_model(cls, obj):
        return cls(
            id=obj.id,
            provider=obj.provider,
            enabled=bool(obj.enabled),
            is_mock=bool(obj.is_mock),
            last_polled_at=obj.last_polled_at,
            last_poll_count=obj.last_poll_count,
            status=obj.status,
        )


class IntegrationToggle(BaseModel):
    enabled: bool


# ----- IOC Schemas -----

class IOCCreate(BaseModel):
    ioc_type: str
    value: str
    source_alert_id: Optional[int] = None


class IOCOut(BaseModel):
    id: int
    ioc_type: str
    value: str
    vt_score: Optional[int] = None
    vt_engines_total: Optional[int] = None
    vt_engines_malicious: Optional[int] = None
    abuseipdb_score: Optional[int] = None
    last_enriched_at: Optional[datetime] = None
    source_alert_id: Optional[int] = None
    created_at: datetime

    class Config:
        from_attributes = True


# ----- Compliance Report Schemas -----

class ComplianceReportOut(BaseModel):
    id: int
    framework: str
    date_range_start: datetime
    date_range_end: datetime
    generated_at: datetime
    status: str
    alert_count: int
    threat_count: int

    class Config:
        from_attributes = True


class ComplianceReportGenerate(BaseModel):
    framework: str  # SOC2, HIPAA, NIST, CMMC
    date_range_start: datetime
    date_range_end: datetime


# ----- Playbook Schemas -----

class PlaybookOut(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    enabled: bool
    trigger_yaml: str
    actions_yaml: str
    is_builtin: bool
    run_count: int
    last_run_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    class Config:
        from_attributes = True

class PlaybookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    trigger_yaml: str
    actions_yaml: str

class PlaybookUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    trigger_yaml: Optional[str] = None
    actions_yaml: Optional[str] = None

class PlaybookRunOut(BaseModel):
    id: int
    playbook_id: int
    triggered_by: Optional[str] = None
    status: str
    output: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    class Config:
        from_attributes = True
