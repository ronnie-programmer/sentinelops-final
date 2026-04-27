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
    status: str
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
