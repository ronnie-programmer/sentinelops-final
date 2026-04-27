from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Enum
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base
import enum


class SeverityEnum(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ThreatStatusEnum(str, enum.Enum):
    OPEN = "Open"
    INVESTIGATING = "Investigating"
    RESOLVED = "Resolved"
    FALSE_POSITIVE = "False Positive"


class AlertStatusEnum(str, enum.Enum):
    PENDING = "Pending"
    SENT = "Sent"
    ACKNOWLEDGED = "Acknowledged"


class AssetTypeEnum(str, enum.Enum):
    SERVER = "Server"
    ENDPOINT = "Endpoint"
    NETWORK = "Network"


class AssetStatusEnum(str, enum.Enum):
    ONLINE = "Online"
    OFFLINE = "Offline"
    VULNERABLE = "Vulnerable"


class IntelTypeEnum(str, enum.Enum):
    CVE = "CVE"
    THREAT_ACTOR = "Threat Actor"
    IOC_IP = "IOC-IP"
    IOC_HASH = "IOC-Hash"
    IOC_DOMAIN = "IOC-Domain"


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(100), nullable=False)
    ip_address = Column(String(45), nullable=False)
    os = Column(String(100), nullable=False)
    asset_type = Column(String(20), default="Server", nullable=False)
    status = Column(String(20), default="Online", nullable=False)
    owner = Column(String(100), nullable=True)
    location = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    threats = relationship("Threat", back_populates="asset")

    @property
    def vulnerability_count(self):
        return len([t for t in self.threats if t.status != "Resolved"])


class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), default="MEDIUM", nullable=False)
    status = Column(String(30), default="Open", nullable=False)
    threat_type = Column(String(100), nullable=False)
    mitre_tactic = Column(String(100), nullable=True)
    mitre_technique = Column(String(100), nullable=True)
    mitre_techniques = Column(Text, nullable=True)
    source_ip = Column(String(45), nullable=True)
    destination_ip = Column(String(45), nullable=True)
    affected_system = Column(String(200), nullable=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    ai_analysis = Column(Text, nullable=True)
    ai_analyzed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    asset = relationship("Asset", back_populates="threats")
    alerts = relationship("AlertLog", back_populates="threat")


class AlertLog(Base):
    __tablename__ = "alert_logs"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id"), nullable=False)
    severity = Column(String(20), nullable=False)
    message = Column(Text, nullable=False)
    recipient = Column(String(200), nullable=True)
    source = Column(String(50), nullable=True)
    status = Column(String(20), default="Pending", nullable=False)
    summary = Column(Text, nullable=True)
    mitre_techniques = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    acknowledged_at = Column(DateTime, nullable=True)

    threat = relationship("Threat", back_populates="alerts")


class ThreatIntel(Base):
    __tablename__ = "threat_intel"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    intel_type = Column(String(30), nullable=False)
    value = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), default="MEDIUM", nullable=False)
    source = Column(String(200), nullable=True)
    tags = Column(String(500), nullable=True)
    confidence = Column(Integer, default=75)
    is_imported = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id"), nullable=True)
    channel = Column(String(50), nullable=False)  # "slack" or "pagerduty"
    payload = Column(Text, nullable=True)
    status = Column(String(20), default="pending")  # sent, skipped, error
    error_message = Column(Text, nullable=True)
    attempted_at = Column(DateTime, default=datetime.utcnow)


class Integration(Base):
    __tablename__ = "integrations"

    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String(50), nullable=False, unique=True)  # crowdstrike, datadog, splunk
    enabled = Column(Integer, default=0)  # 0=disabled, 1=enabled
    is_mock = Column(Integer, default=1)
    last_polled_at = Column(DateTime, nullable=True)
    last_poll_count = Column(Integer, default=0)
    status = Column(String(20), default="idle")  # idle, connected, mock, error
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    ioc_type = Column(String(20), nullable=False)  # ip, domain, hash, url
    value = Column(String(500), nullable=False, unique=True)
    vt_score = Column(Integer, nullable=True)         # 0-100 (malicious %)
    vt_engines_total = Column(Integer, nullable=True)
    vt_engines_malicious = Column(Integer, nullable=True)
    abuseipdb_score = Column(Integer, nullable=True)  # 0-100 confidence of abuse
    last_enriched_at = Column(DateTime, nullable=True)
    source_alert_id = Column(Integer, ForeignKey("alert_logs.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ComplianceReport(Base):
    __tablename__ = "compliance_reports"
    id = Column(Integer, primary_key=True, index=True)
    framework = Column(String(20), nullable=False)   # SOC2, HIPAA, NIST, CMMC
    date_range_start = Column(DateTime, nullable=False)
    date_range_end = Column(DateTime, nullable=False)
    generated_at = Column(DateTime, default=datetime.utcnow)
    file_path = Column(String(500), nullable=True)
    status = Column(String(20), default="generating")  # generating, ready, error
    alert_count = Column(Integer, default=0)
    threat_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)


class Playbook(Base):
    __tablename__ = "playbooks"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    enabled = Column(Integer, default=1)  # 0=disabled, 1=enabled
    trigger_yaml = Column(Text, nullable=False)   # YAML string
    actions_yaml = Column(Text, nullable=False)   # YAML string
    is_builtin = Column(Integer, default=0)       # 1 = prebuilt, read-only
    run_count = Column(Integer, default=0)
    last_run_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    runs = relationship("PlaybookRun", back_populates="playbook")


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"
    id = Column(Integer, primary_key=True, index=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id"), nullable=False)
    triggered_by = Column(String(200), nullable=True)  # "alert:42", "manual", etc.
    status = Column(String(20), default="running")  # running, success, error
    output = Column(Text, nullable=True)   # JSON string of action results
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    playbook = relationship("Playbook", back_populates="runs")
