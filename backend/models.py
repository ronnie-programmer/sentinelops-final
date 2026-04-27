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
    status = Column(String(20), default="Pending", nullable=False)
    summary = Column(Text, nullable=True)
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
