from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
import random

from database import get_db
from models import Threat, AlertLog
from schemas import ThreatCreate, ThreatUpdate, ThreatOut, AIAnalysisOut

router = APIRouter(prefix="/api/threats", tags=["threats"])


# ── AI Analysis Templates ────────────────────────────────────────────────────

AI_ANALYSIS_TEMPLATES = {
    "Malware": [
        "This malware sample exhibits characteristics consistent with a {severity}-severity implant. "
        "Static analysis reveals obfuscated payload delivery mechanisms targeting {affected}. "
        "The binary communicates with command-and-control infrastructure using encrypted channels. "
        "Behavioral indicators suggest persistence via scheduled tasks and registry modification. "
        "Recommended remediation: isolate affected endpoints, revoke compromised credentials, "
        "and deploy updated endpoint detection signatures across the fleet.",

        "Advanced malware detected leveraging {mitre_tactic} techniques. "
        "Code analysis shows similarity to known threat actor tooling (confidence: 84%). "
        "The sample drops secondary payloads designed to evade sandbox detection. "
        "Network traffic analysis reveals beaconing at irregular intervals to avoid detection. "
        "Priority action: quarantine affected systems and conduct full memory forensics.",
    ],
    "Phishing": [
        "Spear-phishing campaign detected targeting {affected}. The email lures leverage "
        "urgency-based social engineering with credential-harvesting payloads. "
        "The sending infrastructure traces to bulletproof hosting providers previously associated "
        "with {mitre_tactic} campaigns. Domain spoofing techniques confirm high attacker sophistication. "
        "Immediate action: block sender domains, reset potentially compromised credentials, "
        "and issue user awareness notification.",

        "Phishing infrastructure analysis indicates a coordinated campaign with {severity} severity. "
        "Multiple look-alike domains registered within the past 72 hours. "
        "Credential theft kit recovered from C2 server mirrors internal login portal. "
        "Risk assessment: {severity} likelihood of successful account compromise. "
        "Recommended: deploy MFA enforcement and enable advanced email filtering rules.",
    ],
    "Ransomware": [
        "Ransomware precursor activity detected — immediate containment required. "
        "Indicators match {mitre_tactic} stage of a multi-phase ransomware operation. "
        "Lateral movement artifacts discovered across {affected} segments. "
        "Attacker dwell time estimated at 3-7 days based on log analysis. "
        "CRITICAL: Initiate incident response protocol, isolate network segments, "
        "verify backup integrity before any ransom consideration.",

        "This ransomware variant employs double-extortion tactics: data exfiltration prior to encryption. "
        "File system telemetry confirms bulk data staging in hidden directories. "
        "Encryption routine targets business-critical file extensions. "
        "Recovery time objective severely impacted without clean backups. "
        "Forensic priority: identify patient-zero endpoint and map full blast radius.",
    ],
    "Insider Threat": [
        "Behavioral analytics flagged anomalous data access patterns consistent with insider threat indicators. "
        "User activity logs show bulk downloads of sensitive files outside business hours. "
        "DLP alerts correlate with {mitre_tactic} exfiltration techniques. "
        "Access to restricted repositories not aligned with user's role permissions. "
        "Recommended: revoke access pending HR investigation, preserve all audit logs, "
        "engage legal and compliance teams.",

        "Privileged user activity analysis reveals policy violations with {severity} risk classification. "
        "Shadow IT tool usage detected, bypassing approved data channels. "
        "Timeline correlation suggests deliberate evasion of monitoring controls. "
        "Data classification review required to assess full exposure scope.",
    ],
    "DDoS": [
        "Distributed denial-of-service attack confirmed targeting {affected}. "
        "Peak traffic volume exceeded baseline by 4,200% — volumetric flood attack pattern. "
        "Botnet fingerprinting identifies compromised IoT devices as primary traffic source. "
        "BGP anomaly detection triggered upstream provider alerts. "
        "Mitigation: activate scrubbing center, apply rate limiting rules, coordinate with upstream ISP.",

        "Layer 7 application DDoS detected using HTTP flood with rotating user agents. "
        "Attack sophistication indicates professional threat actor tooling. "
        "WAF rules partially mitigating impact; 23% of requests reaching origin. "
        "Geographic source analysis shows multi-region coordinated attack infrastructure. "
        "Recommended: enable advanced bot protection and implement CAPTCHA challenges.",
    ],
    "Brute Force": [
        "Credential brute force campaign detected against {affected}. "
        "Attack pattern consistent with credential stuffing using leaked database. "
        "Over 50,000 authentication attempts recorded in a 6-hour window. "
        "Account lockout policies limiting impact but attacker rotating source IPs via proxy networks. "
        "Immediate action: enforce MFA, block identified IP ranges, audit successful logins for anomalies.",

        "Password spraying attack identified using {mitre_tactic} technique. "
        "Low-and-slow approach designed to evade lockout thresholds. "
        "Valid usernames enumerated via OSINT prior to attack. "
        "Three accounts confirmed compromised — immediate credential reset required. "
        "Recommended: deploy adaptive authentication and review identity governance policies.",
    ],
    "SQL Injection": [
        "SQL injection attack chain detected targeting {affected} database layer. "
        "Payload analysis confirms UNION-based extraction technique. "
        "Attacker successfully enumerated database schema before detection. "
        "Web Application Firewall bypass techniques observed — WAF rule updates required. "
        "Remediation: patch vulnerable input fields, review ORM query patterns, "
        "conduct full database audit for unauthorized data access.",

        "Blind SQL injection campaign identified with {severity} data exposure risk. "
        "Time-based inference techniques used to avoid error-based detection. "
        "Data exfiltration volume estimated at 2.3GB based on outbound traffic analysis. "
        "PII exposure likely — initiate breach assessment and notification procedures per regulatory requirements.",
    ],
    "Lateral Movement": [
        "Active lateral movement campaign detected across internal network segments. "
        "Attacker leveraging {mitre_tactic} to escalate privileges and pivot across systems. "
        "Pass-the-hash and Kerberoasting artifacts identified in Active Directory logs. "
        "Three high-value systems compromised — IT admin accounts at risk. "
        "Immediate action: reset all privileged credentials, enable enhanced AD monitoring, "
        "implement network segmentation to contain spread.",

        "Sophisticated lateral movement using living-off-the-land binaries (LOLBins). "
        "WMI, PowerShell Remoting, and PsExec usage flagged across {affected}. "
        "Defense evasion techniques employed to bypass EDR behavioral rules. "
        "Threat actor appears to be mapping internal network topology. "
        "Recommended: isolate compromised systems, deploy honeypots, engage threat hunting team.",
    ],
    "Zero-Day Exploit": [
        "Zero-day exploit activity detected against unpatched {affected} infrastructure. "
        "Exploit chain leverages memory corruption vulnerability — CVE analysis pending. "
        "Proof-of-concept code does not match any known public exploits, suggesting novel attack. "
        "Vendor notification initiated; temporary mitigations applied via virtual patching. "
        "CRITICAL: Activate war room, engage vendor emergency response, implement network-level controls.",

        "Novel exploitation technique observed in {severity} severity incident. "
        "Heap spray and ROP chain artifacts confirm advanced exploit development. "
        "No existing signatures detect this attack pattern — custom detection rules deployed. "
        "Threat intelligence shared with ISAC partners for wider awareness. "
        "Recommended: apply compensating controls and accelerate patch deployment pipeline.",
    ],
    "Data Exfiltration": [
        "Data exfiltration operation detected using {mitre_tactic} techniques. "
        "Sensitive data staged and compressed before transmission to external infrastructure. "
        "DNS tunneling used to bypass data loss prevention controls. "
        "Exfiltrated data volume: estimated 15GB of potentially sensitive records. "
        "Immediate action: block external DNS resolvers, audit data classification policies, "
        "initiate regulatory breach assessment timeline.",

        "Advanced persistent data theft campaign in progress targeting {affected}. "
        "Attacker using cloud storage services as exfiltration staging points. "
        "OAuth token abuse identified to maintain persistent access. "
        "UEBA alerts confirm deviation from normal user behavior baseline. "
        "Recommended: revoke OAuth grants, enable CASB policies, conduct full data audit.",
    ],
}

DEFAULT_ANALYSIS = [
    "Threat analysis complete. This {severity} severity incident exhibits indicators consistent "
    "with {mitre_tactic} tactics. Behavioral telemetry collected from affected systems shows "
    "evidence of attacker persistence and lateral movement attempts. "
    "Current containment measures are partially effective. "
    "Recommended actions: escalate to Tier 2 SOC analysts, preserve forensic evidence, "
    "and implement additional detection rules based on observed IOCs.",

    "SentinelAI analysis indicates this event represents a {severity} risk to organizational assets. "
    "MITRE ATT&CK mapping to {mitre_tactic} confirms structured attack methodology. "
    "Cross-referencing with threat intelligence feeds shows 67% similarity to known APT activity. "
    "Recommended: activate incident response playbook for {threat_type} incidents and "
    "brief CISO with preliminary findings within 2 hours.",
]


def generate_ai_analysis(threat: Threat) -> str:
    templates = AI_ANALYSIS_TEMPLATES.get(threat.threat_type, DEFAULT_ANALYSIS)
    template = random.choice(templates)

    affected = threat.affected_system or threat.destination_ip or "critical infrastructure"
    mitre = threat.mitre_tactic or "Initial Access"
    threat_type = threat.threat_type or "Unknown"

    analysis = template.format(
        severity=threat.severity,
        affected=affected,
        mitre_tactic=mitre,
        threat_type=threat_type,
    )

    # Add a footer with metadata
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    footer = (
        f"\n\n---\n"
        f"**Analysis generated by SentinelAI v3.1** | {timestamp}\n"
        f"Confidence Score: {random.randint(72, 96)}% | "
        f"MITRE ATT&CK: {mitre} | "
        f"Severity: {threat.severity}"
    )
    return analysis + footer


# ── CRUD Endpoints ───────────────────────────────────────────────────────────

@router.get("/", response_model=List[ThreatOut])
def get_threats(
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    threat_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    query = db.query(Threat)
    if severity:
        query = query.filter(Threat.severity == severity)
    if status:
        query = query.filter(Threat.status == status)
    if threat_type:
        query = query.filter(Threat.threat_type == threat_type)
    return query.order_by(Threat.created_at.desc()).offset(skip).limit(limit).all()


@router.get("/{threat_id}", response_model=ThreatOut)
def get_threat(threat_id: int, db: Session = Depends(get_db)):
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return threat


@router.post("/", response_model=ThreatOut, status_code=201)
def create_threat(threat_in: ThreatCreate, db: Session = Depends(get_db)):
    threat = Threat(**threat_in.model_dump())
    db.add(threat)
    db.flush()

    # Auto-create alert for HIGH and CRITICAL threats
    if threat.severity in ("CRITICAL", "HIGH"):
        alert = AlertLog(
            threat_id=threat.id,
            severity=threat.severity,
            message=(
                f"[{threat.severity}] New threat detected: '{threat.title}'. "
                f"Type: {threat.threat_type}. "
                f"Immediate attention required by SOC team."
            ),
            recipient="soc-team@sentinelops.internal",
            status="Pending",
        )
        db.add(alert)

    db.commit()
    db.refresh(threat)
    return threat


@router.put("/{threat_id}", response_model=ThreatOut)
def update_threat(threat_id: int, threat_in: ThreatUpdate, db: Session = Depends(get_db)):
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    update_data = threat_in.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(threat, key, value)
    threat.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(threat)
    return threat


@router.delete("/{threat_id}", status_code=204)
def delete_threat(threat_id: int, db: Session = Depends(get_db)):
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    db.delete(threat)
    db.commit()


# ── AI Analysis Endpoint ─────────────────────────────────────────────────────

@router.post("/{threat_id}/analyze", response_model=AIAnalysisOut)
def analyze_threat(threat_id: int, db: Session = Depends(get_db)):
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    analysis_text = generate_ai_analysis(threat)
    analyzed_at = datetime.utcnow()

    threat.ai_analysis = analysis_text
    threat.ai_analyzed_at = analyzed_at
    threat.updated_at = analyzed_at
    db.commit()

    return AIAnalysisOut(
        threat_id=threat.id,
        analysis=analysis_text,
        analyzed_at=analyzed_at,
        model="SentinelAI v3.1",
    )
