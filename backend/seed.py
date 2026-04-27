"""
SentinelOps v3 — Seed Script
Run: python seed.py
"""
from datetime import datetime, timedelta
import random
from database import SessionLocal, engine
from models import Base, Asset, Threat, AlertLog, ThreatIntel

Base.metadata.create_all(bind=engine)

db = SessionLocal()

# Clear existing data
db.query(AlertLog).delete()
db.query(Threat).delete()
db.query(ThreatIntel).delete()
db.query(Asset).delete()
db.commit()

print("Seeding assets...")

ASSETS = [
    Asset(hostname="web-prod-01", ip_address="10.0.1.10", os="Ubuntu 22.04 LTS", asset_type="Server", status="Online", owner="Platform Team", location="us-east-1"),
    Asset(hostname="web-prod-02", ip_address="10.0.1.11", os="Ubuntu 22.04 LTS", asset_type="Server", status="Online", owner="Platform Team", location="us-east-1"),
    Asset(hostname="db-primary", ip_address="10.0.2.5", os="Amazon Linux 2023", asset_type="Server", status="Vulnerable", owner="Database Team", location="us-east-1"),
    Asset(hostname="db-replica", ip_address="10.0.2.6", os="Amazon Linux 2023", asset_type="Server", status="Online", owner="Database Team", location="us-west-2"),
    Asset(hostname="k8s-master-01", ip_address="10.0.3.1", os="Ubuntu 22.04 LTS", asset_type="Server", status="Online", owner="DevOps", location="us-east-1"),
    Asset(hostname="k8s-worker-01", ip_address="10.0.3.10", os="Ubuntu 22.04 LTS", asset_type="Server", status="Online", owner="DevOps", location="us-east-1"),
    Asset(hostname="k8s-worker-02", ip_address="10.0.3.11", os="Ubuntu 22.04 LTS", asset_type="Server", status="Vulnerable", owner="DevOps", location="us-east-1"),
    Asset(hostname="bastion-host", ip_address="52.23.145.67", os="Amazon Linux 2023", asset_type="Server", status="Online", owner="Network Security", location="us-east-1"),
    Asset(hostname="fw-edge-01", ip_address="10.0.0.1", os="Palo Alto PAN-OS 11.1", asset_type="Network", status="Online", owner="Network Security", location="us-east-1"),
    Asset(hostname="fw-edge-02", ip_address="10.0.0.2", os="Palo Alto PAN-OS 11.1", asset_type="Network", status="Online", owner="Network Security", location="us-west-2"),
    Asset(hostname="vpn-gateway", ip_address="10.0.0.10", os="Cisco IOS XE 17.9", asset_type="Network", status="Online", owner="Network Security", location="us-east-1"),
    Asset(hostname="switch-core-01", ip_address="192.168.1.1", os="Cisco IOS 15.2", asset_type="Network", status="Offline", owner="Network Security", location="HQ-Datacenter"),
    Asset(hostname="wks-finance-01", ip_address="192.168.10.45", os="Windows 11 Pro", asset_type="Endpoint", status="Vulnerable", owner="Finance Dept", location="HQ-Floor2"),
    Asset(hostname="wks-hr-03", ip_address="192.168.10.78", os="Windows 11 Pro", asset_type="Endpoint", status="Online", owner="HR Dept", location="HQ-Floor3"),
    Asset(hostname="wks-eng-22", ip_address="192.168.20.22", os="macOS 14.4 Sonoma", asset_type="Endpoint", status="Online", owner="Engineering", location="Remote"),
    Asset(hostname="wks-eng-23", ip_address="192.168.20.23", os="macOS 14.4 Sonoma", asset_type="Endpoint", status="Online", owner="Engineering", location="Remote"),
    Asset(hostname="wks-exec-ceo", ip_address="192.168.5.2", os="macOS 14.4 Sonoma", asset_type="Endpoint", status="Online", owner="Executive", location="HQ-Floor5"),
    Asset(hostname="jenkins-ci-01", ip_address="10.0.4.20", os="Ubuntu 20.04 LTS", asset_type="Server", status="Vulnerable", owner="DevOps", location="us-east-1"),
    Asset(hostname="splunk-indexer", ip_address="10.0.5.30", os="CentOS 7.9", asset_type="Server", status="Online", owner="SOC Team", location="us-east-1"),
    Asset(hostname="elk-stack-01", ip_address="10.0.5.31", os="Ubuntu 22.04 LTS", asset_type="Server", status="Online", owner="SOC Team", location="us-east-1"),
]

db.add_all(ASSETS)
db.commit()
for a in ASSETS:
    db.refresh(a)
print(f"  Added {len(ASSETS)} assets.")

asset_ids = [a.id for a in ASSETS]


def days_ago(n):
    return datetime.utcnow() - timedelta(days=n, hours=random.randint(0, 23))


print("Seeding threats...")

THREATS = [
    Threat(title="Cobalt Strike Beacon Detected on db-primary", description="EDR telemetry identified Cobalt Strike beacon process injection on the primary database server. C2 communication detected over port 443 to a known malicious IP.", severity="CRITICAL", status="Investigating", threat_type="Malware", mitre_tactic="Command and Control", mitre_technique="T1071.001", source_ip="198.51.100.42", destination_ip="10.0.2.5", affected_system="db-primary", asset_id=ASSETS[2].id, created_at=days_ago(1)),
    Threat(title="Spear-Phishing Campaign Targeting Finance Team", description="Multiple finance department employees received crafted phishing emails impersonating the CFO with malicious Excel attachments containing macro-enabled payload delivery.", severity="HIGH", status="Open", threat_type="Phishing", mitre_tactic="Initial Access", mitre_technique="T1566.001", source_ip="185.220.101.5", destination_ip="192.168.10.45", affected_system="wks-finance-01", asset_id=ASSETS[12].id, created_at=days_ago(2)),
    Threat(title="RDP Brute Force Against Bastion Host", description="Sustained RDP brute force attack from distributed IP ranges targeting the bastion host. Over 15,000 authentication attempts detected in 4 hours.", severity="HIGH", status="Resolved", threat_type="Brute Force", mitre_tactic="Credential Access", mitre_technique="T1110.001", source_ip="45.33.32.156", destination_ip="52.23.145.67", affected_system="bastion-host", asset_id=ASSETS[7].id, created_at=days_ago(5)),
    Threat(title="Suspicious Lateral Movement via PsExec", description="PsExec usage detected originating from compromised endpoint moving laterally to k8s-worker-02. Pass-the-hash attack pattern identified in NTLM authentication logs.", severity="CRITICAL", status="Investigating", threat_type="Lateral Movement", mitre_tactic="Lateral Movement", mitre_technique="T1021.002", source_ip="192.168.10.45", destination_ip="10.0.3.11", affected_system="k8s-worker-02", asset_id=ASSETS[6].id, created_at=days_ago(0)),
    Threat(title="SQL Injection on Web Application API", description="SQL injection attack detected targeting the /api/users endpoint. UNION-based extraction technique used to enumerate database schema. WAF partially blocked but attacker adapted payload.", severity="HIGH", status="Resolved", threat_type="SQL Injection", mitre_tactic="Collection", mitre_technique="T1213", source_ip="91.108.56.130", destination_ip="10.0.1.10", affected_system="web-prod-01", asset_id=ASSETS[0].id, created_at=days_ago(7)),
    Threat(title="Ransomware Precursor: Bulk File Staging Detected", description="Behavioral analytics detected bulk file compression and staging activity on wks-finance-01 consistent with pre-ransomware data collection. Files staged in C:\\Users\\Public\\temp directory.", severity="CRITICAL", status="Open", threat_type="Ransomware", mitre_tactic="Collection", mitre_technique="T1560.001", source_ip=None, destination_ip="192.168.10.45", affected_system="wks-finance-01", asset_id=ASSETS[12].id, created_at=days_ago(0)),
    Threat(title="Insider Threat: Bulk Download of Sensitive Records", description="UEBA alert triggered by wks-hr-03 user downloading 3.2GB of employee PII records to external USB drive outside business hours. Access does not align with user role.", severity="HIGH", status="Investigating", threat_type="Insider Threat", mitre_tactic="Exfiltration", mitre_technique="T1052.001", source_ip=None, destination_ip="192.168.10.78", affected_system="wks-hr-03", asset_id=ASSETS[13].id, created_at=days_ago(3)),
    Threat(title="DDoS Attack on Web Frontend", description="Volumetric DDoS attack targeting web-prod-01 and web-prod-02. Peak traffic exceeded 45Gbps from distributed botnet. Scrubbing center activated, impact partially mitigated.", severity="HIGH", status="Resolved", threat_type="DDoS", mitre_tactic="Impact", mitre_technique="T1498.001", source_ip="0.0.0.0", destination_ip="10.0.1.10", affected_system="web-prod-01, web-prod-02", asset_id=ASSETS[0].id, created_at=days_ago(10)),
    Threat(title="Data Exfiltration via DNS Tunneling", description="DNS tunneling detected from jenkins-ci-01 to external domain 'exfil-c2.xyz'. High-frequency DNS queries with unusually long subdomain strings indicate covert data exfiltration channel.", severity="CRITICAL", status="Open", threat_type="Data Exfiltration", mitre_tactic="Exfiltration", mitre_technique="T1048.003", source_ip="10.0.4.20", destination_ip="8.8.8.8", affected_system="jenkins-ci-01", asset_id=ASSETS[17].id, created_at=days_ago(1)),
    Threat(title="CVE-2024-21413 Exploitation Attempt", description="Exploitation attempt against Microsoft Outlook RCE vulnerability CVE-2024-21413 detected targeting executive endpoints. Zero-click exploit pattern identified in email headers.", severity="CRITICAL", status="Investigating", threat_type="Zero-Day Exploit", mitre_tactic="Execution", mitre_technique="T1203", source_ip="77.88.55.88", destination_ip="192.168.5.2", affected_system="wks-exec-ceo", asset_id=ASSETS[16].id, created_at=days_ago(2)),
    Threat(title="Unauthorized Kubernetes API Access", description="Anomalous API calls to Kubernetes control plane from unknown service account. Attacker attempted to create privileged pods and access cluster secrets.", severity="HIGH", status="Resolved", threat_type="Lateral Movement", mitre_tactic="Privilege Escalation", mitre_technique="T1611", source_ip="10.0.3.10", destination_ip="10.0.3.1", affected_system="k8s-master-01", asset_id=ASSETS[4].id, created_at=days_ago(6)),
    Threat(title="Mimikatz Credential Dumping Detected", description="EDR alert triggered by Mimikatz lsass.exe memory dump on wks-eng-22. Multiple credential sets at risk. Immediate password rotation required for affected accounts.", severity="HIGH", status="Open", threat_type="Malware", mitre_tactic="Credential Access", mitre_technique="T1003.001", source_ip=None, destination_ip="192.168.20.22", affected_system="wks-eng-22", asset_id=ASSETS[14].id, created_at=days_ago(1)),
    Threat(title="Port Scan from Internal Host", description="Comprehensive port scan of internal network subnets detected originating from db-replica. May indicate compromised host performing internal reconnaissance.", severity="MEDIUM", status="Investigating", threat_type="Lateral Movement", mitre_tactic="Discovery", mitre_technique="T1046", source_ip="10.0.2.6", destination_ip="10.0.0.0/8", affected_system="Internal Network", asset_id=ASSETS[3].id, created_at=days_ago(4)),
    Threat(title="Suspicious PowerShell Execution Policy Bypass", description="PowerShell execution policy bypass detected on multiple endpoints using -ExecutionPolicy Bypass flag. Scripts downloaded from remote URLs and executed in memory.", severity="MEDIUM", status="Resolved", threat_type="Malware", mitre_tactic="Defense Evasion", mitre_technique="T1059.001", source_ip=None, destination_ip="192.168.20.23", affected_system="wks-eng-23", asset_id=ASSETS[15].id, created_at=days_ago(8)),
    Threat(title="VPN Credential Stuffing Attack", description="Credential stuffing attack against VPN gateway using list of 45,000 leaked credentials. 12 successful authentications from unrecognized geographic locations.", severity="HIGH", status="Open", threat_type="Brute Force", mitre_tactic="Initial Access", mitre_technique="T1078.001", source_ip="185.107.80.202", destination_ip="10.0.0.10", affected_system="vpn-gateway", asset_id=ASSETS[10].id, created_at=days_ago(2)),
]

db.add_all(THREATS)
db.commit()
for t in THREATS:
    db.refresh(t)
print(f"  Added {len(THREATS)} threats.")

print("Seeding alert logs...")

# Create alerts for HIGH/CRITICAL threats that were seeded
alert_threats = [t for t in THREATS if t.severity in ("CRITICAL", "HIGH")]
statuses = ["Sent", "Sent", "Acknowledged", "Pending", "Sent", "Acknowledged", "Pending", "Sent"]
for i, threat in enumerate(alert_threats):
    alert = AlertLog(
        threat_id=threat.id,
        severity=threat.severity,
        message=f"[{threat.severity}] Threat detected: '{threat.title}'. Type: {threat.threat_type}. Immediate SOC review required.",
        recipient="soc-team@sentinelops.internal",
        status=statuses[i % len(statuses)],
        created_at=threat.created_at + timedelta(seconds=30),
        acknowledged_at=threat.created_at + timedelta(hours=2) if statuses[i % len(statuses)] == "Acknowledged" else None,
    )
    db.add(alert)

db.commit()
print(f"  Added {len(alert_threats)} alert logs.")

print("Seeding threat intelligence feed...")

INTEL_ITEMS = [
    ThreatIntel(title="CVE-2024-21413 - Microsoft Outlook RCE", intel_type="CVE", value="CVE-2024-21413", description="Critical remote code execution vulnerability in Microsoft Outlook. Zero-click exploit via specially crafted email. CVSS score 9.8. Actively exploited in the wild by APT28.", severity="CRITICAL", source="NVD / MSRC", tags="microsoft,outlook,rce,zero-click,apt28", confidence=98),
    ThreatIntel(title="CVE-2024-3400 - Palo Alto PAN-OS Command Injection", intel_type="CVE", value="CVE-2024-3400", description="Command injection vulnerability in Palo Alto Networks PAN-OS GlobalProtect feature. Allows unauthenticated remote command execution. Actively exploited since March 2024.", severity="CRITICAL", source="Palo Alto PSIRT / CISA KEV", tags="paloalto,pan-os,command-injection,globalprotect,cisa-kev", confidence=99),
    ThreatIntel(title="CVE-2024-27198 - JetBrains TeamCity Auth Bypass", intel_type="CVE", value="CVE-2024-27198", description="Authentication bypass vulnerability in JetBrains TeamCity before version 2023.11.4. Allows full server takeover without authentication.", severity="CRITICAL", source="JetBrains / NVD", tags="jetbrains,teamcity,auth-bypass,ci-cd", confidence=95),
    ThreatIntel(title="CVE-2023-44487 - HTTP/2 Rapid Reset Attack", intel_type="CVE", value="CVE-2023-44487", description="HTTP/2 protocol vulnerability allowing distributed denial of service via rapid stream resets. Affects major web servers and frameworks. Patch widely available.", severity="HIGH", source="CERT / NVD", tags="http2,ddos,protocol,web-server", confidence=97),
    ThreatIntel(title="CVE-2024-1709 - ConnectWise ScreenConnect Auth Bypass", intel_type="CVE", value="CVE-2024-1709", description="Critical authentication bypass in ConnectWise ScreenConnect allowing unauthenticated access to all client files. Ransomware groups actively exploiting.", severity="CRITICAL", source="ConnectWise / CISA", tags="connectwise,screenconnect,auth-bypass,ransomware,cisa-kev", confidence=99),
    ThreatIntel(title="APT29 (Cozy Bear) - Active Campaign", intel_type="Threat Actor", value="APT29", description="Russian state-sponsored threat actor APT29 conducting active espionage campaigns targeting government and technology sectors. Uses NOBELIUM malware family and spear-phishing with ROOTSAW dropper.", severity="CRITICAL", source="Microsoft MSTIC / Mandiant", tags="russia,apt,espionage,nobelium,rootsaw,spearphishing", confidence=92),
    ThreatIntel(title="Scattered Spider - Financial Sector Targeting", intel_type="Threat Actor", value="Scattered Spider (UNC3944)", description="English-speaking threat actor using social engineering to compromise MFA and helpdesk procedures. Targeting financial services and insurance companies for ransomware deployment.", severity="HIGH", source="CrowdStrike / FBI Advisory", tags="social-engineering,mfa-bypass,ransomware,financial,helpdesk", confidence=88),
    ThreatIntel(title="LockBit 3.0 RaaS - Active Infrastructure", intel_type="Threat Actor", value="LockBit 3.0", description="Ransomware-as-a-service group with active affiliate network. Employs double extortion tactics. Recent law enforcement disruption reduced but did not eliminate operations.", severity="HIGH", source="Europol / FBI", tags="ransomware,raas,double-extortion,lockbit,affiliate", confidence=85),
    ThreatIntel(title="Volt Typhoon - US Critical Infrastructure", intel_type="Threat Actor", value="Volt Typhoon", description="Chinese state-sponsored actor pre-positioning in US critical infrastructure networks using living-off-the-land techniques. Active in energy, water, and telecommunications sectors.", severity="CRITICAL", source="CISA / NSA Advisory", tags="china,apt,critical-infrastructure,lotl,pre-positioning", confidence=94),
    ThreatIntel(title="Malicious IP - Cobalt Strike C2 Node", intel_type="IOC-IP", value="198.51.100.42", description="Confirmed Cobalt Strike command-and-control server. Associated with multiple enterprise compromises in Q1 2024. Hosted on bulletproof hosting in Eastern Europe.", severity="HIGH", source="Recorded Future / VirusTotal", tags="cobalt-strike,c2,malware,bulletproof-hosting", confidence=91),
    ThreatIntel(title="Tor Exit Node - Known Attack Origin", intel_type="IOC-IP", value="185.220.101.5", description="Active Tor exit node used in credential stuffing and phishing campaigns. Frequently changes behavior. Block at perimeter firewall recommended.", severity="MEDIUM", source="Abuse.ch / Shodan", tags="tor,exit-node,anonymization,phishing,brute-force", confidence=82),
    ThreatIntel(title="Botnet C2 - Mirai Variant Infrastructure", intel_type="IOC-IP", value="45.33.32.156", description="Command-and-control infrastructure for Mirai botnet variant targeting IoT devices. Associated with recent DDoS campaigns exceeding 1Tbps.", severity="HIGH", source="Cloudflare Radar / Akamai", tags="mirai,botnet,iot,ddos,c2", confidence=89),
    ThreatIntel(title="DNS Tunneling C2 Domain", intel_type="IOC-Domain", value="exfil-c2.xyz", description="Domain used for DNS tunneling data exfiltration. High-frequency subdomain queries observed from compromised enterprise hosts. Registered through privacy-protected registrar.", severity="CRITICAL", source="Passive DNS / Internal Detection", tags="dns-tunneling,exfiltration,c2,ioc", confidence=96),
    ThreatIntel(title="Phishing Kit Distribution Domain", intel_type="IOC-Domain", value="microsoft-secure-login.com", description="Phishing domain serving credential harvesting kit impersonating Microsoft 365 login. Targets enterprise credentials. SSL certificate issued by Let's Encrypt.", severity="HIGH", source="PhishTank / URLhaus", tags="phishing,microsoft,credential-theft,kit", confidence=93),
    ThreatIntel(title="Ransomware Dropper Domain", intel_type="IOC-Domain", value="update-cdn-delivery.net", description="Domain serving ransomware droppers disguised as software update packages. Used in supply chain attack campaigns. Hosted on compromised WordPress sites.", severity="HIGH", source="MalwareBazaar / ANY.RUN", tags="ransomware,dropper,supply-chain,fake-update", confidence=87),
    ThreatIntel(title="Cobalt Strike Beacon SHA-256 Hash", intel_type="IOC-Hash", value="a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456", description="SHA-256 hash of Cobalt Strike beacon DLL with custom C2 profile. Detected in multiple enterprise compromises. Signed with stolen Authenticode certificate.", severity="CRITICAL", source="VirusTotal / Any.run", tags="cobalt-strike,beacon,dll,authenticode,hash", confidence=98),
    ThreatIntel(title="Ransomware Encryptor Binary Hash", intel_type="IOC-Hash", value="deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678", description="SHA-256 hash of LockBit 3.0 encryptor binary. Targets shadow copy deletion and Active Directory enumeration before encryption.", severity="CRITICAL", source="MalwareBazaar / Hybrid Analysis", tags="lockbit,ransomware,encryptor,shadow-copy,active-directory", confidence=97),
    ThreatIntel(title="Infostealer Malware Hash - Redline Stealer", intel_type="IOC-Hash", value="f1e2d3c4b5a6978801234567890abcdef9876543210fedcba0987654321fedcba", description="SHA-256 hash of Redline Stealer variant targeting browser credentials, cryptocurrency wallets, and VPN configurations. Distributed via Discord and fake gaming software.", severity="HIGH", source="AnyRun / Triage", tags="infostealer,redline,browser-credentials,crypto-wallet,gaming", confidence=90),
    ThreatIntel(title="CVE-2024-6387 - OpenSSH regreSSHion RCE", intel_type="CVE", value="CVE-2024-6387", description="Remote unauthenticated code execution vulnerability in OpenSSH server (sshd) on glibc-based Linux systems. Race condition in signal handler. Affects versions 8.5p1 to 9.8p1.", severity="CRITICAL", source="Qualys / NVD", tags="openssh,rce,linux,race-condition,unauthenticated", confidence=96),
    ThreatIntel(title="APT41 - Dual Espionage/Criminal Operations", intel_type="Threat Actor", value="APT41 (Double Dragon)", description="Chinese state-sponsored threat actor conducting both government-directed espionage and financially motivated cybercrime. Targeting healthcare, telecommunications, and video game industries.", severity="HIGH", source="Mandiant / DOJ Indictment", tags="china,apt,espionage,financial,healthcare,telecom", confidence=91),
]

db.add_all(INTEL_ITEMS)
db.commit()
print(f"  Added {len(INTEL_ITEMS)} threat intel items.")

db.close()
print("\nSeed complete! SentinelOps v3 database is ready.")
