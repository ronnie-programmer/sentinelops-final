import os
import random
import logging
from datetime import datetime, timedelta
from typing import Any
from integrations.base import IntegrationAdapter

logger = logging.getLogger(__name__)

MOCK_ALERT_TEMPLATES = [
    {
        "severity": "CRITICAL",
        "threat_type": "Malware",
        "title_template": "CrowdStrike: {malware} detected on {host}",
        "description_template": "CrowdStrike Falcon detected {malware} executing on {host}. Process tree shows parent-child relationship with {parent}.",
        "source_ip_range": ["185.220.101.", "91.108.4.", "198.51.100."],
        "malware_names": ["WannaCry.B", "Emotet.Gen", "Cobalt Strike Beacon", "BlackCat Ransomware", "RedLine Stealer"],
    },
    {
        "severity": "HIGH",
        "threat_type": "Lateral Movement",
        "title_template": "CrowdStrike: Lateral movement from {host}",
        "description_template": "CrowdStrike Falcon Prevent detected lateral movement attempt. {host} attempting authentication against {count} internal systems.",
        "source_ip_range": ["10.0.1.", "10.0.2.", "192.168."],
        "malware_names": [],
    },
    {
        "severity": "HIGH",
        "threat_type": "Brute Force",
        "title_template": "CrowdStrike: Credential stuffing against {host}",
        "description_template": "CrowdStrike Identity Protection flagged {count} failed authentication attempts in 60 seconds against {host}.",
        "source_ip_range": ["203.0.113.", "198.51.100.", "185.220."],
        "malware_names": [],
    },
    {
        "severity": "MEDIUM",
        "threat_type": "Data Exfiltration",
        "title_template": "CrowdStrike: Suspicious data staging on {host}",
        "description_template": "Large volume of file compression and staging activity detected on {host}. Potential data exfiltration precursor.",
        "source_ip_range": ["10.0.", "192.168."],
        "malware_names": [],
    },
]

HOSTS = ["web-prod-01", "db-primary", "wks-finance-01", "k8s-worker-01", "bastion-host", "wks-exec-ceo"]


def _is_configured() -> bool:
    return bool(os.getenv("CROWDSTRIKE_CLIENT_ID")) and bool(os.getenv("CROWDSTRIKE_CLIENT_SECRET"))


class CrowdStrikeAdapter(IntegrationAdapter):
    provider_name = "crowdstrike"

    def __init__(self):
        self.is_mock = not _is_configured()
        if self.is_mock:
            logger.info("CrowdStrike adapter running in MOCK mode (no credentials configured)")

    def poll_alerts(self) -> list[dict[str, Any]]:
        if self.is_mock:
            return self._mock_alerts()
        return self._real_poll()

    def _mock_alerts(self) -> list[dict[str, Any]]:
        count = random.randint(2, 5)
        alerts = []
        for _ in range(count):
            tmpl = random.choice(MOCK_ALERT_TEMPLATES)
            host = random.choice(HOSTS)
            ip_prefix = random.choice(tmpl["source_ip_range"])
            source_ip = ip_prefix + str(random.randint(1, 254))
            malware = random.choice(tmpl["malware_names"]) if tmpl["malware_names"] else "Unknown"
            parent = random.choice(["explorer.exe", "cmd.exe", "powershell.exe", "svchost.exe"])
            alert_count = random.randint(100, 5000)
            alerts.append({
                "external_id": f"cs-{random.randint(100000, 999999)}",
                "title": tmpl["title_template"].format(host=host, malware=malware, count=alert_count),
                "description": tmpl["description_template"].format(host=host, malware=malware, count=alert_count, parent=parent),
                "severity": tmpl["severity"],
                "threat_type": tmpl["threat_type"],
                "source_ip": source_ip,
                "affected_system": host,
                "source": "crowdstrike",
                "raw_severity": random.randint(60, 100),
            })
        return alerts

    def _real_poll(self) -> list[dict[str, Any]]:
        """Real CrowdStrike Falcon API poll (OAuth2 + detections endpoint)."""
        try:
            import requests
            client_id = os.getenv("CROWDSTRIKE_CLIENT_ID")
            client_secret = os.getenv("CROWDSTRIKE_CLIENT_SECRET")
            base_url = os.getenv("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com")

            # Get OAuth2 token
            r = requests.post(
                f"{base_url}/oauth2/token",
                data={"client_id": client_id, "client_secret": client_secret},
                timeout=15,
            )
            r.raise_for_status()
            token = r.json()["access_token"]

            # Fetch detections
            r = requests.get(
                f"{base_url}/detects/queries/detects/v1",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": 20, "filter": "status:'new'"},
                timeout=15,
            )
            r.raise_for_status()
            detection_ids = r.json().get("resources", [])
            if not detection_ids:
                return []

            r = requests.post(
                f"{base_url}/detects/entities/summaries/GET/v1",
                headers={"Authorization": f"Bearer {token}"},
                json={"ids": detection_ids[:10]},
                timeout=15,
            )
            r.raise_for_status()
            detections = r.json().get("resources", [])

            normalized = []
            for d in detections:
                severity_score = d.get("max_severity_displayname", "Medium")
                severity_map = {"Critical": "CRITICAL", "High": "HIGH", "Medium": "MEDIUM", "Low": "LOW"}
                normalized.append({
                    "external_id": d.get("detection_id", ""),
                    "title": f"CrowdStrike: {d.get('scenario', 'Detection')} on {d.get('device', {}).get('hostname', 'unknown')}",
                    "description": d.get("behaviors", [{}])[0].get("description", "CrowdStrike detection"),
                    "severity": severity_map.get(severity_score, "MEDIUM"),
                    "threat_type": "Malware",
                    "source_ip": d.get("behaviors", [{}])[0].get("network_accesses", [{}])[0].get("remote_address", ""),
                    "affected_system": d.get("device", {}).get("hostname", ""),
                    "source": "crowdstrike",
                })
            return normalized
        except Exception as exc:
            logger.error("CrowdStrike real poll failed: %s", exc)
            return []

    def push_acknowledgement(self, alert_id: str) -> bool:
        if self.is_mock:
            logger.info("Mock CrowdStrike acknowledge: %s", alert_id)
            return True
        try:
            import requests
            # In real impl: PATCH detection status to "in_progress"
            return True
        except Exception as exc:
            logger.error("CrowdStrike acknowledge failed: %s", exc)
            return False
