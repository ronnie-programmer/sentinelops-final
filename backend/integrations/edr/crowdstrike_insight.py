import os
import random
import logging
from typing import Any
from integrations.base import IntegrationAdapter

logger = logging.getLogger(__name__)

MOCK_EDR_ALERTS = [
    {
        "severity": "CRITICAL",
        "threat_type": "Process Injection",
        "title_template": "CrowdStrike Insight: Process injection detected on {host}",
        "description_template": "Falcon EDR detected {process} injecting into {target_process} on {host}. Technique: T1055.",
        "processes": ["malware.exe", "loader.dll", "beacon.exe"],
        "target_processes": ["lsass.exe", "explorer.exe", "svchost.exe"],
    },
    {
        "severity": "CRITICAL",
        "threat_type": "Credential Dumping",
        "title_template": "CrowdStrike Insight: Credential dumping on {host}",
        "description_template": "Falcon EDR detected credential harvesting from LSASS memory on {host}. Possible Mimikatz variant.",
        "processes": ["mimikatz.exe", "procdump.exe"],
        "target_processes": ["lsass.exe"],
    },
    {
        "severity": "HIGH",
        "threat_type": "Fileless Malware",
        "title_template": "CrowdStrike Insight: Fileless execution on {host}",
        "description_template": "PowerShell cradle executed in-memory payload on {host}. No disk artifact found.",
        "processes": ["powershell.exe"],
        "target_processes": ["powershell.exe"],
    },
    {
        "severity": "HIGH",
        "threat_type": "Lateral Movement",
        "title_template": "CrowdStrike Insight: WMI lateral movement from {host}",
        "description_template": "WMI-based lateral movement detected originating from {host}. Targeting {count} remote systems.",
        "processes": ["wmiprvse.exe"],
        "target_processes": ["wmiprvse.exe"],
    },
]

HOSTS = ["web-prod-01", "db-primary", "wks-finance-01", "k8s-worker-01", "bastion-host", "dc-01"]


def _is_configured() -> bool:
    has_insight = bool(os.getenv("CROWDSTRIKE_INSIGHT_CLIENT_ID")) and bool(os.getenv("CROWDSTRIKE_INSIGHT_CLIENT_SECRET"))
    has_fallback = bool(os.getenv("CROWDSTRIKE_CLIENT_ID")) and bool(os.getenv("CROWDSTRIKE_CLIENT_SECRET"))
    return has_insight or has_fallback


class CrowdStrikeInsightAdapter(IntegrationAdapter):
    provider_name = "crowdstrike_insight"

    def __init__(self):
        self.is_mock = not _is_configured()
        self.client_id = os.getenv("CROWDSTRIKE_INSIGHT_CLIENT_ID") or os.getenv("CROWDSTRIKE_CLIENT_ID")
        self.client_secret = os.getenv("CROWDSTRIKE_INSIGHT_CLIENT_SECRET") or os.getenv("CROWDSTRIKE_CLIENT_SECRET")
        self.base_url = os.getenv("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com")
        if self.is_mock:
            logger.info("CrowdStrike Insight adapter running in MOCK mode")

    def poll_alerts(self) -> list[dict[str, Any]]:
        if self.is_mock:
            return self._mock_alerts()
        return self._real_poll()

    def _mock_alerts(self) -> list[dict[str, Any]]:
        count = random.randint(1, 3)
        alerts = []
        for _ in range(count):
            tmpl = random.choice(MOCK_EDR_ALERTS)
            host = random.choice(HOSTS)
            process = random.choice(tmpl["processes"])
            target = random.choice(tmpl["target_processes"])
            alerts.append({
                "external_id": f"csi-{random.randint(100000, 999999)}",
                "title": tmpl["title_template"].format(host=host, process=process, count=random.randint(3, 10)),
                "description": tmpl["description_template"].format(host=host, process=process, target_process=target, count=random.randint(3, 10)),
                "severity": tmpl["severity"],
                "threat_type": tmpl["threat_type"],
                "source_ip": f"10.0.{random.randint(1, 5)}.{random.randint(1, 254)}",
                "affected_system": host,
                "source": "crowdstrike_insight",
            })
        return alerts

    def _real_poll(self) -> list[dict[str, Any]]:
        try:
            import requests
            r = requests.post(
                f"{self.base_url}/oauth2/token",
                data={"client_id": self.client_id, "client_secret": self.client_secret},
                timeout=15,
            )
            r.raise_for_status()
            token = r.json()["access_token"]
            r = requests.get(
                f"{self.base_url}/detects/queries/detects/v1",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": 10, "filter": "status:'new'+max_severity_displayname:['Critical','High']"},
                timeout=15,
            )
            r.raise_for_status()
            detection_ids = r.json().get("resources", [])
            if not detection_ids:
                return []
            r = requests.post(
                f"{self.base_url}/detects/entities/summaries/GET/v1",
                headers={"Authorization": f"Bearer {token}"},
                json={"ids": detection_ids[:5]},
                timeout=15,
            )
            r.raise_for_status()
            detections = r.json().get("resources", [])
            normalized = []
            for d in detections:
                normalized.append({
                    "external_id": d.get("detection_id", ""),
                    "title": f"CrowdStrike Insight: {d.get('scenario', 'EDR Detection')}",
                    "description": d.get("behaviors", [{}])[0].get("description", "EDR detection"),
                    "severity": {"Critical": "CRITICAL", "High": "HIGH", "Medium": "MEDIUM"}.get(
                        d.get("max_severity_displayname", "Medium"), "MEDIUM"),
                    "threat_type": "EDR Detection",
                    "source_ip": "",
                    "affected_system": d.get("device", {}).get("hostname", ""),
                    "source": "crowdstrike_insight",
                })
            return normalized
        except Exception as exc:
            logger.error("CrowdStrike Insight real poll failed: %s", exc)
            return []

    def push_acknowledgement(self, alert_id: str) -> bool:
        if self.is_mock:
            return True
        try:
            # In real impl: update detection status
            return True
        except Exception as exc:
            logger.error("CrowdStrike Insight acknowledge failed: %s", exc)
            return False

    def isolate_host(self, hostname: str, device_id: str = "") -> dict:
        """Isolate a host via Falcon Real Time Response API."""
        if self.is_mock:
            logger.info("Mock: isolate_host %s", hostname)
            return {"status": "mock_isolated", "hostname": hostname}
        try:
            import requests
            r = requests.post(
                f"{self.base_url}/oauth2/token",
                data={"client_id": self.client_id, "client_secret": self.client_secret},
                timeout=15,
            )
            r.raise_for_status()
            token = r.json()["access_token"]
            r = requests.post(
                f"{self.base_url}/devices/entities/devices-actions/v2",
                headers={"Authorization": f"Bearer {token}"},
                params={"action_name": "contain"},
                json={"ids": [device_id or hostname]},
                timeout=15,
            )
            r.raise_for_status()
            return {"status": "isolated", "hostname": hostname}
        except Exception as exc:
            logger.error("Host isolation failed for %s: %s", hostname, exc)
            return {"status": "error", "message": str(exc)}

    def get_process_tree(self, hostname: str) -> list[dict]:
        """Fetch process tree for a host (stub for non-mock)."""
        if self.is_mock:
            return [
                {"pid": 1, "name": "System", "parent_pid": 0},
                {"pid": 4, "name": "explorer.exe", "parent_pid": 1},
                {"pid": random.randint(1000, 9999), "name": "suspicious.exe", "parent_pid": 4},
            ]
        return []  # Real impl would use RTR API
