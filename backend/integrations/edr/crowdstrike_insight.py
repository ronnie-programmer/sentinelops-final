import os
import random
import logging
from typing import Any
from integrations.edr.base import EDRAdapter

logger = logging.getLogger(__name__)

MOCK_EDR_TEMPLATES = [
    {
        "severity": "CRITICAL",
        "threat_type": "Process Injection",
        "title_template": "CrowdStrike Insight: Process injection on {host}",
        "description_template": "Falcon EDR observed {process} injecting into {target} on {host}. Maps to MITRE T1055 (Process Injection).",
        "processes": ["loader.dll", "beacon.exe", "implant.dll"],
        "targets": ["lsass.exe", "explorer.exe", "svchost.exe"],
    },
    {
        "severity": "CRITICAL",
        "threat_type": "Credential Dumping",
        "title_template": "CrowdStrike Insight: LSASS credential access on {host}",
        "description_template": "Falcon EDR detected memory read of lsass.exe by {process} on {host}. Possible Mimikatz / pypykatz variant. T1003.001.",
        "processes": ["mimikatz.exe", "procdump.exe", "rundll32.exe"],
        "targets": ["lsass.exe"],
    },
    {
        "severity": "HIGH",
        "threat_type": "Fileless Execution",
        "title_template": "CrowdStrike Insight: In-memory PowerShell payload on {host}",
        "description_template": "PowerShell cradle executed an in-memory payload on {host} with no disk artifact. Encoded command length: {enc_len} bytes. T1059.001.",
        "processes": ["powershell.exe"],
        "targets": ["powershell.exe"],
    },
    {
        "severity": "HIGH",
        "threat_type": "Lateral Movement",
        "title_template": "CrowdStrike Insight: WMI lateral movement from {host}",
        "description_template": "WMI-based lateral movement originating from {host} targeting {count} remote systems via Win32_Process.Create. T1047.",
        "processes": ["wmiprvse.exe"],
        "targets": ["wmiprvse.exe"],
    },
    {
        "severity": "MEDIUM",
        "threat_type": "Defense Evasion",
        "title_template": "CrowdStrike Insight: Security tool tampering on {host}",
        "description_template": "Process {process} attempted to disable Windows Defender / EDR sensor on {host}. T1562.001.",
        "processes": ["sc.exe", "powershell.exe", "reg.exe"],
        "targets": ["MsMpEng.exe", "CSFalconService.exe"],
    },
]

HOSTS = ["web-prod-01", "db-primary", "wks-finance-01", "k8s-worker-01", "bastion-host", "dc-01", "wks-exec-ceo"]


def _is_configured() -> bool:
    has_insight = bool(os.getenv("CROWDSTRIKE_INSIGHT_CLIENT_ID")) and bool(os.getenv("CROWDSTRIKE_INSIGHT_CLIENT_SECRET"))
    has_fallback = bool(os.getenv("CROWDSTRIKE_CLIENT_ID")) and bool(os.getenv("CROWDSTRIKE_CLIENT_SECRET"))
    return has_insight or has_fallback


class CrowdStrikeInsightAdapter(EDRAdapter):
    """CrowdStrike Falcon Insight EDR — deeper endpoint telemetry (process trees,
    in-memory payloads, lateral movement) compared to the base CrowdStrike adapter
    which surfaces detection-summary alerts."""

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
            tmpl = random.choice(MOCK_EDR_TEMPLATES)
            host = random.choice(HOSTS)
            process = random.choice(tmpl["processes"])
            target = random.choice(tmpl["targets"])
            ext_id = f"csi-{random.randint(100000, 999999)}"
            alerts.append({
                "external_id": ext_id,
                "title": tmpl["title_template"].format(host=host, process=process),
                "description": tmpl["description_template"].format(
                    host=host,
                    process=process,
                    target=target,
                    count=random.randint(3, 10),
                    enc_len=random.randint(1024, 16384),
                ),
                "severity": tmpl["severity"],
                "threat_type": tmpl["threat_type"],
                "source_ip": f"10.0.{random.randint(1, 5)}.{random.randint(1, 254)}",
                "affected_system": host,
                "source": "crowdstrike_insight",
                "host_id": ext_id,
                "process_id": str(random.randint(1000, 65000)),
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
                f"{self.base_url}/incidents/queries/incidents/v1",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": 20, "filter": "status:'20'"},
                timeout=15,
            )
            r.raise_for_status()
            incident_ids = r.json().get("resources", [])
            if not incident_ids:
                return []
            r = requests.post(
                f"{self.base_url}/incidents/entities/incidents/GET/v1",
                headers={"Authorization": f"Bearer {token}"},
                json={"ids": incident_ids[:10]},
                timeout=15,
            )
            r.raise_for_status()
            incidents = r.json().get("resources", [])
            severity_map = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
            normalized = []
            for inc in incidents:
                fine = inc.get("fine_score", 0)
                sev_tier = max(1, min(4, (fine // 25) + 1))
                hosts = inc.get("hosts", [])
                hostname = hosts[0].get("hostname", "") if hosts else ""
                normalized.append({
                    "external_id": inc.get("incident_id", ""),
                    "title": f"CrowdStrike Insight: {inc.get('name', 'Incident')} on {hostname}",
                    "description": inc.get("description", "Falcon Insight EDR incident"),
                    "severity": severity_map[sev_tier],
                    "threat_type": "EDR Incident",
                    "affected_system": hostname,
                    "source": "crowdstrike_insight",
                    "host_id": hosts[0].get("device_id", "") if hosts else "",
                })
            return normalized
        except Exception as exc:
            logger.error("CrowdStrike Insight real poll failed: %s", exc)
            return []

    def push_acknowledgement(self, alert_id: str) -> bool:
        if self.is_mock:
            logger.info("Mock CrowdStrike Insight acknowledge: %s", alert_id)
            return True
        return True

    def isolate_host(self, host_id: str) -> dict[str, Any]:
        if self.is_mock:
            logger.info("Mock isolate_host(%s) on CrowdStrike Insight", host_id)
            return {"ok": True, "message": f"[MOCK] Network containment requested for device {host_id}"}
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
                json={"ids": [host_id]},
                timeout=15,
            )
            r.raise_for_status()
            return {"ok": True, "message": f"Containment issued for {host_id}"}
        except Exception as exc:
            logger.error("CrowdStrike Insight isolate_host failed: %s", exc)
            return {"ok": False, "message": str(exc)}

    def kill_process(self, host_id: str, process_id: str) -> dict[str, Any]:
        if self.is_mock:
            logger.info("Mock kill_process(host=%s, pid=%s) on CrowdStrike Insight", host_id, process_id)
            return {"ok": True, "message": f"[MOCK] Real-time response kill issued for PID {process_id} on {host_id}"}
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
                f"{self.base_url}/real-time-response/entities/admin-command/v1",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "device_id": host_id,
                    "base_command": "kill",
                    "command_string": f"kill {process_id}",
                },
                timeout=20,
            )
            r.raise_for_status()
            return {"ok": True, "message": f"Kill command sent for PID {process_id} on {host_id}"}
        except Exception as exc:
            logger.error("CrowdStrike Insight kill_process failed: %s", exc)
            return {"ok": False, "message": str(exc)}
