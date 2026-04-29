import os
import random
import logging
from typing import Any
from integrations.edr.base import EDRAdapter

logger = logging.getLogger(__name__)

MOCK_S1_TEMPLATES = [
    {
        "severity": "CRITICAL",
        "threat_type": "Ransomware",
        "title": "SentinelOne: Ransomware behavior detected",
        "description_template": "Behavioral AI flagged rapid file encryption activity on {host} (agent {agent_id}). {file_count} files encrypted in {seconds}s. Auto-mitigation: kill+quarantine.",
    },
    {
        "severity": "HIGH",
        "threat_type": "Suspicious Process Chain",
        "title": "SentinelOne: Anomalous process lineage",
        "description_template": "Static AI flagged process chain on {host}: cmd.exe → powershell.exe → regsvr32.exe → suspicious DLL load. Storyline: {storyline}.",
    },
    {
        "severity": "HIGH",
        "threat_type": "C2 Beaconing",
        "title": "SentinelOne: Outbound C2 communication",
        "description_template": "Endpoint {host} beaconing to known C2 infrastructure {ip} every {interval}s. Storyline: {storyline}.",
    },
    {
        "severity": "MEDIUM",
        "threat_type": "Privilege Escalation",
        "title": "SentinelOne: Privilege escalation attempt",
        "description_template": "Process on {host} attempted privilege escalation via {technique}. Storyline: {storyline}.",
    },
    {
        "severity": "HIGH",
        "threat_type": "Persistence",
        "title": "SentinelOne: Scheduled task persistence",
        "description_template": "Suspicious scheduled task created on {host} pointing to {path}. Possible T1053.005 persistence.",
    },
]

HOSTS = ["workstation-101", "laptop-exec-01", "server-app-02", "dc-backup", "kiosk-01", "wks-finance-04"]
TECHNIQUES = ["Token Impersonation", "UAC Bypass", "DLL Search Order Hijack", "Named Pipe Impersonation"]
PERSIST_PATHS = [
    r"C:\Windows\Temp\update.exe",
    r"C:\ProgramData\svc.exe",
    r"C:\Users\Public\Downloads\helper.dll",
]


def _is_configured() -> bool:
    return bool(os.getenv("SENTINELONE_API_KEY")) and bool(os.getenv("SENTINELONE_MANAGEMENT_URL"))


class SentinelOneAdapter(EDRAdapter):
    """SentinelOne Singularity EDR — endpoint behavioral AI alerts plus
    response actions (disconnect from network, kill process)."""

    provider_name = "sentinelone"

    def __init__(self):
        self.is_mock = not _is_configured()
        self.api_key = os.getenv("SENTINELONE_API_KEY", "")
        self.management_url = os.getenv("SENTINELONE_MANAGEMENT_URL", "https://usea1.sentinelone.net")
        if self.is_mock:
            logger.info("SentinelOne adapter running in MOCK mode")

    def poll_alerts(self) -> list[dict[str, Any]]:
        if self.is_mock:
            return self._mock_alerts()
        return self._real_poll()

    def _mock_alerts(self) -> list[dict[str, Any]]:
        count = random.randint(1, 3)
        alerts = []
        for _ in range(count):
            tmpl = random.choice(MOCK_S1_TEMPLATES)
            host = random.choice(HOSTS)
            agent_id = f"s1-{random.randint(100000, 999999)}"
            storyline = f"{random.randint(10**14, 10**15 - 1):X}"
            alerts.append({
                "external_id": agent_id,
                "title": tmpl["title"],
                "description": tmpl["description_template"].format(
                    host=host,
                    agent_id=agent_id,
                    ip=f"185.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
                    technique=random.choice(TECHNIQUES),
                    file_count=random.randint(50, 5000),
                    seconds=random.randint(2, 30),
                    interval=random.randint(30, 600),
                    storyline=storyline,
                    path=random.choice(PERSIST_PATHS),
                ),
                "severity": tmpl["severity"],
                "threat_type": tmpl["threat_type"],
                "source_ip": f"10.0.{random.randint(1, 5)}.{random.randint(1, 254)}",
                "affected_system": host,
                "source": "sentinelone",
                "host_id": agent_id,
                "process_id": str(random.randint(1000, 65000)),
            })
        return alerts

    def _real_poll(self) -> list[dict[str, Any]]:
        try:
            import requests
            headers = {
                "Authorization": f"ApiToken {self.api_key}",
                "Content-Type": "application/json",
            }
            r = requests.get(
                f"{self.management_url}/web/api/v2.1/threats",
                headers=headers,
                params={"limit": 10, "resolved": "false", "sortOrder": "desc", "sortBy": "createdAt"},
                timeout=15,
            )
            r.raise_for_status()
            threats = r.json().get("data", [])
            severity_map = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
            normalized = []
            for t in threats:
                info = t.get("threatInfo", {}) or {}
                agent = t.get("agentRealtimeInfo", {}) or {}
                normalized.append({
                    "external_id": t.get("id", ""),
                    "title": f"SentinelOne: {info.get('threatName', 'Threat')}",
                    "description": info.get("classification", "SentinelOne EDR detection"),
                    "severity": severity_map.get((info.get("confidenceLevel") or "medium").lower(), "MEDIUM"),
                    "threat_type": info.get("classification", "Malware"),
                    "affected_system": agent.get("agentComputerName", ""),
                    "source": "sentinelone",
                    "host_id": agent.get("agentId", ""),
                })
            return normalized
        except Exception as exc:
            logger.error("SentinelOne real poll failed: %s", exc)
            return []

    def push_acknowledgement(self, alert_id: str) -> bool:
        if self.is_mock:
            logger.info("Mock SentinelOne acknowledge: %s", alert_id)
            return True
        return True

    def isolate_host(self, host_id: str) -> dict[str, Any]:
        if self.is_mock:
            logger.info("Mock isolate_host(%s) on SentinelOne", host_id)
            return {"ok": True, "message": f"[MOCK] Disconnect-from-network issued for agent {host_id}"}
        try:
            import requests
            r = requests.post(
                f"{self.management_url}/web/api/v2.1/agents/actions/disconnect",
                headers={"Authorization": f"ApiToken {self.api_key}", "Content-Type": "application/json"},
                json={"filter": {"ids": [host_id]}},
                timeout=15,
            )
            r.raise_for_status()
            return {"ok": True, "message": f"Disconnect issued for {host_id}"}
        except Exception as exc:
            logger.error("SentinelOne isolate_host failed: %s", exc)
            return {"ok": False, "message": str(exc)}

    def kill_process(self, host_id: str, process_id: str) -> dict[str, Any]:
        if self.is_mock:
            logger.info("Mock kill_process(host=%s, pid=%s) on SentinelOne", host_id, process_id)
            return {"ok": True, "message": f"[MOCK] Mitigate-kill issued for PID {process_id} on agent {host_id}"}
        try:
            import requests
            r = requests.post(
                f"{self.management_url}/web/api/v2.1/threats/mitigate/kill",
                headers={"Authorization": f"ApiToken {self.api_key}", "Content-Type": "application/json"},
                json={"filter": {"ids": [host_id]}},
                timeout=15,
            )
            r.raise_for_status()
            return {"ok": True, "message": f"Mitigate-kill issued for {host_id}"}
        except Exception as exc:
            logger.error("SentinelOne kill_process failed: %s", exc)
            return {"ok": False, "message": str(exc)}
