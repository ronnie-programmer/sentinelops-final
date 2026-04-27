import os
import random
import logging
from typing import Any
from integrations.base import IntegrationAdapter

logger = logging.getLogger(__name__)

MOCK_S1_ALERTS = [
    {
        "severity": "CRITICAL",
        "threat_type": "Ransomware",
        "title": "SentinelOne: Ransomware behavior detected",
        "description_template": "SentinelOne Behavioral AI detected ransomware activity on {host}. File encryption started. Agent: {agent_id}.",
    },
    {
        "severity": "HIGH",
        "threat_type": "Suspicious Process",
        "title": "SentinelOne: Suspicious process chain",
        "description_template": "SentinelOne detected anomalous process chain on {host}: cmd.exe → powershell.exe → regsvr32.exe.",
    },
    {
        "severity": "HIGH",
        "threat_type": "Network Anomaly",
        "title": "SentinelOne: Outbound C2 communication",
        "description_template": "SentinelOne detected outbound beaconing from {host} to known C2 infrastructure at {ip}.",
    },
    {
        "severity": "MEDIUM",
        "threat_type": "Privilege Escalation",
        "title": "SentinelOne: Privilege escalation attempt",
        "description_template": "SentinelOne detected process attempting to escalate privileges via {technique} on {host}.",
    },
]

HOSTS = ["workstation-101", "laptop-exec-01", "server-app-02", "dc-backup", "kiosk-01"]
TECHNIQUES = ["Token Impersonation", "UAC Bypass", "DLL Injection", "Kernel Exploit"]


def _is_configured() -> bool:
    return bool(os.getenv("SENTINELONE_API_KEY")) and bool(os.getenv("SENTINELONE_MANAGEMENT_URL"))


class SentinelOneAdapter(IntegrationAdapter):
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
            tmpl = random.choice(MOCK_S1_ALERTS)
            host = random.choice(HOSTS)
            agent_id = f"s1-{random.randint(100000, 999999)}"
            alerts.append({
                "external_id": agent_id,
                "title": tmpl["title"],
                "description": tmpl["description_template"].format(
                    host=host,
                    agent_id=agent_id,
                    ip=f"185.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
                    technique=random.choice(TECHNIQUES),
                ),
                "severity": tmpl["severity"],
                "threat_type": tmpl["threat_type"],
                "source_ip": f"10.0.{random.randint(1, 5)}.{random.randint(1, 254)}",
                "affected_system": host,
                "source": "sentinelone",
            })
        return alerts

    def _real_poll(self) -> list[dict[str, Any]]:
        try:
            import requests
            headers = {"Authorization": f"ApiToken {self.api_key}", "Content-Type": "application/json"}
            r = requests.get(
                f"{self.management_url}/web/api/v2.1/threats",
                headers=headers,
                params={"limit": 10, "resolved": "false", "sortOrder": "desc", "sortBy": "createdAt"},
                timeout=15,
            )
            r.raise_for_status()
            threats = r.json().get("data", [])
            normalized = []
            for t in threats:
                severity_map = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
                normalized.append({
                    "external_id": t.get("id", ""),
                    "title": f"SentinelOne: {t.get('threatInfo', {}).get('threatName', 'Threat')}",
                    "description": t.get("threatInfo", {}).get("description", "SentinelOne threat detected"),
                    "severity": severity_map.get(t.get("riskScore", "medium"), "MEDIUM"),
                    "threat_type": t.get("threatInfo", {}).get("classification", "Malware"),
                    "source_ip": t.get("agentRealtimeInfo", {}).get("agentIpV4", ""),
                    "affected_system": t.get("agentRealtimeInfo", {}).get("agentComputerName", ""),
                    "source": "sentinelone",
                })
            return normalized
        except Exception as exc:
            logger.error("SentinelOne real poll failed: %s", exc)
            return []

    def push_acknowledgement(self, alert_id: str) -> bool:
        if self.is_mock:
            return True
        try:
            import requests
            headers = {"Authorization": f"ApiToken {self.api_key}", "Content-Type": "application/json"}
            r = requests.post(
                f"{self.management_url}/web/api/v2.1/threats/mark-as-resolved",
                headers=headers,
                json={"filter": {"ids": [alert_id]}},
                timeout=15,
            )
            r.raise_for_status()
            return True
        except Exception as exc:
            logger.error("SentinelOne acknowledge failed: %s", exc)
            return False

    def kill_process(self, agent_id: str, process_id: int) -> dict:
        """Kill a process on an endpoint via SentinelOne Remote Script Orchestration."""
        if self.is_mock:
            logger.info("Mock: kill_process on agent %s, pid %d", agent_id, process_id)
            return {"status": "mock_killed", "agent_id": agent_id, "pid": process_id}
        try:
            import requests
            headers = {"Authorization": f"ApiToken {self.api_key}", "Content-Type": "application/json"}
            r = requests.post(
                f"{self.management_url}/web/api/v2.1/remote-scripts/execute",
                headers=headers,
                json={
                    "data": {"scriptId": "kill-process", "outputDestination": "SentinelCloud"},
                    "filter": {"agentIds": [agent_id]},
                    "taskDescription": f"Kill PID {process_id}",
                },
                timeout=15,
            )
            r.raise_for_status()
            return {"status": "command_sent", "agent_id": agent_id}
        except Exception as exc:
            logger.error("SentinelOne kill_process failed: %s", exc)
            return {"status": "error", "message": str(exc)}
