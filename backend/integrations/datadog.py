import os
import random
import logging
from typing import Any
from integrations.base import IntegrationAdapter

logger = logging.getLogger(__name__)

MOCK_SIGNAL_TEMPLATES = [
    {"severity": "HIGH", "threat_type": "Brute Force", "title": "Datadog: SSH brute force detected on {host}", "description": "Datadog Security Monitoring rule triggered: multiple failed SSH logins from {ip} against {host}. Tactic: Credential Access."},
    {"severity": "CRITICAL", "threat_type": "Data Exfiltration", "title": "Datadog: Large data transfer anomaly from {host}", "description": "Datadog Cloud SIEM: Anomalous outbound data volume detected from {host}. Transfer size 3x baseline. Potential data exfiltration."},
    {"severity": "MEDIUM", "threat_type": "Lateral Movement", "title": "Datadog: Unusual API access pattern from {host}", "description": "Datadog detected unusual cross-service API calls from {host}. User agent and timing inconsistent with normal operations."},
    {"severity": "HIGH", "threat_type": "Malware", "title": "Datadog: Crypto miner process detected on {host}", "description": "Datadog Runtime Security detected process matching crypto miner signature on {host}. High CPU usage with network egress to mining pool."},
]

HOSTS = ["web-prod-01", "k8s-worker-02", "db-primary", "jenkins-ci-01", "elk-stack-01"]


def _is_configured() -> bool:
    return bool(os.getenv("DATADOG_API_KEY")) and bool(os.getenv("DATADOG_APP_KEY"))


class DatadogAdapter(IntegrationAdapter):
    provider_name = "datadog"

    def __init__(self):
        self.is_mock = not _is_configured()
        if self.is_mock:
            logger.info("Datadog adapter running in MOCK mode (no credentials configured)")

    def poll_alerts(self) -> list[dict[str, Any]]:
        if self.is_mock:
            return self._mock_alerts()
        return self._real_poll()

    def _mock_alerts(self) -> list[dict[str, Any]]:
        count = random.randint(1, 4)
        alerts = []
        for _ in range(count):
            tmpl = random.choice(MOCK_SIGNAL_TEMPLATES)
            host = random.choice(HOSTS)
            ip = f"203.0.113.{random.randint(1, 254)}"
            alerts.append({
                "external_id": f"dd-sig-{random.randint(10000, 99999)}",
                "title": tmpl["title"].format(host=host, ip=ip),
                "description": tmpl["description"].format(host=host, ip=ip),
                "severity": tmpl["severity"],
                "threat_type": tmpl["threat_type"],
                "source_ip": ip,
                "affected_system": host,
                "source": "datadog",
            })
        return alerts

    def _real_poll(self) -> list[dict[str, Any]]:
        try:
            import requests
            api_key = os.getenv("DATADOG_API_KEY")
            app_key = os.getenv("DATADOG_APP_KEY")
            site = os.getenv("DATADOG_SITE", "datadoghq.com")

            r = requests.get(
                f"https://api.{site}/api/v2/security_monitoring/signals",
                headers={"DD-API-KEY": api_key, "DD-APPLICATION-KEY": app_key},
                params={"filter[status]": "open", "page[limit]": 10},
                timeout=15,
            )
            r.raise_for_status()
            signals = r.json().get("data", [])
            normalized = []
            for s in signals:
                attrs = s.get("attributes", {})
                sev_map = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "LOW"}
                normalized.append({
                    "external_id": s.get("id", ""),
                    "title": f"Datadog: {attrs.get('title', 'Security Signal')}",
                    "description": attrs.get("message", "Datadog security signal"),
                    "severity": sev_map.get(attrs.get("severity", "medium"), "MEDIUM"),
                    "threat_type": "Malware",
                    "source_ip": "",
                    "affected_system": "",
                    "source": "datadog",
                })
            return normalized
        except Exception as exc:
            logger.error("Datadog real poll failed: %s", exc)
            return []

    def push_acknowledgement(self, alert_id: str) -> bool:
        if self.is_mock:
            return True
        try:
            import requests
            api_key = os.getenv("DATADOG_API_KEY")
            app_key = os.getenv("DATADOG_APP_KEY")
            site = os.getenv("DATADOG_SITE", "datadoghq.com")
            r = requests.patch(
                f"https://api.{site}/api/v2/security_monitoring/signals/{alert_id}/state",
                headers={"DD-API-KEY": api_key, "DD-APPLICATION-KEY": app_key},
                json={"data": {"attributes": {"state": "archived"}}},
                timeout=10,
            )
            return r.status_code == 200
        except Exception:
            return False
