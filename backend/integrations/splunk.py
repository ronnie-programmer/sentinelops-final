import os
import random
import logging
from typing import Any
from integrations.base import IntegrationAdapter

logger = logging.getLogger(__name__)

MOCK_ALERT_TEMPLATES = [
    {"severity": "HIGH", "threat_type": "SQL Injection", "title": "Splunk: SQL injection attempt on web tier", "description": "Splunk ES correlation rule: Multiple SQL injection attempts detected from {ip} against web application. WAF partially blocking."},
    {"severity": "CRITICAL", "threat_type": "Ransomware", "title": "Splunk: Ransomware indicators on {host}", "description": "Splunk UEBA flagged rapid file rename/encryption pattern on {host}. Matches ransomware IOC signatures in threat intel feed."},
    {"severity": "MEDIUM", "threat_type": "Insider Threat", "title": "Splunk: After-hours sensitive data access", "description": "Splunk behavioral analytics detected user accessing sensitive HR and Finance documents at {time}. Access volume 400% above baseline."},
    {"severity": "HIGH", "threat_type": "Phishing", "title": "Splunk: Phishing email payload executed on {host}", "description": "Splunk SIEM correlated email gateway alert with endpoint telemetry: malicious attachment opened on {host}, spawning cmd.exe child process."},
]

HOSTS = ["wks-finance-01", "wks-hr-03", "splunk-indexer", "wks-eng-22", "wks-exec-ceo"]


def _is_configured() -> bool:
    return bool(os.getenv("SPLUNK_HOST")) and bool(os.getenv("SPLUNK_TOKEN"))


class SplunkAdapter(IntegrationAdapter):
    provider_name = "splunk"

    def __init__(self):
        self.is_mock = not _is_configured()
        if self.is_mock:
            logger.info("Splunk adapter running in MOCK mode (no credentials configured)")

    def poll_alerts(self) -> list[dict[str, Any]]:
        if self.is_mock:
            return self._mock_alerts()
        return self._real_poll()

    def _mock_alerts(self) -> list[dict[str, Any]]:
        count = random.randint(1, 3)
        alerts = []
        import datetime as dt
        for _ in range(count):
            tmpl = random.choice(MOCK_ALERT_TEMPLATES)
            host = random.choice(HOSTS)
            ip = f"10.0.{random.randint(1, 5)}.{random.randint(1, 254)}"
            hour = random.randint(0, 5)
            time_str = f"0{hour}:{random.choice(['14', '32', '47', '58'])} UTC"
            alerts.append({
                "external_id": f"splunk-{random.randint(1000000, 9999999)}",
                "title": tmpl["title"].format(host=host, ip=ip),
                "description": tmpl["description"].format(host=host, ip=ip, time=time_str),
                "severity": tmpl["severity"],
                "threat_type": tmpl["threat_type"],
                "source_ip": ip,
                "affected_system": host,
                "source": "splunk",
            })
        return alerts

    def _real_poll(self) -> list[dict[str, Any]]:
        try:
            import requests
            host = os.getenv("SPLUNK_HOST")
            token = os.getenv("SPLUNK_TOKEN")
            port = os.getenv("SPLUNK_PORT", "8089")

            r = requests.get(
                f"https://{host}:{port}/services/alerts/fired_alerts",
                headers={"Authorization": f"Bearer {token}"},
                params={"output_mode": "json", "count": 10},
                timeout=15,
                verify=False,
            )
            r.raise_for_status()
            entries = r.json().get("entry", [])
            normalized = []
            for e in entries:
                content = e.get("content", {})
                normalized.append({
                    "external_id": e.get("id", ""),
                    "title": f"Splunk: {e.get('name', 'Alert')}",
                    "description": content.get("description", "Splunk correlation alert"),
                    "severity": "HIGH",
                    "threat_type": "Malware",
                    "source_ip": "",
                    "affected_system": "",
                    "source": "splunk",
                })
            return normalized
        except Exception as exc:
            logger.error("Splunk real poll failed: %s", exc)
            return []

    def push_acknowledgement(self, alert_id: str) -> bool:
        if self.is_mock:
            return True
        return True
