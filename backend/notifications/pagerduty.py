import os
import logging
import requests

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "info",
}

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _severity_meets_threshold(severity: str, threshold: str) -> bool:
    try:
        return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(threshold)
    except ValueError:
        return False


def _is_configured(severity: str) -> bool:
    if os.getenv("PAGERDUTY_ENABLED", "false").lower() != "true":
        return False
    if not os.getenv("PAGERDUTY_INTEGRATION_KEY", ""):
        return False
    threshold = os.getenv("PAGERDUTY_SEVERITY_THRESHOLD", "HIGH")
    return _severity_meets_threshold(severity, threshold)


def send_pagerduty_alert(
    title: str, message: str, severity: str, threat_id: int, dedup_key: str | None = None
) -> dict:
    if not _is_configured(severity):
        logger.info("PagerDuty notification skipped (not configured or below threshold)")
        return {"status": "skipped", "channel": "pagerduty"}

    integration_key = os.getenv("PAGERDUTY_INTEGRATION_KEY")
    payload = {
        "routing_key": integration_key,
        "event_action": "trigger",
        "dedup_key": dedup_key or f"sentinelops-threat-{threat_id}",
        "payload": {
            "summary": f"[{severity}] {title}",
            "source": "SentinelOps",
            "severity": SEVERITY_MAP.get(severity, "error"),
            "class": "security-alert",
            "custom_details": {"message": message, "threat_id": threat_id, "platform": "SentinelOps v3"},
        },
    }
    try:
        r = requests.post(
            "https://events.pagerduty.com/v2/enqueue",
            json=payload,
            timeout=10,
        )
        r.raise_for_status()
        return {"status": "sent", "channel": "pagerduty", "response_code": r.status_code}
    except Exception as exc:
        logger.error("PagerDuty notification failed: %s", exc)
        return {"status": "error", "channel": "pagerduty", "error": str(exc)}
