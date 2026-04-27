import os
import json
import logging
import requests

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "CRITICAL": ":red_circle:",
    "HIGH": ":orange_circle:",
    "MEDIUM": ":yellow_circle:",
    "LOW": ":blue_circle:",
}


def _is_configured() -> bool:
    return (
        os.getenv("SLACK_ENABLED", "false").lower() == "true"
        and bool(os.getenv("SLACK_WEBHOOK_URL", ""))
    )


def send_slack_alert(title: str, message: str, severity: str, threat_id: int) -> dict:
    if not _is_configured():
        logger.info("Slack notification skipped (not configured)")
        return {"status": "skipped", "channel": "slack"}

    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    emoji = SEVERITY_EMOJI.get(severity, ":white_circle:")
    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} [{severity}] {title}",
                },
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": message},
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Threat ID:* #{threat_id} | *Severity:* {severity} | *Source:* SentinelOps",
                    }
                ],
            },
        ]
    }
    try:
        r = requests.post(webhook_url, json=payload, timeout=10)
        r.raise_for_status()
        return {"status": "sent", "channel": "slack", "response_code": r.status_code}
    except Exception as exc:
        logger.error("Slack notification failed: %s", exc)
        return {"status": "error", "channel": "slack", "error": str(exc)}
