import os, requests, logging
logger = logging.getLogger(__name__)

def execute(params: dict, context: dict) -> str:
    webhook_url = os.getenv("SLACK_PLAYBOOK_WEBHOOK") or os.getenv("SLACK_WEBHOOK_URL")
    if not webhook_url:
        return "skipped: no Slack webhook configured"
    message = params.get("message", f"SentinelOps playbook triggered: {context.get('title', 'unknown')}")
    try:
        r = requests.post(webhook_url, json={"text": message}, timeout=10)
        r.raise_for_status()
        return "sent"
    except Exception as e:
        logger.warning("notify_slack failed: %s", e)
        return f"error: {e}"
