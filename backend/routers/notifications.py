import os
import json
import logging
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List

from database import get_db
from models import Notification
from schemas import NotificationOut, NotificationSettings
from notifications.slack import send_slack_alert
from notifications.pagerduty import send_pagerduty_alert

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/notifications", tags=["notifications"])

# In-memory settings store (persisted to env at startup only)
_settings: dict = {}


def _load_settings() -> NotificationSettings:
    return NotificationSettings(
        slack_enabled=os.getenv("SLACK_ENABLED", "false").lower() == "true",
        slack_webhook_url=os.getenv("SLACK_WEBHOOK_URL", ""),
        pagerduty_enabled=os.getenv("PAGERDUTY_ENABLED", "false").lower() == "true",
        pagerduty_integration_key=os.getenv("PAGERDUTY_INTEGRATION_KEY", ""),
        pagerduty_severity_threshold=os.getenv("PAGERDUTY_SEVERITY_THRESHOLD", "HIGH"),
    )


@router.get("/", response_model=List[NotificationOut])
def list_notifications(limit: int = 100, db: Session = Depends(get_db)):
    return (
        db.query(Notification)
        .order_by(Notification.attempted_at.desc())
        .limit(limit)
        .all()
    )


@router.get("/settings", response_model=NotificationSettings)
def get_settings():
    return _load_settings()


@router.post("/settings", response_model=NotificationSettings)
def save_settings(settings: NotificationSettings):
    os.environ["SLACK_ENABLED"] = str(settings.slack_enabled).lower()
    os.environ["SLACK_WEBHOOK_URL"] = settings.slack_webhook_url
    os.environ["PAGERDUTY_ENABLED"] = str(settings.pagerduty_enabled).lower()
    os.environ["PAGERDUTY_INTEGRATION_KEY"] = settings.pagerduty_integration_key
    os.environ["PAGERDUTY_SEVERITY_THRESHOLD"] = settings.pagerduty_severity_threshold
    return _load_settings()


@router.post("/test")
def test_notification(body: dict, db: Session = Depends(get_db)):
    channel = body.get("channel", "slack")
    results = []
    if channel in ("slack", "all"):
        result = send_slack_alert(
            title="SentinelOps Test Alert",
            message="This is a test notification from SentinelOps. If you see this, Slack routing is working correctly.",
            severity="HIGH",
            threat_id=0,
        )
        notif = Notification(channel="slack", status=result["status"], payload=json.dumps(result))
        db.add(notif)
        results.append(result)
    if channel in ("pagerduty", "all"):
        result = send_pagerduty_alert(
            title="SentinelOps Test Alert",
            message="Test notification from SentinelOps.",
            severity="HIGH",
            threat_id=0,
            dedup_key="sentinelops-test",
        )
        notif = Notification(channel="pagerduty", status=result["status"], payload=json.dumps(result))
        db.add(notif)
        results.append(result)
    db.commit()
    return {"results": results}
