import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)

_scheduler: AsyncIOScheduler | None = None


async def _poll_integration(adapter_class, db_factory):
    from models import AlertLog, Threat
    adapter = adapter_class()
    try:
        raw_alerts = adapter.poll_alerts()
    except Exception as exc:
        logger.error("Poll failed for %s: %s", adapter.provider_name, exc)
        return

    if not raw_alerts:
        return

    db = db_factory()
    try:
        for raw in raw_alerts:
            # Check for duplicate by external_id in message field
            ext_id = raw.get("external_id", "")
            existing = (
                db.query(AlertLog)
                .filter(AlertLog.message.contains(ext_id))
                .first()
                if ext_id
                else None
            )
            if existing:
                continue

            threat = Threat(
                title=raw.get("title", "Integration Alert"),
                description=raw.get("description", ""),
                severity=raw.get("severity", "MEDIUM"),
                status="Open",
                threat_type=raw.get("threat_type", "Malware"),
                source_ip=raw.get("source_ip"),
                affected_system=raw.get("affected_system"),
            )
            db.add(threat)
            db.flush()

            alert = AlertLog(
                threat_id=threat.id,
                severity=raw.get("severity", "MEDIUM"),
                message=f"[{adapter.provider_name.upper()}][{ext_id}] {raw.get('title', '')}",
                recipient="soc-team@sentinelops.internal",
                status="Pending",
            )
            db.add(alert)
        db.commit()
        logger.info("%s poll: ingested %d alerts", adapter.provider_name, len(raw_alerts))
    except Exception as exc:
        logger.error("DB write failed for %s: %s", adapter.provider_name, exc)
        db.rollback()
    finally:
        db.close()


def start_scheduler(db_factory, poll_interval_minutes: int = 5):
    global _scheduler
    from integrations.crowdstrike import CrowdStrikeAdapter
    from integrations.datadog import DatadogAdapter
    from integrations.splunk import SplunkAdapter

    _scheduler = AsyncIOScheduler()

    for adapter_class in [CrowdStrikeAdapter, DatadogAdapter, SplunkAdapter]:
        _scheduler.add_job(
            _poll_integration,
            trigger=IntervalTrigger(minutes=poll_interval_minutes),
            args=[adapter_class, db_factory],
            id=f"poll_{adapter_class.provider_name}",
            replace_existing=True,
        )

    _scheduler.start()
    logger.info("Integration scheduler started (interval: %d min)", poll_interval_minutes)


def stop_scheduler():
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
