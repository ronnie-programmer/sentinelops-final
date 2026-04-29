"""Daily UEBA job: recompute baselines and detect new anomalies for the most
recent day. Runs on the same APScheduler instance as the integration poller —
the scheduler module exposes a registration helper that backend/main.py
calls during startup."""

import logging
from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from ueba.baseline import recompute_all
from ueba.scoring import detect_recent_anomalies

logger = logging.getLogger(__name__)

# Default cadence — once per day. The scheduler module that owns the
# AsyncIOScheduler instance picks this up.
UEBA_INTERVAL_HOURS = 24


async def run_ueba_cycle(db_factory):
    db = db_factory()
    try:
        n = recompute_all(db)
        anomalies = detect_recent_anomalies(db)
        logger.info("UEBA cycle: refreshed %d baselines, detected %d new anomalies", n, len(anomalies))
    except Exception as exc:
        logger.error("UEBA cycle failed: %s", exc)
        db.rollback()
    finally:
        db.close()


def register_ueba_job(scheduler: AsyncIOScheduler, db_factory) -> None:
    scheduler.add_job(
        run_ueba_cycle,
        trigger=IntervalTrigger(hours=UEBA_INTERVAL_HOURS),
        args=[db_factory],
        id="ueba_cycle",
        replace_existing=True,
    )
    logger.info("UEBA cycle registered (every %d hours)", UEBA_INTERVAL_HOURS)
