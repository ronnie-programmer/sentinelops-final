"""Nightly UEBA baseline retraining job for APScheduler."""
import logging
from ueba.event_generator import generate_baseline_events, USERS

logger = logging.getLogger(__name__)


def retrain_all_baselines(session_factory):
    """Retrain IsolationForest baselines for all users. Called nightly by APScheduler."""
    from ueba.models.baseline import train_baseline
    from models import UserBaseline
    db = session_factory()
    try:
        for username in USERS:
            baseline = db.query(UserBaseline).filter(UserBaseline.username == username).first()
            if baseline:
                # In production: fetch real events from ueba_events table
                # For now: generate synthetic baseline events
                events = generate_baseline_events(username, 40)
                result = train_baseline(username, events)
                from datetime import datetime
                baseline.last_trained_at = datetime.utcnow()
                baseline.event_count = len(events)
                db.commit()
                logger.info("Retrained baseline for %s: %s", username, result)
    except Exception as e:
        logger.error("UEBA retraining failed: %s", e)
    finally:
        db.close()
