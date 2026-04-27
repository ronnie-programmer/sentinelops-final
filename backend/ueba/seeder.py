"""Seed initial UEBA data: baselines + sample events."""
import json
import logging
from datetime import datetime
from ueba.event_generator import USERS, generate_baseline_events, generate_anomalous_event
from ueba.models.baseline import train_baseline
from ueba.scoring import score_event, is_anomaly

logger = logging.getLogger(__name__)


def seed_ueba_data(db):
    from models import UserBaseline, UEBAEvent

    # Seed user baselines
    for username in USERS:
        existing = db.query(UserBaseline).filter(UserBaseline.username == username).first()
        if not existing:
            baseline = UserBaseline(username=username, entity_type="user")
            db.add(baseline)
    db.commit()

    # Train initial baselines
    for username in USERS:
        events = generate_baseline_events(username, 30)
        result = train_baseline(username, events)
        baseline = db.query(UserBaseline).filter(UserBaseline.username == username).first()
        if baseline:
            baseline.event_count = len(events)
            baseline.last_trained_at = datetime.utcnow()
            if result.get("artifact_path"):
                baseline.model_artifact_path = result["artifact_path"]
    db.commit()

    # Seed sample UEBA events (mix of normal + anomalous)
    if db.query(UEBAEvent).count() == 0:
        for username in USERS:
            # 8 normal events
            for _ in range(8):
                from ueba.event_generator import generate_normal_event
                event_data = generate_normal_event(username)
                score = score_event(username, event_data)
                db.add(UEBAEvent(
                    username=username,
                    event_type=event_data["event_type"],
                    event_data_json=json.dumps(event_data),
                    anomaly_score=score,
                    is_anomaly=0,
                    source="ueba_seed",
                ))
            # 2 anomalous events per user
            for _ in range(2):
                event_data = generate_anomalous_event(username)
                score = score_event(username, event_data)
                db.add(UEBAEvent(
                    username=username,
                    event_type=event_data["event_type"],
                    event_data_json=json.dumps(event_data),
                    anomaly_score=score,
                    is_anomaly=1 if is_anomaly(score) else 0,
                    source="ueba_seed",
                ))
        db.commit()
        logger.info("Seeded UEBA events for %d users", len(USERS))
