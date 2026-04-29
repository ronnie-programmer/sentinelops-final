"""On-startup seeder for UEBA. Idempotent: only seeds users + history when
the ueba_users table is empty. Produces 30 days of synthetic events for each
user, with a small handful of anomalies on the most-recent few days so the
UI has something interesting to display."""

import logging
import random
from datetime import datetime

from sqlalchemy.orm import Session

from models import UEBAUser
from ueba.baseline import recompute_all
from ueba.generator import generate_history
from ueba.scoring import detect_recent_anomalies

logger = logging.getLogger(__name__)

SEED_USERS = [
    {"username": "j.morales",      "department": "Finance",     "role": "finance",     "is_privileged": 0, "anomalies": [0, 2]},
    {"username": "p.chen",         "department": "Engineering", "role": "engineering", "is_privileged": 0, "anomalies": []},
    {"username": "s.kowalski",     "department": "Engineering", "role": "engineering", "is_privileged": 1, "anomalies": [1]},
    {"username": "a.diaz",         "department": "Executive",   "role": "executive",   "is_privileged": 0, "anomalies": [0]},
    {"username": "m.okafor",       "department": "HR",          "role": "hr",          "is_privileged": 0, "anomalies": []},
    {"username": "k.tanaka",       "department": "SOC",         "role": "soc",         "is_privileged": 1, "anomalies": []},
    {"username": "r.singh",        "department": "Engineering", "role": "engineering", "is_privileged": 0, "anomalies": [3]},
    {"username": "svc-backup$",    "department": "IT",          "role": "service",     "is_privileged": 1, "anomalies": []},
]

SEED_HISTORY_DAYS = 30


def seed_ueba(db: Session, now: datetime | None = None) -> bool:
    """Returns True if seeding ran, False if it was skipped."""
    if db.query(UEBAUser).count() > 0:
        return False

    now = now or datetime.utcnow()
    logger.info("UEBA seeder: bootstrapping %d users with %d days of history", len(SEED_USERS), SEED_HISTORY_DAYS)

    rng = random.Random(0xC0FFEE)
    for spec in SEED_USERS:
        user = UEBAUser(
            username=spec["username"],
            department=spec["department"],
            role=spec["role"],
            is_privileged=spec["is_privileged"],
        )
        db.add(user)
        db.flush()

        events = generate_history(
            user, days=SEED_HISTORY_DAYS, now=now, rng=rng,
            anomaly_day_indices=spec["anomalies"],
        )
        for e in events:
            db.add(e)
    db.commit()

    recompute_all(db, now=now)
    detect_recent_anomalies(db, now=now, days_back=1)
    return True
