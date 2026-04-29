"""Per-user baseline computation. Pure statistics — mean and population
standard deviation per feature over the trailing 30-day window. No ML."""

import json
import math
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from models import UEBAEvent, UEBAUser
from ueba.features import ALL_FEATURES, aggregate_day, group_events_by_day

BASELINE_WINDOW_DAYS = 30
MIN_BASELINE_DAYS = 5    # below this, mark baseline as low-confidence
MIN_STD = 1.0            # floor for std to avoid blowing up z-scores on quiet baselines


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _pstd(values: list[float], mean: float) -> float:
    if not values:
        return 0.0
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(var)


def compute_user_baseline(db: Session, user: UEBAUser, now: Optional[datetime] = None) -> dict:
    """Return a baseline dict {feature: {mean, std, n, low_confidence}}."""
    now = now or datetime.utcnow()
    cutoff = now - timedelta(days=BASELINE_WINDOW_DAYS)

    events = (
        db.query(UEBAEvent)
        .filter(UEBAEvent.user_id == user.id, UEBAEvent.occurred_at >= cutoff, UEBAEvent.occurred_at < now)
        .all()
    )
    by_day = group_events_by_day(events)

    daily_features: dict[str, list[float]] = {f: [] for f in ALL_FEATURES}
    for day_events in by_day.values():
        day_vec = aggregate_day(day_events)
        for feat in ALL_FEATURES:
            daily_features[feat].append(float(day_vec[feat]))

    n_days = len(by_day)
    low_confidence = n_days < MIN_BASELINE_DAYS

    baseline = {}
    for feat in ALL_FEATURES:
        vals = daily_features[feat]
        mean = _mean(vals)
        std = max(_pstd(vals, mean), MIN_STD)
        baseline[feat] = {
            "mean": round(mean, 3),
            "std": round(std, 3),
            "n": n_days,
            "low_confidence": low_confidence,
        }
    return baseline


def recompute_all(db: Session, now: Optional[datetime] = None) -> int:
    """Recompute baselines for every user. Returns count of users updated."""
    now = now or datetime.utcnow()
    users = db.query(UEBAUser).all()
    for user in users:
        baseline = compute_user_baseline(db, user, now=now)
        user.baseline_json = json.dumps(baseline)
        user.baseline_updated_at = now
    db.commit()
    return len(users)
