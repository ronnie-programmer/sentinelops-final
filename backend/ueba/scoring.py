"""Anomaly scoring. Pure rules + z-scores — no ML, no model artifacts.

The score for a single feature is the absolute z-score against the baseline.
Rule bonuses are added on top for behaviors that don't show up cleanly in the
z-score (e.g. logins from a never-before-seen IP). The user's day-level score
is the maximum feature-level score across all features, then mapped to a
0-100 normalized score and a severity bucket."""

import json
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from models import UEBAAnomaly, UEBAEvent, UEBAUser
from ueba.features import (
    ALL_FEATURES,
    FEATURE_AFTER_HOURS_COUNT,
    FEATURE_FAILED_LOGIN_COUNT,
    FEATURE_PRIVILEGED_COUNT,
    aggregate_day,
)
from ueba.baseline import BASELINE_WINDOW_DAYS

# z-score weight per feature: failures and privileged activity get amplified
# because they're more security-relevant than e.g. resource diversity.
FEATURE_WEIGHTS = {
    FEATURE_FAILED_LOGIN_COUNT: 1.5,
    FEATURE_PRIVILEGED_COUNT: 1.4,
    FEATURE_AFTER_HOURS_COUNT: 1.3,
}

# Score → severity bucket. Score is clamped to [0, 100].
SEVERITY_BUCKETS = (
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (0, "LOW"),
)


def _score_to_severity(score: float) -> str:
    for threshold, label in SEVERITY_BUCKETS:
        if score >= threshold:
            return label
    return "LOW"


def _zscore(value: float, mean: float, std: float) -> float:
    if std <= 0:
        return 0.0
    return (value - mean) / std


def score_day(
    user: UEBAUser,
    day_events: list[UEBAEvent],
    historical_ips: set[str],
) -> dict:
    """Score one day's worth of events for a user against their stored baseline.
    Returns {score, severity, contributions: [...], summary}."""
    if not user.baseline_json:
        return {"score": 0, "severity": "LOW", "contributions": [], "summary": "no baseline"}

    baseline = json.loads(user.baseline_json)
    day_vec = aggregate_day(day_events)

    contributions = []
    max_score = 0.0
    for feat in ALL_FEATURES:
        b = baseline.get(feat, {"mean": 0.0, "std": 1.0})
        observed = float(day_vec[feat])
        mean = float(b["mean"])
        std = float(b["std"])
        z = _zscore(observed, mean, std)
        weighted_z = abs(z) * FEATURE_WEIGHTS.get(feat, 1.0)
        # Map weighted z (typical max ~6) onto a 0-100 axis.
        feat_score = min(weighted_z * 15.0, 100.0)
        contributions.append({
            "feature": feat,
            "observed": round(observed, 2),
            "mean": round(mean, 2),
            "std": round(std, 2),
            "z": round(z, 2),
            "score": round(feat_score, 1),
        })
        if feat_score > max_score:
            max_score = feat_score

    # Rule bonuses (added once, not per-feature).
    bonus = 0.0
    bonus_notes = []
    new_ips = {e.source_ip for e in day_events if e.source_ip and e.source_ip not in historical_ips}
    if new_ips:
        bonus += 15.0
        bonus_notes.append(f"login from {len(new_ips)} new IP(s)")
    if user.is_privileged and day_vec[FEATURE_FAILED_LOGIN_COUNT] >= 3:
        bonus += 10.0
        bonus_notes.append("multiple failed logins on privileged account")
    if day_vec[FEATURE_AFTER_HOURS_COUNT] > 0 and (user.role or "").lower() in ("finance", "executive", "hr"):
        bonus += 10.0
        bonus_notes.append("after-hours activity on sensitive role")

    final_score = min(max_score + bonus, 100.0)

    top = max(contributions, key=lambda c: c["score"]) if contributions else None
    summary_parts = []
    if top and top["score"] > 0:
        summary_parts.append(
            f"{top['feature']}={top['observed']} (baseline {top['mean']}±{top['std']}, z={top['z']})"
        )
    summary_parts.extend(bonus_notes)
    summary = "; ".join(summary_parts) if summary_parts else "within baseline"

    return {
        "score": round(final_score, 1),
        "severity": _score_to_severity(final_score),
        "contributions": contributions,
        "summary": summary,
    }


ANOMALY_THRESHOLD = 40.0  # below this we don't bother creating an anomaly row


def detect_recent_anomalies(
    db: Session,
    now: Optional[datetime] = None,
    days_back: int = 1,
    threshold: float = ANOMALY_THRESHOLD,
) -> list[UEBAAnomaly]:
    """Score the last `days_back` day(s) for every user and persist any
    anomalies above `threshold`. Returns the list of newly-created rows."""
    now = now or datetime.utcnow()
    window_end = now
    window_start = now - timedelta(days=days_back)

    historical_cutoff = now - timedelta(days=BASELINE_WINDOW_DAYS)

    users = db.query(UEBAUser).all()
    created: list[UEBAAnomaly] = []
    for user in users:
        recent_events = (
            db.query(UEBAEvent)
            .filter(
                UEBAEvent.user_id == user.id,
                UEBAEvent.occurred_at >= window_start,
                UEBAEvent.occurred_at < window_end,
            )
            .all()
        )
        if not recent_events:
            continue
        historical_ips = {
            ip for (ip,) in db.query(UEBAEvent.source_ip)
            .filter(
                UEBAEvent.user_id == user.id,
                UEBAEvent.occurred_at >= historical_cutoff,
                UEBAEvent.occurred_at < window_start,
                UEBAEvent.source_ip.isnot(None),
            )
            .distinct()
            .all()
        }
        result = score_day(user, recent_events, historical_ips)
        if result["score"] < threshold:
            continue

        # De-dupe: skip if we already have an open anomaly for this user in the same window.
        existing = (
            db.query(UEBAAnomaly)
            .filter(
                UEBAAnomaly.user_id == user.id,
                UEBAAnomaly.window_start == window_start,
                UEBAAnomaly.status == "Open",
            )
            .first()
        )
        if existing:
            continue

        anomaly = UEBAAnomaly(
            user_id=user.id,
            window_start=window_start,
            window_end=window_end,
            score=int(result["score"]),
            severity=result["severity"],
            status="Open",
            contributing_features=json.dumps(result["contributions"]),
            summary=result["summary"],
        )
        db.add(anomaly)
        created.append(anomaly)

    if created:
        db.commit()
    return created
