"""Feature extraction for UEBA. A feature is a per-user, per-day numeric
aggregate over a window of UEBAEvent rows. Features must be deterministic
(same input -> same output) so that baselines and scoring agree."""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Iterable

# Canonical feature names — keep in sync with scoring.SCORE_RULES.
FEATURE_LOGIN_COUNT = "login_count"
FEATURE_FAILED_LOGIN_COUNT = "failed_login_count"
FEATURE_UNIQUE_SOURCE_IPS = "unique_source_ips"
FEATURE_AFTER_HOURS_COUNT = "after_hours_count"
FEATURE_PRIVILEGED_COUNT = "privileged_count"
FEATURE_DISTINCT_RESOURCES = "distinct_resources"

ALL_FEATURES = (
    FEATURE_LOGIN_COUNT,
    FEATURE_FAILED_LOGIN_COUNT,
    FEATURE_UNIQUE_SOURCE_IPS,
    FEATURE_AFTER_HOURS_COUNT,
    FEATURE_PRIVILEGED_COUNT,
    FEATURE_DISTINCT_RESOURCES,
)


def aggregate_day(events: Iterable) -> dict:
    """Compute the feature vector for a single day's events for one user."""
    login_count = 0
    failed_login_count = 0
    after_hours_count = 0
    privileged_count = 0
    source_ips = set()
    resources = set()

    for e in events:
        if e.event_type == "login":
            login_count += 1
        elif e.event_type == "login_failed":
            failed_login_count += 1
        if e.after_hours:
            after_hours_count += 1
        if e.is_privileged_action:
            privileged_count += 1
        if e.source_ip:
            source_ips.add(e.source_ip)
        if e.resource:
            resources.add(e.resource)

    return {
        FEATURE_LOGIN_COUNT: login_count,
        FEATURE_FAILED_LOGIN_COUNT: failed_login_count,
        FEATURE_UNIQUE_SOURCE_IPS: len(source_ips),
        FEATURE_AFTER_HOURS_COUNT: after_hours_count,
        FEATURE_PRIVILEGED_COUNT: privileged_count,
        FEATURE_DISTINCT_RESOURCES: len(resources),
    }


def group_events_by_day(events: Iterable) -> dict[datetime, list]:
    """Group an iterable of events into a dict keyed by midnight-truncated day."""
    by_day: dict[datetime, list] = defaultdict(list)
    for e in events:
        day_key = e.occurred_at.replace(hour=0, minute=0, second=0, microsecond=0)
        by_day[day_key].append(e)
    return dict(by_day)


def is_after_hours(ts: datetime) -> bool:
    """SOC convention: after-hours is outside 06:00-22:00."""
    return ts.hour < 6 or ts.hour >= 22
