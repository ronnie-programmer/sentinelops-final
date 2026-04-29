"""Synthetic event generator for UEBA mock mode. Produces a stream of plausible
SOC events for a given user over a date range — most days are 'normal' and
inside the user's typical envelope, but a small fraction of days include
injected anomalies (failed-login bursts, after-hours bulk access, new-IP
logins). This is deterministic given the same seed and user."""

import random
from datetime import datetime, timedelta
from typing import Iterable

from models import UEBAEvent, UEBAUser
from ueba.features import is_after_hours

# Per-role activity envelope. Mean events per day for the major event types,
# plus the chance an event is privileged.
ROLE_PROFILES = {
    "finance": {"login_mean": 4, "fail_mean": 0.4, "file_mean": 25, "privileged_p": 0.05, "internal_ips": 2},
    "engineering": {"login_mean": 6, "fail_mean": 0.6, "file_mean": 40, "privileged_p": 0.20, "internal_ips": 3},
    "executive": {"login_mean": 3, "fail_mean": 0.2, "file_mean": 18, "privileged_p": 0.02, "internal_ips": 2},
    "hr": {"login_mean": 4, "fail_mean": 0.3, "file_mean": 30, "privileged_p": 0.04, "internal_ips": 2},
    "soc": {"login_mean": 5, "fail_mean": 0.5, "file_mean": 50, "privileged_p": 0.40, "internal_ips": 2},
    "service": {"login_mean": 12, "fail_mean": 0.0, "file_mean": 80, "privileged_p": 0.50, "internal_ips": 1},
}

INTERNAL_IP_POOL = [
    "10.0.1.42", "10.0.1.99", "10.0.2.15", "10.0.2.88",
    "192.168.1.10", "192.168.1.55", "172.16.4.7",
]
EXTERNAL_IP_POOL = [
    "203.0.113.45", "198.51.100.27",
    "185.220.101.42", "91.108.4.221",
]
RESOURCES = [
    "/finance/budget-2026.xlsx", "/hr/comp-bands.docx", "/eng/repo/auth-service",
    "/soc/playbooks/ransomware.md", "/exec/board-deck.pdf", "/it/admin-console",
    "/db/postgres-prod", "/aws/iam-policies", "/k8s/prod-cluster",
]


def _pick_internal_ip(rng: random.Random, count: int) -> list[str]:
    return rng.sample(INTERNAL_IP_POOL, min(count, len(INTERNAL_IP_POOL)))


def _profile_for(user: UEBAUser) -> dict:
    if user.username and user.username.endswith("$"):
        return ROLE_PROFILES["service"]
    role = (user.role or "engineering").lower()
    return ROLE_PROFILES.get(role, ROLE_PROFILES["engineering"])


def generate_day_events(
    user: UEBAUser,
    day: datetime,
    rng: random.Random,
    inject_anomaly: bool = False,
) -> list[UEBAEvent]:
    """Produce a list of UEBAEvent rows for one user-day."""
    profile = _profile_for(user)
    home_ips = _pick_internal_ip(rng, profile["internal_ips"])

    login_count = max(0, int(rng.gauss(profile["login_mean"], 1)))
    fail_count = max(0, int(rng.gauss(profile["fail_mean"], 0.5)))
    file_count = max(0, int(rng.gauss(profile["file_mean"], profile["file_mean"] / 5)))

    events: list[UEBAEvent] = []

    def _ts(hour: int, minute: int) -> datetime:
        return day.replace(hour=hour, minute=minute, second=0, microsecond=0)

    # Logins — clustered around 8-10am.
    for _ in range(login_count):
        hour = max(0, min(23, int(rng.gauss(9, 1.2))))
        minute = rng.randint(0, 59)
        ts = _ts(hour, minute)
        events.append(UEBAEvent(
            user_id=user.id,
            event_type="login",
            occurred_at=ts,
            source_ip=rng.choice(home_ips),
            after_hours=1 if is_after_hours(ts) else 0,
            is_privileged_action=0,
        ))
    for _ in range(fail_count):
        hour = max(0, min(23, int(rng.gauss(11, 3))))
        ts = _ts(hour, rng.randint(0, 59))
        events.append(UEBAEvent(
            user_id=user.id,
            event_type="login_failed",
            occurred_at=ts,
            source_ip=rng.choice(home_ips),
            after_hours=1 if is_after_hours(ts) else 0,
            is_privileged_action=0,
        ))
    # File / resource access — clustered during work hours.
    for _ in range(file_count):
        hour = max(0, min(23, int(rng.gauss(13, 2.5))))
        ts = _ts(hour, rng.randint(0, 59))
        privileged = 1 if rng.random() < profile["privileged_p"] else 0
        events.append(UEBAEvent(
            user_id=user.id,
            event_type="command" if privileged else "file_access",
            occurred_at=ts,
            source_ip=rng.choice(home_ips),
            resource=rng.choice(RESOURCES),
            after_hours=1 if is_after_hours(ts) else 0,
            is_privileged_action=privileged,
        ))

    if inject_anomaly:
        kind = rng.choice(["failed_burst", "after_hours_bulk", "new_geo", "privileged_spike"])
        if kind == "failed_burst":
            for _ in range(rng.randint(15, 40)):
                ts = _ts(rng.randint(2, 5), rng.randint(0, 59))
                events.append(UEBAEvent(
                    user_id=user.id,
                    event_type="login_failed",
                    occurred_at=ts,
                    source_ip=rng.choice(EXTERNAL_IP_POOL),
                    after_hours=1,
                    is_privileged_action=0,
                ))
        elif kind == "after_hours_bulk":
            for _ in range(rng.randint(40, 120)):
                ts = _ts(rng.choice([2, 3, 4, 23]), rng.randint(0, 59))
                events.append(UEBAEvent(
                    user_id=user.id,
                    event_type="file_access",
                    occurred_at=ts,
                    source_ip=rng.choice(home_ips),
                    resource=rng.choice(RESOURCES),
                    after_hours=1,
                    is_privileged_action=0,
                ))
        elif kind == "new_geo":
            new_ip = f"45.{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}"
            for _ in range(rng.randint(2, 6)):
                ts = _ts(rng.randint(0, 23), rng.randint(0, 59))
                events.append(UEBAEvent(
                    user_id=user.id,
                    event_type="login",
                    occurred_at=ts,
                    source_ip=new_ip,
                    after_hours=1 if is_after_hours(ts) else 0,
                    is_privileged_action=0,
                ))
        elif kind == "privileged_spike":
            for _ in range(rng.randint(20, 60)):
                ts = _ts(rng.randint(8, 20), rng.randint(0, 59))
                events.append(UEBAEvent(
                    user_id=user.id,
                    event_type="command",
                    occurred_at=ts,
                    source_ip=rng.choice(home_ips),
                    resource=rng.choice(RESOURCES),
                    after_hours=0,
                    is_privileged_action=1,
                ))

    return events


def generate_history(
    user: UEBAUser,
    days: int,
    now: datetime,
    rng: random.Random,
    anomaly_day_indices: Iterable[int] = (),
) -> list[UEBAEvent]:
    """Produce `days` days of events ending at `now`. Pass `anomaly_day_indices`
    (where 0 == most recent day) to inject anomalies into specific days."""
    anomaly_days = set(anomaly_day_indices)
    events: list[UEBAEvent] = []
    for i in range(days):
        day = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        events.extend(generate_day_events(user, day, rng, inject_anomaly=(i in anomaly_days)))
    return events
