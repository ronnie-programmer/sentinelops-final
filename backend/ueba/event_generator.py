"""Generate mock UEBA events for seeding/demo purposes."""
import random
from datetime import datetime, timedelta

USERS = ["alice.chen", "bob.martinez", "carol.davis", "dave.wilson", "eve.johnson"]
EVENT_TYPES = ["login", "file_access", "data_transfer", "privilege_escalation"]
GEOS = ["US", "US", "US", "US", "EU", "APAC"]  # US-weighted for realism


def generate_normal_event(username: str, dt: datetime = None) -> dict:
    dt = dt or datetime.utcnow()
    return {
        "username": username,
        "event_type": random.choice(EVENT_TYPES[:2]),  # mostly login + file_access
        "hour_of_day": random.randint(8, 18),          # business hours
        "day_of_week": random.randint(0, 4),            # weekdays
        "geo": "US",
        "file_count": random.randint(1, 20),
        "is_privileged": False,
        "bytes_transferred": random.randint(1000, 50000),
        "failed_logins": 0,
        "timestamp": dt.isoformat(),
    }


def generate_anomalous_event(username: str) -> dict:
    event_type = random.choice(["privilege_escalation", "data_transfer", "file_access"])
    return {
        "username": username,
        "event_type": event_type,
        "hour_of_day": random.choice([1, 2, 3, 23]),   # off-hours
        "day_of_week": random.choice([5, 6]),            # weekend
        "geo": random.choice(["APAC", "SA", "AF"]),     # unusual geo
        "file_count": random.randint(100, 500),         # mass file access
        "is_privileged": True,
        "bytes_transferred": random.randint(500000, 5000000),
        "failed_logins": random.randint(5, 20),
        "timestamp": datetime.utcnow().isoformat(),
    }


def generate_baseline_events(username: str, count: int = 30) -> list[dict]:
    events = []
    for i in range(count):
        dt = datetime.utcnow() - timedelta(days=30 - i)
        events.append(generate_normal_event(username, dt))
    return events
