"""Convert raw event dicts into numeric feature vectors for IsolationForest."""
import numpy as np

KNOWN_EVENT_TYPES = ["login", "file_access", "privilege_escalation", "data_transfer", "anomalous_time", "new_device", "new_geo", "mass_download"]
KNOWN_GEOS = ["US", "EU", "APAC", "SA", "AF", "OTHER"]


def event_to_features(event_data: dict) -> np.ndarray:
    """Convert event dict to a fixed-length numeric feature vector."""
    hour_of_day = event_data.get("hour_of_day", 12)  # 0-23
    day_of_week = event_data.get("day_of_week", 0)   # 0-6
    event_type_idx = KNOWN_EVENT_TYPES.index(event_data.get("event_type", "login")) if event_data.get("event_type") in KNOWN_EVENT_TYPES else 0
    geo_idx = KNOWN_GEOS.index(event_data.get("geo", "US")) if event_data.get("geo") in KNOWN_GEOS else 5
    file_count = min(event_data.get("file_count", 0), 1000)
    is_privileged = 1 if event_data.get("is_privileged", False) else 0
    bytes_transferred = min(event_data.get("bytes_transferred", 0), 1_000_000) / 1_000_000
    failed_logins = min(event_data.get("failed_logins", 0), 100)
    return np.array([
        hour_of_day / 23.0,
        day_of_week / 6.0,
        event_type_idx / max(len(KNOWN_EVENT_TYPES) - 1, 1),
        geo_idx / max(len(KNOWN_GEOS) - 1, 1),
        file_count / 1000.0,
        is_privileged,
        bytes_transferred,
        failed_logins / 100.0,
    ], dtype=float)
