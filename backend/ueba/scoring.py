"""Score a new event against a user's baseline model."""
import logging
import numpy as np
from ueba.features import event_to_features
from ueba.models.baseline import load_model

logger = logging.getLogger(__name__)


def score_event(username: str, event_data: dict) -> int:
    """
    Score event against user's baseline.
    Returns anomaly_score 0-100 (higher = more anomalous).
    If no model exists, returns 50 (neutral).
    """
    model = load_model(username)
    if model is None:
        return 50

    try:
        features = event_to_features(event_data).reshape(1, -1)
        # IsolationForest.decision_function returns negative values for anomalies
        # Score range is roughly [-0.5, 0.5], more negative = more anomalous
        raw_score = model.decision_function(features)[0]
        # Convert to 0-100: -0.5 → 100, +0.5 → 0
        score = int(max(0, min(100, ((-raw_score + 0.5) / 1.0) * 100)))
        return score
    except Exception as e:
        logger.warning("Scoring failed for %s: %s", username, e)
        return 50


def is_anomaly(score: int, threshold: int = 70) -> bool:
    return score >= threshold
