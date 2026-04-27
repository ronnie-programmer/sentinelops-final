"""Train and persist IsolationForest baseline model per user."""
import os
import logging
import numpy as np
import joblib
from pathlib import Path
from ueba.features import event_to_features

logger = logging.getLogger(__name__)

ARTIFACTS_DIR = Path(os.getenv("UEBA_BASELINE_DIR", "ueba/artifacts"))


def get_artifact_path(username: str) -> Path:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in username)
    return ARTIFACTS_DIR / f"{safe_name}_baseline.joblib"


def train_baseline(username: str, events: list[dict]) -> dict:
    """Train IsolationForest on a list of event dicts. Returns summary dict."""
    if len(events) < 5:
        return {"status": "insufficient_data", "event_count": len(events)}

    try:
        from sklearn.ensemble import IsolationForest
        X = np.array([event_to_features(e) for e in events])
        model = IsolationForest(contamination=0.1, random_state=42, n_estimators=50)
        model.fit(X)
        artifact_path = get_artifact_path(username)
        joblib.dump(model, artifact_path)
        logger.info("Trained baseline for %s on %d events → %s", username, len(events), artifact_path)
        return {"status": "trained", "event_count": len(events), "artifact_path": str(artifact_path)}
    except Exception as e:
        logger.error("Failed to train baseline for %s: %s", username, e)
        return {"status": "error", "message": str(e)}


def load_model(username: str):
    """Load a trained IsolationForest model. Returns None if not found."""
    artifact_path = get_artifact_path(username)
    if not artifact_path.exists():
        return None
    try:
        return joblib.load(artifact_path)
    except Exception as e:
        logger.warning("Could not load model for %s: %s", username, e)
        return None
