"""
Inference layer for SentinelOps ML.

Loads pickles produced by train.py (or falls back gracefully when they
don't exist yet). Uses a module-level cache so pickles are read from disk
only once per process; call reload() after retraining.
"""

import os
from typing import List, Dict, Optional

import joblib

from .train import (
    ANOMALY_PATH,
    ENCODERS_PATH,
    META_PATH,
    MODEL_PATH,
    SCALER_PATH,
    artifacts_exist,
    build_features,
    load_threats_df,
)

_cache: Dict = {}


def _load():
    if _cache.get("loaded"):
        return _cache["clf"], _cache["scaler"], _cache["encoders"], _cache["iso"]
    if not artifacts_exist():
        return None, None, None, None
    _cache["clf"] = joblib.load(MODEL_PATH)
    _cache["scaler"] = joblib.load(SCALER_PATH)
    _cache["encoders"] = joblib.load(ENCODERS_PATH)
    _cache["iso"] = joblib.load(ANOMALY_PATH)
    _cache["loaded"] = True
    return _cache["clf"], _cache["scaler"], _cache["encoders"], _cache["iso"]


def reload() -> None:
    """Clear the in-memory cache so the next call re-reads pickles from disk."""
    _cache.clear()


def get_status() -> dict:
    if not artifacts_exist():
        return {"ready": False, "trained_at": None, "n_samples": None, "n_high_risk": None}
    meta = joblib.load(META_PATH) if os.path.exists(META_PATH) else {}
    return {"ready": True, **meta}


def _risk_label(score: float) -> str:
    if score >= 0.65:
        return "High"
    if score >= 0.35:
        return "Medium"
    return "Low"


def score_all_threats(db_session) -> List[Dict]:
    """
    Return all threats with ML risk scores and anomaly flags.
    Falls back to empty list when model isn't trained or DB is empty.
    """
    clf, scaler, encoders, iso = _load()

    df = load_threats_df(db_session)
    if df is None or df.empty:
        return []

    if clf is None:
        # Model not trained yet — return neutral placeholder scores
        return [
            {
                "id": int(row.id),
                "title": str(row.title),
                "severity": str(row.severity),
                "threat_type": str(row.threat_type),
                "risk_score": 0.5,
                "risk_label": "Unknown",
                "is_anomaly": False,
            }
            for row in df.itertuples()
        ]

    X, _, _ = build_features(df, encoders=encoders)
    X_scaled = scaler.transform(X)

    # Probability of being HIGH/CRITICAL (class index 1)
    probs = clf.predict_proba(X_scaled)[:, 1]
    # IsolationForest: -1 = anomaly, 1 = normal
    anomaly_flags = iso.predict(X_scaled)

    results = []
    for i, row in enumerate(df.itertuples()):
        score = float(probs[i])
        results.append({
            "id": int(row.id),
            "title": str(row.title),
            "severity": str(row.severity),
            "threat_type": str(row.threat_type),
            "risk_score": round(score, 4),
            "risk_label": _risk_label(score),
            "is_anomaly": bool(anomaly_flags[i] == -1),
        })

    results.sort(key=lambda x: x["risk_score"], reverse=True)
    return results
