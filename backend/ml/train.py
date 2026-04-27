"""
ML training for SentinelOps threat risk scoring.

Adapts the RandomForest + IsolationForest pipeline from sentinelops_ai/ml_models.py
to operate on the security domain (threats table) instead of shipments.

Classifier: predicts whether a threat will be HIGH or CRITICAL severity
            based on its metadata features (type, tactic, IP presence, time).
Anomaly:    IsolationForest flags threats whose feature combination is
            statistically unusual vs the rest of the dataset.

Pickles written to ml/artifacts/ on first startup and on POST /ml/train.
"""

import os
from datetime import datetime
from typing import Optional, Dict, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler

ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "artifacts")
MODEL_PATH = os.path.join(ARTIFACTS_DIR, "threat_clf.pkl")
SCALER_PATH = os.path.join(ARTIFACTS_DIR, "threat_scaler.pkl")
ENCODERS_PATH = os.path.join(ARTIFACTS_DIR, "threat_encoders.pkl")
ANOMALY_PATH = os.path.join(ARTIFACTS_DIR, "anomaly_iso.pkl")
META_PATH = os.path.join(ARTIFACTS_DIR, "train_meta.pkl")

FEATURE_COLS = ["type_enc", "tactic_enc", "has_src", "has_dst", "has_asset", "hour", "dow"]


def artifacts_exist() -> bool:
    return all(os.path.exists(p) for p in [MODEL_PATH, SCALER_PATH, ENCODERS_PATH, ANOMALY_PATH])


def load_threats_df(db_session) -> Optional[pd.DataFrame]:
    from sqlalchemy import text
    rows = db_session.execute(text(
        "SELECT id, title, threat_type, mitre_tactic, source_ip, destination_ip, "
        "asset_id, severity, created_at FROM threats"
    )).fetchall()
    if not rows:
        return None
    return pd.DataFrame(rows, columns=[
        "id", "title", "threat_type", "mitre_tactic", "source_ip",
        "destination_ip", "asset_id", "severity", "created_at",
    ])


def build_features(
    df: pd.DataFrame,
    encoders: Optional[Dict] = None,
) -> Tuple[np.ndarray, list, Dict]:
    """
    Build feature matrix from a threats DataFrame.

    If encoders=None, fits new LabelEncoders (training mode).
    Otherwise transforms using the saved encoders (inference mode),
    mapping unseen labels to 0 rather than raising.
    """
    df = df.copy()
    df["threat_type"] = df["threat_type"].fillna("Unknown")
    df["mitre_tactic"] = df["mitre_tactic"].fillna("Unknown")

    fitting = encoders is None
    if fitting:
        encoders = {"type": LabelEncoder(), "tactic": LabelEncoder()}
        df["type_enc"] = encoders["type"].fit_transform(df["threat_type"])
        df["tactic_enc"] = encoders["tactic"].fit_transform(df["mitre_tactic"])
    else:
        def safe_enc(le: LabelEncoder, series: pd.Series) -> pd.Series:
            known = set(le.classes_)
            return series.map(lambda v: int(le.transform([v])[0]) if v in known else 0)

        df["type_enc"] = safe_enc(encoders["type"], df["threat_type"])
        df["tactic_enc"] = safe_enc(encoders["tactic"], df["mitre_tactic"])

    df["has_src"] = df["source_ip"].notna().astype(int)
    df["has_dst"] = df["destination_ip"].notna().astype(int)
    df["has_asset"] = df["asset_id"].notna().astype(int)

    created = pd.to_datetime(df["created_at"], errors="coerce")
    df["hour"] = created.dt.hour.fillna(12).astype(int)
    df["dow"] = created.dt.dayofweek.fillna(0).astype(int)

    X = df[FEATURE_COLS].values.astype(float)
    return X, FEATURE_COLS, encoders


def run_training(db_session) -> dict:
    """Train both models and persist pickles. Returns a status dict."""
    df = load_threats_df(db_session)
    if df is None or len(df) < 5:
        return {"status": "insufficient_data", "n_samples": 0 if df is None else len(df)}

    X, feature_cols, encoders = build_features(df)
    y = df["severity"].isin(["CRITICAL", "HIGH"]).astype(int).values

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    clf = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42)
    clf.fit(X_scaled, y)

    # contamination = fraction of outliers; clamp between 5% and 20%
    low_risk_ratio = float((y == 0).sum()) / len(y)
    contamination = max(0.05, min(0.20, low_risk_ratio))
    iso = IsolationForest(contamination=contamination, random_state=42)
    iso.fit(X_scaled)

    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(encoders, ENCODERS_PATH)
    joblib.dump(iso, ANOMALY_PATH)

    meta = {
        "trained_at": datetime.utcnow().isoformat(),
        "n_samples": len(df),
        "n_high_risk": int(y.sum()),
        "feature_cols": feature_cols,
    }
    joblib.dump(meta, META_PATH)
    return {"status": "trained", **meta}
