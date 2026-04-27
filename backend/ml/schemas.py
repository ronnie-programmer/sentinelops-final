from pydantic import BaseModel
from typing import Optional, List


class TrainResponse(BaseModel):
    status: str
    n_samples: Optional[int] = None
    n_high_risk: Optional[int] = None
    trained_at: Optional[str] = None
    feature_cols: Optional[List[str]] = None


class ThreatPrediction(BaseModel):
    id: int
    title: str
    severity: str
    threat_type: str
    risk_score: float
    risk_label: str
    is_anomaly: bool


class MLStatus(BaseModel):
    ready: bool
    trained_at: Optional[str] = None
    n_samples: Optional[int] = None
    n_high_risk: Optional[int] = None
