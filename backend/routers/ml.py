from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from ml import predict, train as ml_train
from ml.schemas import MLStatus, ThreatPrediction, TrainResponse

router = APIRouter(prefix="/api/ml", tags=["ml"])


@router.get("/status", response_model=MLStatus)
def ml_status():
    return predict.get_status()


@router.post("/train", response_model=TrainResponse)
def train_models(db: Session = Depends(get_db)):
    result = ml_train.run_training(db)
    predict.reload()
    return result


@router.get("/predictions", response_model=List[ThreatPrediction])
def get_predictions(db: Session = Depends(get_db)):
    return predict.score_all_threats(db)


@router.get("/anomalies", response_model=List[ThreatPrediction])
def get_anomalies(db: Session = Depends(get_db)):
    return [p for p in predict.score_all_threats(db) if p["is_anomaly"]]
