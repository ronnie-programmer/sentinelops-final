from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from database import get_db
from models import Asset, Threat
from schemas import AssetCreate, AssetUpdate, AssetOut

router = APIRouter(prefix="/api/assets", tags=["assets"])


def asset_to_dict(asset: Asset) -> dict:
    vuln_count = len([t for t in asset.threats if t.status not in ("Resolved", "False Positive")])
    return {
        "id": asset.id,
        "hostname": asset.hostname,
        "ip_address": asset.ip_address,
        "os": asset.os,
        "asset_type": asset.asset_type,
        "status": asset.status,
        "owner": asset.owner,
        "location": asset.location,
        "vulnerability_count": vuln_count,
        "created_at": asset.created_at,
        "updated_at": asset.updated_at,
    }


@router.get("/")
def get_assets(
    skip: int = 0,
    limit: int = 100,
    asset_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    query = db.query(Asset)
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    if status:
        query = query.filter(Asset.status == status)
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            Asset.hostname.ilike(search_term)
            | Asset.ip_address.ilike(search_term)
            | Asset.os.ilike(search_term)
            | Asset.owner.ilike(search_term)
        )
    assets = query.order_by(Asset.created_at.desc()).offset(skip).limit(limit).all()
    return [asset_to_dict(a) for a in assets]


@router.get("/{asset_id}")
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    result = asset_to_dict(asset)
    result["threats"] = [
        {
            "id": t.id,
            "title": t.title,
            "severity": t.severity,
            "status": t.status,
            "threat_type": t.threat_type,
            "created_at": t.created_at,
        }
        for t in asset.threats
    ]
    return result


@router.post("/", status_code=201)
def create_asset(asset_in: AssetCreate, db: Session = Depends(get_db)):
    asset = Asset(**asset_in.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset_to_dict(asset)


@router.put("/{asset_id}")
def update_asset(asset_id: int, asset_in: AssetUpdate, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    update_data = asset_in.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(asset, key, value)
    asset.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(asset)
    return asset_to_dict(asset)


@router.delete("/{asset_id}", status_code=204)
def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.delete(asset)
    db.commit()
