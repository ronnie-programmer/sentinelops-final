import json
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import Playbook, PlaybookRun
from schemas import PlaybookOut, PlaybookCreate, PlaybookUpdate, PlaybookRunOut
from playbooks import engine

router = APIRouter(prefix="/api/playbooks", tags=["playbooks"])


def _playbook_out(pb: Playbook) -> PlaybookOut:
    return PlaybookOut(
        id=pb.id,
        name=pb.name,
        description=pb.description,
        enabled=bool(pb.enabled),
        trigger_yaml=pb.trigger_yaml,
        actions_yaml=pb.actions_yaml,
        is_builtin=bool(pb.is_builtin),
        run_count=pb.run_count,
        last_run_at=pb.last_run_at,
        created_at=pb.created_at,
        updated_at=pb.updated_at,
    )


@router.get("/runs/all", response_model=List[PlaybookRunOut])
def get_all_runs(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return (
        db.query(PlaybookRun)
        .order_by(PlaybookRun.started_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


@router.get("/", response_model=List[PlaybookOut])
def list_playbooks(db: Session = Depends(get_db)):
    playbooks = db.query(Playbook).order_by(Playbook.created_at.asc()).all()
    return [_playbook_out(pb) for pb in playbooks]


@router.post("/", response_model=PlaybookOut, status_code=201)
def create_playbook(data: PlaybookCreate, db: Session = Depends(get_db)):
    pb = Playbook(
        name=data.name,
        description=data.description,
        trigger_yaml=data.trigger_yaml,
        actions_yaml=data.actions_yaml,
        enabled=1,
        is_builtin=0,
    )
    db.add(pb)
    db.commit()
    db.refresh(pb)
    return _playbook_out(pb)


@router.get("/{playbook_id}", response_model=PlaybookOut)
def get_playbook(playbook_id: int, db: Session = Depends(get_db)):
    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return _playbook_out(pb)


@router.put("/{playbook_id}", response_model=PlaybookOut)
def update_playbook(playbook_id: int, data: PlaybookUpdate, db: Session = Depends(get_db)):
    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    if data.name is not None:
        pb.name = data.name
    if data.description is not None:
        pb.description = data.description
    if data.enabled is not None:
        pb.enabled = 1 if data.enabled else 0
    if data.trigger_yaml is not None:
        pb.trigger_yaml = data.trigger_yaml
    if data.actions_yaml is not None:
        pb.actions_yaml = data.actions_yaml
    pb.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(pb)
    return _playbook_out(pb)


@router.delete("/{playbook_id}", status_code=204)
def delete_playbook(playbook_id: int, db: Session = Depends(get_db)):
    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    if pb.is_builtin:
        raise HTTPException(status_code=403, detail="Built-in playbooks cannot be deleted")
    db.delete(pb)
    db.commit()


@router.post("/{playbook_id}/toggle", response_model=PlaybookOut)
def toggle_playbook(playbook_id: int, db: Session = Depends(get_db)):
    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    pb.enabled = 0 if pb.enabled else 1
    pb.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(pb)
    return _playbook_out(pb)


@router.post("/{playbook_id}/run", response_model=PlaybookRunOut)
def run_playbook(playbook_id: int, db: Session = Depends(get_db)):
    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")

    test_context = {
        "title": "Manual test run",
        "severity": "HIGH",
        "source_ip": "1.2.3.4",
        "affected_system": "test-host",
        "mitre_techniques": "",
    }

    run = PlaybookRun(
        playbook_id=pb.id,
        triggered_by="manual",
        status="running",
        started_at=datetime.utcnow(),
    )
    db.add(run)
    db.flush()

    triggered = engine.evaluate_trigger(pb.trigger_yaml, test_context)
    if triggered:
        results = engine.execute_actions(pb.actions_yaml, test_context)
        any_error = any(r.get("status") == "error" for r in results)
        run.status = "error" if any_error else "success"
    else:
        results = [{"action": "trigger_check", "status": "skipped", "message": "trigger conditions not met for test context"}]
        run.status = "success"

    run.output = json.dumps(results)
    run.completed_at = datetime.utcnow()

    pb.run_count = (pb.run_count or 0) + 1
    pb.last_run_at = run.completed_at

    db.commit()
    db.refresh(run)
    return run


@router.get("/{playbook_id}/runs", response_model=List[PlaybookRunOut])
def get_playbook_runs(playbook_id: int, skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return (
        db.query(PlaybookRun)
        .filter(PlaybookRun.playbook_id == playbook_id)
        .order_by(PlaybookRun.started_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
