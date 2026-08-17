"""FastAPI REST API server & Dashboard host for RDRS."""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.config import settings
from app.core.entropy import calculate_file_entropy
from app.database.db import get_db, init_db, SessionLocal
from app.database.models import FileEventModel, AlertModel, IncidentModel, ProcessSnapshotModel
from app.detectors.file_monitor import FileMonitorService, FileEvent
from app.detectors.process_monitor import ProcessMonitor
from app.detectors.detection_engine import SlidingWindowDetectionEngine
from app.detectors.threat_scorer import ThreatScorer
from app.detectors.responder import IncidentResponder

app = FastAPI(
    title="Ransomware Detection and Response System (RDRS) API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine_detector = SlidingWindowDetectionEngine()
file_monitor_service = None

def event_pipeline_callback(event: FileEvent):
    session = SessionLocal()
    try:
        record = FileEventModel(
            event_type=event.event_type,
            src_path=event.src_path,
            dest_path=event.dest_path,
            file_extension=event.file_extension,
            entropy=event.entropy,
            timestamp=event.timestamp
        )
        session.add(record)
        session.commit()
    except Exception as e:
        session.rollback()
    finally:
        session.close()

    signals = engine_detector.analyze_event(event)
    if signals.is_burst_detected:
        active_processes = ProcessMonitor.capture_snapshots(limit=5)
        assessment = ThreatScorer.calculate_score(signals, active_processes)
        IncidentResponder.handle_threat(assessment)

@app.on_event("startup")
def on_startup():
    global file_monitor_service
    init_db()
    file_monitor_service = FileMonitorService(callback=event_pipeline_callback)
    file_monitor_service.start()

@app.on_event("shutdown")
def on_shutdown():
    global file_monitor_service
    if file_monitor_service:
        file_monitor_service.stop()

@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.get("/status")
def get_system_status(db: Session = Depends(get_db)):
    total_events = db.query(FileEventModel).count()
    total_alerts = db.query(AlertModel).count()
    total_incidents = db.query(IncidentModel).count()
    latest_alert = db.query(AlertModel).order_by(desc(AlertModel.timestamp)).first()

    current_threat_level = latest_alert.severity if latest_alert else "Normal"
    current_score = latest_alert.score if latest_alert else 0.0

    return {
        "threat_level": current_threat_level,
        "threat_score": current_score,
        "monitored_paths": settings.monitor.watch_paths,
        "total_events_observed": total_events,
        "total_alerts_raised": total_alerts,
        "total_incidents_recorded": total_incidents,
        "simulation_mode": settings.system.simulation_mode
    }

@app.get("/alerts")
def get_alerts(limit: int = 50, db: Session = Depends(get_db)):
    alerts = db.query(AlertModel).order_by(desc(AlertModel.timestamp)).limit(limit).all()
    return [
        {
            "id": a.id,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "severity": a.severity,
            "score": a.score,
            "rule_name": a.rule_name,
            "description": a.description,
            "suspect_process": a.suspect_process,
            "suspect_pid": a.suspect_pid
        }
        for a in alerts
    ]

@app.get("/events")
def get_events(limit: int = 50, db: Session = Depends(get_db)):
    events = db.query(FileEventModel).order_by(desc(FileEventModel.timestamp)).limit(limit).all()
    return [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "event_type": e.event_type,
            "src_path": e.src_path,
            "dest_path": e.dest_path,
            "file_extension": e.file_extension,
            "entropy": e.entropy
        }
        for e in events
    ]

class ScanRequest(BaseModel):
    target_path: str = Field(default="./data/sandbox")

@app.post("/scan")
def manual_file_scan(req: ScanRequest):
    path = Path(req.target_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Target path does not exist")

    scanned_files = []
    suspicious_files = []
    files = list(path.rglob("*")) if path.is_dir() else [path]
    for f in files:
        if f.is_file():
            entropy = calculate_file_entropy(str(f))
            item = {"file": str(f), "entropy": entropy, "extension": f.suffix}
            scanned_files.append(item)
            if entropy >= settings.detection.entropy_threshold or f.suffix.lower() in [".locked", ".enc", ".crypto"]:
                suspicious_files.append(item)

    return {
        "status": "Scan Complete",
        "total_scanned": len(scanned_files),
        "suspicious_found": len(suspicious_files),
        "suspicious_files": suspicious_files
    }
