"""FastAPI REST API server for the Ransomware Detection and Response System."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.entropy import calculate_file_entropy
from app.database.db import get_db, init_db, SessionLocal
from app.database.models import (
    FileEventModel,
    AlertModel,
    IncidentModel,
    ProcessSnapshotModel,
)
from app.detectors.file_monitor import FileMonitorService, FileEvent
from app.detectors.process_monitor import ProcessMonitor
from app.detectors.detection_engine import SlidingWindowDetectionEngine
from app.detectors.threat_scorer import ThreatScorer
from app.detectors.responder import IncidentResponder
from app.reports.generator import ReportGenerator


app = FastAPI(
    title="Ransomware Detection and Response System (RDRS) API",
    version="1.0.0",
    description=(
        "Defensive REST API for the Ransomware Detection and Response System."
    ),
)


# Restrict CORS to the local dashboard during normal development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


engine_detector = SlidingWindowDetectionEngine()
file_monitor_service = None


def save_process_snapshots(snapshots) -> None:
    """Persist process telemetry captured by psutil."""
    if not snapshots:
        return

    session = SessionLocal()

    try:
        records = [
            ProcessSnapshotModel(
                timestamp=snapshot.timestamp,
                pid=snapshot.pid,
                name=snapshot.name,
                exe_path=snapshot.exe_path,
                cpu_percent=snapshot.cpu_percent,
                memory_percent=snapshot.memory_percent,
                read_bytes=snapshot.read_bytes,
                write_bytes=snapshot.write_bytes,
                parent_pid=snapshot.parent_pid,
            )
            for snapshot in snapshots
        ]

        session.add_all(records)
        session.commit()

    except Exception:
        session.rollback()
        raise

    finally:
        session.close()


def event_pipeline_callback(event: FileEvent):
    """Process filesystem events through storage, detection, scoring and response."""

    session = SessionLocal()

    try:
        record = FileEventModel(
            event_type=event.event_type,
            src_path=event.src_path,
            dest_path=event.dest_path,
            file_extension=event.file_extension,
            entropy=event.entropy,
            timestamp=event.timestamp,
        )

        session.add(record)
        session.commit()

    except Exception:
        session.rollback()

    finally:
        session.close()

    signals = engine_detector.analyze_event(event)

    if signals.is_burst_detected:
        active_processes = ProcessMonitor.capture_snapshots(limit=5)

        try:
            save_process_snapshots(active_processes)
        except Exception:
            # Detection should continue even if telemetry persistence fails.
            pass

        assessment = ThreatScorer.calculate_score(
            signals,
            active_processes,
        )

        IncidentResponder.handle_threat(assessment)


@app.on_event("startup")
def on_startup():
    """Initialize the database and start filesystem monitoring."""
    global file_monitor_service

    init_db()

    file_monitor_service = FileMonitorService(
        callback=event_pipeline_callback
    )

    file_monitor_service.start()


@app.on_event("shutdown")
def on_shutdown():
    """Stop filesystem monitoring cleanly."""
    global file_monitor_service

    if file_monitor_service:
        file_monitor_service.stop()


@app.get("/health")
def health_check():
    """Return API health status."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/status")
def get_system_status(db: Session = Depends(get_db)):
    """Return the current RDRS operational status."""

    total_events = db.query(FileEventModel).count()
    total_alerts = db.query(AlertModel).count()
    total_incidents = db.query(IncidentModel).count()
    total_process_snapshots = db.query(ProcessSnapshotModel).count()

    latest_alert = (
        db.query(AlertModel)
        .order_by(desc(AlertModel.timestamp))
        .first()
    )

    current_threat_level = (
        latest_alert.severity
        if latest_alert
        else "Normal"
    )

    current_score = (
        latest_alert.score
        if latest_alert
        else 0.0
    )

    return {
        "threat_level": current_threat_level,
        "threat_score": current_score,
        "monitored_paths": settings.monitor.watch_paths,
        "total_events_observed": total_events,
        "total_alerts_raised": total_alerts,
        "total_incidents_recorded": total_incidents,
        "total_process_snapshots": total_process_snapshots,
        "simulation_mode": settings.system.simulation_mode,
    }


@app.get("/alerts")
def get_alerts(
    limit: int = 50,
    db: Session = Depends(get_db),
):
    """Return recent security alerts."""

    limit = max(1, min(limit, 500))

    alerts = (
        db.query(AlertModel)
        .order_by(desc(AlertModel.timestamp))
        .limit(limit)
        .all()
    )

    return [
        {
            "id": alert.id,
            "timestamp": (
                alert.timestamp.isoformat()
                if alert.timestamp
                else None
            ),
            "severity": alert.severity,
            "score": alert.score,
            "rule_name": alert.rule_name,
            "description": alert.description,
            "suspect_process": alert.suspect_process,
            "suspect_pid": alert.suspect_pid,
        }
        for alert in alerts
    ]


@app.get("/events")
def get_events(
    limit: int = 50,
    db: Session = Depends(get_db),
):
    """Return recent filesystem events."""

    limit = max(1, min(limit, 500))

    events = (
        db.query(FileEventModel)
        .order_by(desc(FileEventModel.timestamp))
        .limit(limit)
        .all()
    )

    return [
        {
            "id": event.id,
            "timestamp": (
                event.timestamp.isoformat()
                if event.timestamp
                else None
            ),
            "event_type": event.event_type,
            "src_path": event.src_path,
            "dest_path": event.dest_path,
            "file_extension": event.file_extension,
            "entropy": event.entropy,
        }
        for event in events
    ]


@app.get("/processes")
def get_processes(
    limit: int = 50,
    db: Session = Depends(get_db),
):
    """Return recent process telemetry."""

    limit = max(1, min(limit, 500))

    processes = (
        db.query(ProcessSnapshotModel)
        .order_by(desc(ProcessSnapshotModel.timestamp))
        .limit(limit)
        .all()
    )

    return [
        {
            "id": process.id,
            "timestamp": (
                process.timestamp.isoformat()
                if process.timestamp
                else None
            ),
            "pid": process.pid,
            "name": process.name,
            "exe_path": process.exe_path,
            "cpu_percent": process.cpu_percent,
            "memory_percent": process.memory_percent,
            "read_bytes": process.read_bytes,
            "write_bytes": process.write_bytes,
            "parent_pid": process.parent_pid,
            "is_suspicious": process.is_suspicious,
        }
        for process in processes
    ]


@app.get("/incidents")
def get_incidents(
    limit: int = 50,
    db: Session = Depends(get_db),
):
    """Return recent incident records."""

    limit = max(1, min(limit, 500))

    incidents = (
        db.query(IncidentModel)
        .order_by(desc(IncidentModel.timestamp))
        .limit(limit)
        .all()
    )

    return [
        {
            "id": incident.id,
            "timestamp": (
                incident.timestamp.isoformat()
                if incident.timestamp
                else None
            ),
            "threat_score": incident.threat_score,
            "status": incident.status,
            "affected_files_count": incident.affected_files_count,
            "suspect_process": incident.suspect_process,
            "suspect_pid": incident.suspect_pid,
            "evidence_path": incident.evidence_path,
            "mitigation_action": incident.mitigation_action,
        }
        for incident in incidents
    ]


@app.get("/reports")
def get_reports():
    """List generated incident and alert reports."""

    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    reports = []

    for report_file in sorted(
        reports_dir.iterdir(),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    ):
        if report_file.is_file():
            stat = report_file.stat()

            reports.append(
                {
                    "name": report_file.name,
                    "path": str(report_file),
                    "type": report_file.suffix.lower().lstrip("."),
                    "size_bytes": stat.st_size,
                    "modified_at": datetime.fromtimestamp(
                        stat.st_mtime,
                        tz=timezone.utc,
                    ).isoformat(),
                }
            )

    return {
        "status": "success",
        "report_count": len(reports),
        "reports": reports,
    }


class ScanRequest(BaseModel):
    """Request body for a manual filesystem scan."""

    target_path: str = Field(default="./data/sandbox")


@app.post("/scan")
def manual_file_scan(req: ScanRequest):
    """Perform a manual entropy and suspicious-extension scan."""

    path = Path(req.target_path)

    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail="Target path does not exist",
        )

    scanned_files = []
    suspicious_files = []

    files = (
        list(path.rglob("*"))
        if path.is_dir()
        else [path]
    )

    for file_path in files:
        if not file_path.is_file():
            continue

        entropy = calculate_file_entropy(str(file_path))

        item = {
            "file": str(file_path),
            "entropy": entropy,
            "extension": file_path.suffix,
        }

        scanned_files.append(item)

        if (
            entropy >= settings.detection.entropy_threshold
            or file_path.suffix.lower()
            in [".locked", ".enc", ".crypto"]
        ):
            suspicious_files.append(item)

    return {
        "status": "Scan Complete",
        "total_scanned": len(scanned_files),
        "suspicious_found": len(suspicious_files),
        "suspicious_files": suspicious_files,
    }


class SettingsUpdate(BaseModel):
    """Supported runtime configuration updates."""

    watch_paths: Optional[List[str]] = None
    entropy_threshold: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=8.0,
    )
    simulation_mode: Optional[bool] = None
    auto_isolate_process: Optional[bool] = None


@app.post("/settings")
def update_settings(update: SettingsUpdate):
    """Update supported RDRS settings and persist them to config.yaml."""

    changed = {}

    if update.watch_paths is not None:
        if not update.watch_paths:
            raise HTTPException(
                status_code=400,
                detail="watch_paths cannot be empty",
            )

        settings.monitor.watch_paths = update.watch_paths
        changed["watch_paths"] = update.watch_paths

    if update.entropy_threshold is not None:
        settings.detection.entropy_threshold = update.entropy_threshold
        changed["entropy_threshold"] = update.entropy_threshold

    if update.simulation_mode is not None:
        settings.system.simulation_mode = update.simulation_mode
        changed["simulation_mode"] = update.simulation_mode

    if update.auto_isolate_process is not None:
        settings.response.auto_isolate_process = (
            update.auto_isolate_process
        )
        changed["auto_isolate_process"] = (
            update.auto_isolate_process
        )

    if not changed:
        return {
            "status": "no_changes",
            "message": "No settings were supplied.",
        }

    config_path = Path("config.yaml")

    try:
        config_data: Dict[str, Any] = {}

        if config_path.exists():
            with config_path.open(
                "r",
                encoding="utf-8",
            ) as config_file:
                config_data = yaml.safe_load(config_file) or {}

        monitor_config = config_data.setdefault("monitor", {})
        detection_config = config_data.setdefault("detection", {})
        system_config = config_data.setdefault("system", {})
        response_config = config_data.setdefault("response", {})

        if update.watch_paths is not None:
            monitor_config["watch_paths"] = update.watch_paths

        if update.entropy_threshold is not None:
            detection_config["entropy_threshold"] = (
                update.entropy_threshold
            )

        if update.simulation_mode is not None:
            system_config["simulation_mode"] = (
                update.simulation_mode
            )

        if update.auto_isolate_process is not None:
            response_config["auto_isolate_process"] = (
                update.auto_isolate_process
            )

        with config_path.open(
            "w",
            encoding="utf-8",
        ) as config_file:
            yaml.safe_dump(
                config_data,
                config_file,
                sort_keys=False,
            )

    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to persist settings: {exc}",
        ) from exc

    return {
        "status": "updated",
        "changed": changed,
        "message": "RDRS settings updated successfully.",
    }


@app.get("/generate-reports")
def generate_reports():
    """Generate JSON, CSV and PDF reports from current database data."""

    try:
        json_report = ReportGenerator.generate_json_report()
        csv_report = ReportGenerator.generate_csv_report()
        pdf_report = ReportGenerator.generate_pdf_report()

        return {
            "status": "success",
            "json_report": json_report,
            "csv_report": csv_report,
            "pdf_report": pdf_report,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Report generation failed: {exc}",
        ) from exc
