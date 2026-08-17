"""Comprehensive Unit & Integration Test Suite for RDRS."""
import os
import pytest
from datetime import datetime, timezone
from pathlib import Path
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.entropy import calculate_shannon_entropy, calculate_file_entropy
from app.database.db import SessionLocal, init_db
from app.database.models import FileEventModel, AlertModel, IncidentModel, ProcessSnapshotModel
from app.detectors.file_monitor import FileEvent
from app.detectors.process_monitor import ProcessMonitor, ProcessTelemetry
from app.detectors.detection_engine import SlidingWindowDetectionEngine, DetectionSignals
from app.detectors.threat_scorer import ThreatScorer
from app.detectors.responder import IncidentResponder
from app.reports.generator import ReportGenerator
from app.api.main import app

client = TestClient(app)


# 1. Entropy Tests
def test_entropy_math_and_file(tmp_path):
    assert calculate_shannon_entropy(b"") == 0.0
    assert calculate_shannon_entropy(b"AAAA" * 100) == 0.0
    
    random_bytes = os.urandom(20000)
    assert 7.8 <= calculate_shannon_entropy(random_bytes) <= 8.0

    test_file = tmp_path / "test.dat"
    test_file.write_bytes(random_bytes)
    assert 7.8 <= calculate_file_entropy(str(test_file)) <= 8.0

    non_existent = tmp_path / "ghost.txt"
    assert calculate_file_entropy(str(non_existent)) == 0.0


# 2. Database Initialization & Models
def test_database_models():
    init_db()
    session = SessionLocal()
    try:
        ev = FileEventModel(event_type="created", src_path="test.txt", entropy=7.5)
        snap = ProcessSnapshotModel(pid=123, name="test.exe", cpu_percent=10.5)
        al = AlertModel(severity="Critical", score=85.0, rule_name="Test Rule", description="Test Alert")
        inc = IncidentModel(threat_score=85.0, status="Contained", suspect_process="test.exe", mitigation_action="Log")

        session.add_all([ev, snap, al, inc])
        session.commit()

        assert session.query(FileEventModel).count() >= 1
        assert session.query(AlertModel).count() >= 1
        assert session.query(IncidentModel).count() >= 1
    finally:
        session.close()


# 3. Sliding Window Detection Engine
def test_detection_engine_window_eviction():
    engine = SlidingWindowDetectionEngine(window_seconds=2)
    old_time = datetime(2020, 1, 1, 12, 0, 0)
    new_time = datetime(2020, 1, 1, 12, 0, 5)

    ev_old = FileEvent(event_type="modified", src_path="old.txt", file_extension=".txt", entropy=7.5, timestamp=old_time)
    ev_new = FileEvent(event_type="renamed", src_path="a.txt", dest_path="a.locked", file_extension=".locked", entropy=7.9, timestamp=new_time)

    engine.analyze_event(ev_old)
    signals = engine.analyze_event(ev_new)

    assert signals.events_in_window == 1
    assert signals.renames_count == 1
    assert signals.extension_changes_count == 1


# 4. Threat Scorer Bands
def test_threat_scorer_bands():
    signals = DetectionSignals(
        events_in_window=30,
        modifications_count=25,
        renames_count=15,
        extension_changes_count=5,
        high_entropy_files_count=10,
        avg_entropy=7.8,
        affected_files=["data/sandbox/doc.locked"],
        is_burst_detected=True,
        triggered_reasons=["High-entropy encryption burst"]
    )
    procs = [ProcessTelemetry(pid=999, name="ransom_sim.exe", cpu_percent=85.0, write_bytes=10000000)]
    
    assessment = ThreatScorer.calculate_score(signals, procs)
    assert assessment.score >= 70
    assert assessment.level == "Critical"


# 5. Incident Responder & Evidence Quarantine
def test_responder_quarantine(tmp_path):
    sample_evidence = tmp_path / "compromised.locked"
    sample_evidence.write_bytes(b"encrypted payload data")

    vault = IncidentResponder.quarantine_evidence([str(sample_evidence)])
    assert Path(vault).exists()

    signals = DetectionSignals(
        high_entropy_files_count=10,
        modifications_count=25,
        renames_count=15,
        affected_files=[str(sample_evidence)],
        is_burst_detected=True
    )
    procs = [ProcessTelemetry(pid=101, name="sim.exe", cpu_percent=50.0)]
    assessment = ThreatScorer.calculate_score(signals, procs)
    IncidentResponder.handle_threat(assessment)


# 6. Process Monitor Telemetry
def test_process_monitor_capture():
    snapshots = ProcessMonitor.capture_snapshots(limit=5)
    assert isinstance(snapshots, list)
    if snapshots:
        assert isinstance(snapshots[0].pid, int)
        assert isinstance(snapshots[0].name, str)


# 7. Report Generators (JSON, CSV, PDF)
def test_report_generation():
    json_path = ReportGenerator.generate_json_report()
    csv_path = ReportGenerator.generate_csv_report()
    pdf_path = ReportGenerator.generate_pdf_report()

    assert Path(json_path).exists()
    assert Path(csv_path).exists()
    assert Path(pdf_path).exists()


# 8. REST API Endpoints Integration
def test_rest_api_endpoints():
    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "healthy"

    res_status = client.get("/status")
    assert res_status.status_code == 200
    assert "threat_level" in res_status.json()

    res_alerts = client.get("/alerts")
    assert res_alerts.status_code == 200

    res_events = client.get("/events")
    assert res_events.status_code == 200

    res_scan = client.post("/scan", json={"target_path": "./data/sandbox"})
    assert res_scan.status_code == 200
