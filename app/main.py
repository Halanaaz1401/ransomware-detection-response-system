"""Application main entry point orchestrating Detection, Scoring, DB and Quarantine."""
import sys
import time
from app.core.logger import get_logger
from app.database.db import init_db, SessionLocal
from app.database.models import FileEventModel, ProcessSnapshotModel
from app.detectors.file_monitor import FileMonitorService, FileEvent
from app.detectors.process_monitor import ProcessMonitor
from app.detectors.detection_engine import SlidingWindowDetectionEngine
from app.detectors.threat_scorer import ThreatScorer
from app.detectors.responder import IncidentResponder

system_logger = get_logger("system")

engine = SlidingWindowDetectionEngine()


def event_pipeline_callback(event: FileEvent):
    """End-to-end event pipeline: Ingest -> DB -> Sliding Window -> Score -> Response."""
    # 1. Save event to SQLite
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
        system_logger.error(f"Error writing event to DB: {e}")
    finally:
        session.close()

    # 2. Sliding Window Heuristic Analysis
    signals = engine.analyze_event(event)

    # 3. Threat Scoring & Containment Trigger
    if signals.is_burst_detected:
        active_processes = ProcessMonitor.capture_snapshots(limit=5)
        assessment = ThreatScorer.calculate_score(signals, active_processes)
        IncidentResponder.handle_threat(assessment)


def main():
    init_db()
    system_logger.info("Starting Ransomware Detection and Response System (RDRS)...")

    monitor = FileMonitorService(callback=event_pipeline_callback)
    monitor.start()

    print("\n" + "="*60)
    print(" [+] RDRS Integrated Detection & Quarantine Engine is LIVE")
    print(" [+] Database: data/rdrs.db")
    print(" [+] Sandbox Folder: ./data/sandbox")
    print(" [+] Quarantine Vault: ./data/quarantine")
    print(" [+] Press Ctrl + C to stop")
    print("="*60 + "\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitor service...")
        monitor.stop()
        system_logger.info("RDRS shutdown cleanly.")
        sys.exit(0)


if __name__ == "__main__":
    main()
