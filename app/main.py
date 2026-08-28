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


def save_process_snapshots(snapshots):
    """Persist captured process telemetry to SQLite."""
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

        if records:
            session.add_all(records)
            session.commit()
            system_logger.info(
                f"Persisted {len(records)} process snapshots to database."
            )

    except Exception as exc:
        session.rollback()
        system_logger.error(
            f"Error writing process snapshots to DB: {exc}"
        )

    finally:
        session.close()


def save_file_event(event: FileEvent):
    """Persist a normalized filesystem event to SQLite."""
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

    except Exception as exc:
        session.rollback()
        system_logger.error(
            f"Error writing file event to DB: {exc}"
        )

    finally:
        session.close()


def event_pipeline_callback(event: FileEvent):
    """End-to-end event pipeline: ingest -> DB -> detection -> scoring -> response."""

    # 1. Save filesystem event to SQLite.
    save_file_event(event)

    # 2. Sliding-window heuristic analysis.
    signals = engine.analyze_event(event)

    # 3. Capture process telemetry when suspicious activity is detected.
    if signals.is_burst_detected:
        active_processes = ProcessMonitor.capture_snapshots(limit=5)

        # 4. Persist process telemetry to SQLite.
        save_process_snapshots(active_processes)

        # 5. Calculate threat score.
        assessment = ThreatScorer.calculate_score(
            signals,
            active_processes
        )

        # 6. Trigger incident response.
        IncidentResponder.handle_threat(assessment)


def main():
    """Start the RDRS monitoring service."""
    init_db()

    system_logger.info(
        "Starting Ransomware Detection and Response System (RDRS)..."
    )

    monitor = FileMonitorService(
        callback=event_pipeline_callback
    )

    monitor.start()

    print("\n" + "=" * 60)
    print(" [+] RDRS Integrated Detection & Quarantine Engine is LIVE")
    print(" [+] Database: data/rdrs.db")
    print(" [+] Sandbox Folder: ./data/sandbox")
    print(" [+] Quarantine Vault: ./data/quarantine")
    print(" [+] Press Ctrl + C to stop")
    print("=" * 60 + "\n")

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping monitor service...")

        monitor.stop()

        system_logger.info(
            "RDRS shutdown cleanly."
        )

        sys.exit(0)


if __name__ == "__main__":
    main()
