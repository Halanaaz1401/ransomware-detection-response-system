"""Automated Incident Response & Evidence Quarantine Handler."""
import shutil
from pathlib import Path
from typing import List
from datetime import datetime

from app.core.config import settings
from app.core.logger import get_logger
from app.database.db import SessionLocal
from app.database.models import AlertModel, IncidentModel
from app.detectors.threat_scorer import ThreatAssessment

alert_logger = get_logger("alert")
audit_logger = get_logger("audit")
system_logger = get_logger("system")


class IncidentResponder:
    """Manages forensic evidence preservation and containment workflows."""

    @staticmethod
    def quarantine_evidence(file_paths: List[str]) -> str:
        """
        Copies affected files to safe quarantine directory.
        Original files are left untouched.
        """
        quarantine_root = Path(settings.response.quarantine_dir)
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        incident_vault = quarantine_root / f"incident_{timestamp_str}"
        incident_vault.mkdir(parents=True, exist_ok=True)

        copied_count = 0
        for path_str in file_paths:
            src = Path(path_str)
            if src.exists() and src.is_file():
                dest = incident_vault / src.name
                shutil.copy2(src, dest)
                copied_count += 1

        audit_logger.info(f"Preserved {copied_count} evidence files in {incident_vault.resolve()}")
        return str(incident_vault.resolve())

    @staticmethod
    def handle_threat(assessment: ThreatAssessment):
        """Processes threat assessment, logs alerts, and triggers quarantine on Critical."""
        if assessment.level == "Normal":
            return

        session = SessionLocal()
        try:
            # 1. Create Alert Record
            alert = AlertModel(
                severity=assessment.level,
                score=assessment.score,
                rule_name=", ".join(assessment.triggered_rules),
                description=f"Behavioral threat detected. Affected files: {len(assessment.affected_files)}",
                suspect_pid=assessment.suspect_pid,
                suspect_process=assessment.suspect_process
            )
            session.add(alert)

            alert_logger.warning(
                f"[{assessment.level.upper()} ALERT] Score: {assessment.score} | Suspect: {assessment.suspect_process} (PID: {assessment.suspect_pid}) | Rules: {alert.rule_name}"
            )

            # 2. Trigger Quarantine & Incident Logging on Critical
            if assessment.level == "Critical":
                evidence_vault = IncidentResponder.quarantine_evidence(assessment.affected_files)

                # Containment Action in Simulation Mode
                action_taken = f"SIMULATION: Would terminate PID {assessment.suspect_pid} ({assessment.suspect_process})"
                if settings.system.simulation_mode:
                    audit_logger.info(f"[SIMULATION RESPONSE] Containment Action: {action_taken}")

                incident = IncidentModel(
                    threat_score=assessment.score,
                    status="Active Containment",
                    affected_files_count=len(assessment.affected_files),
                    suspect_process=assessment.suspect_process,
                    suspect_pid=assessment.suspect_pid,
                    evidence_path=evidence_vault,
                    mitigation_action=action_taken
                )
                session.add(incident)
                audit_logger.info(f"Incident record generated for PID {assessment.suspect_pid}")

            session.commit()
        except Exception as e:
            session.rollback()
            system_logger.error(f"Error handling incident response: {e}")
        finally:
            session.close()
