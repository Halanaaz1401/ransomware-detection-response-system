"""Threat scoring engine mapping behavioral heuristics to a 0-100 score."""
from typing import Dict, List, Tuple
from pydantic import BaseModel, Field
from app.core.config import settings
from app.detectors.detection_engine import DetectionSignals
from app.detectors.process_monitor import ProcessTelemetry


class ThreatAssessment(BaseModel):
    """Result of threat calculation."""
    score: float = 0.0
    level: str = "Normal"  # Normal, Warning, Critical
    triggered_rules: List[str] = Field(default_factory=list)
    suspect_process: str = "Unknown"
    suspect_pid: int = 0
    affected_files: List[str] = Field(default_factory=list)


class ThreatScorer:
    """Computes transparent, weighted threat scores without ML dependencies."""

    @staticmethod
    def calculate_score(signals: DetectionSignals, active_processes: List[ProcessTelemetry]) -> ThreatAssessment:
        weights = settings.scoring.weights
        bands = settings.scoring.bands

        score = 0.0
        triggered_rules: List[str] = []

        # 1. High-entropy encryption burst check
        if signals.high_entropy_files_count >= settings.detection.burst_thresholds.entropy_spike_count:
            score += weights.high_entropy
            triggered_rules.append(f"High Entropy Burst (+{weights.high_entropy})")

        # 2. Rapid modifications burst check
        if signals.modifications_count >= settings.detection.burst_thresholds.modifications_per_minute:
            score += weights.rapid_encryption
            triggered_rules.append(f"Rapid Mass Encryption (+{weights.rapid_encryption})")

        # 3. Mass renames / Extension manipulation check
        if signals.renames_count >= settings.detection.burst_thresholds.renames_per_minute or signals.extension_changes_count > 0:
            score += weights.mass_rename
            triggered_rules.append(f"Mass Rename/Extension Change (+{weights.mass_rename})")

        # 4. Suspect Process Telemetry Check (High CPU / Disk Writes)
        suspect_name = "Unknown"
        suspect_pid = 0

        if active_processes:
            top_process = active_processes[0]
            suspect_name = top_process.name
            suspect_pid = top_process.pid

            if top_process.cpu_percent > 30.0 or top_process.write_bytes > 5_000_000:
                score += weights.cpu_spike
                triggered_rules.append(f"Process CPU/IO Spike (+{weights.cpu_spike})")

        # Cap maximum score at 100
        score = min(100.0, score)

        # Map to severity bands
        if score >= bands.critical_min:
            level = "Critical"
        elif score > bands.normal_max:
            level = "Warning"
        else:
            level = "Normal"

        return ThreatAssessment(
            score=score,
            level=level,
            triggered_rules=triggered_rules,
            suspect_process=suspect_name,
            suspect_pid=suspect_pid,
            affected_files=signals.affected_files
        )
