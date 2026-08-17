"""Sliding window detection engine to detect ransomware behavioral bursts."""
from collections import deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.logger import get_logger
from app.detectors.file_monitor import FileEvent

system_logger = get_logger("system")


class DetectionSignals(BaseModel):
    """Signals computed over the current sliding time window."""
    events_in_window: int = 0
    modifications_count: int = 0
    renames_count: int = 0
    extension_changes_count: int = 0
    high_entropy_files_count: int = 0
    avg_entropy: float = 0.0
    affected_files: List[str] = Field(default_factory=list)
    is_burst_detected: bool = False
    triggered_reasons: List[str] = Field(default_factory=list)


class SlidingWindowDetectionEngine:
    """Maintains a rolling window of file events and evaluates threat heuristics."""

    def __init__(self, window_seconds: Optional[int] = None):
        self.window_seconds = window_seconds or settings.detection.sliding_window_seconds
        self.event_window: deque[FileEvent] = deque()

    def _evict_stale_events(self, current_time: datetime):
        """Removes events older than the sliding window threshold."""
        threshold_time = current_time - timedelta(seconds=self.window_seconds)
        while self.event_window and self.event_window[0].timestamp < threshold_time:
            self.event_window.popleft()

    def analyze_event(self, new_event: FileEvent) -> DetectionSignals:
        """Adds a new event to the window and recomputes behavioral heuristics."""
        self.event_window.append(new_event)
        self._evict_stale_events(new_event.timestamp)

        modifications = 0
        renames = 0
        extension_changes = 0
        high_entropy_count = 0
        total_entropy = 0.0
        entropy_sampled_files = 0
        affected_files: List[str] = []
        triggered_reasons: List[str] = []

        thresholds = settings.detection.burst_thresholds

        for ev in self.event_window:
            target_path = ev.dest_path if ev.dest_path else ev.src_path
            if target_path not in affected_files:
                affected_files.append(target_path)

            if ev.event_type in ["created", "modified"]:
                modifications += 1
                if ev.entropy > 0:
                    total_entropy += ev.entropy
                    entropy_sampled_files += 1
                    if ev.entropy >= settings.detection.entropy_threshold:
                        high_entropy_count += 1

            elif ev.event_type == "renamed":
                renames += 1
                if ev.dest_path and ev.src_path:
                    old_ext = ev.src_path.split(".")[-1] if "." in ev.src_path else ""
                    new_ext = ev.dest_path.split(".")[-1] if "." in ev.dest_path else ""
                    if old_ext != new_ext or new_ext in ["locked", "crypto", "enc", "ransom"]:
                        extension_changes += 1

        avg_entropy = round(total_entropy / entropy_sampled_files, 2) if entropy_sampled_files > 0 else 0.0

        # Heuristic Threshold checks
        if modifications >= thresholds.modifications_per_minute:
            triggered_reasons.append(f"Rapid modifications burst ({modifications} ops/window)")
        if renames >= thresholds.renames_per_minute:
            triggered_reasons.append(f"Mass file renames detected ({renames} renames/window)")
        if extension_changes >= thresholds.extension_changes_per_minute:
            triggered_reasons.append(f"Suspicious extension changes detected ({extension_changes} files)")
        if high_entropy_count >= thresholds.entropy_spike_count:
            triggered_reasons.append(f"High-entropy encryption burst ({high_entropy_count} files >= {settings.detection.entropy_threshold})")

        is_burst = len(triggered_reasons) > 0

        signals = DetectionSignals(
            events_in_window=len(self.event_window),
            modifications_count=modifications,
            renames_count=renames,
            extension_changes_count=extension_changes,
            high_entropy_files_count=high_entropy_count,
            avg_entropy=avg_entropy,
            affected_files=affected_files,
            is_burst_detected=is_burst,
            triggered_reasons=triggered_reasons
        )

        return signals
