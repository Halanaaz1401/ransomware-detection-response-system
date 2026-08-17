"""System process telemetry collector using psutil."""
from datetime import datetime
from typing import List, Optional
import psutil
from pydantic import BaseModel, Field
from app.core.logger import get_logger

system_logger = get_logger("system")


class ProcessTelemetry(BaseModel):
    """Model holding captured process metrics."""
    pid: int
    name: str
    exe_path: Optional[str] = None
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    read_bytes: int = 0
    write_bytes: int = 0
    parent_pid: Optional[int] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ProcessMonitor:
    """Monitors running processes and identifies high-activity suspects."""

    @staticmethod
    def capture_snapshots(limit: int = 15) -> List[ProcessTelemetry]:
        """
        Captures active running processes sorted by recent disk writes and CPU activity.
        Safely handles AccessDenied exceptions.
        """
        snapshots: List[ProcessTelemetry] = []

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_percent', 'io_counters', 'ppid']):
            try:
                info = proc.info
                io = info.get('io_counters')
                read_bytes = io.read_bytes if io else 0
                write_bytes = io.write_bytes if io else 0

                telemetry = ProcessTelemetry(
                    pid=info['pid'],
                    name=info.get('name') or "Unknown",
                    exe_path=info.get('exe'),
                    cpu_percent=info.get('cpu_percent') or 0.0,
                    memory_percent=info.get('memory_percent') or 0.0,
                    read_bytes=read_bytes,
                    write_bytes=write_bytes,
                    parent_pid=info.get('ppid')
                )
                snapshots.append(telemetry)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        snapshots.sort(key=lambda p: (p.write_bytes, p.cpu_percent), reverse=True)
        return snapshots[:limit]
