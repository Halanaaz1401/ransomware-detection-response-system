"""Real-time file system monitoring using Watchdog."""
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional
from pydantic import BaseModel, Field
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from app.core.config import settings
from app.core.entropy import calculate_file_entropy
from app.core.logger import get_logger

event_logger = get_logger("event")
system_logger = get_logger("system")


class FileEvent(BaseModel):
    """Normalized file-system event object."""
    event_type: str = Field(description="create | modify | rename | delete")
    src_path: str
    dest_path: Optional[str] = None
    file_extension: str
    entropy: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    is_directory: bool = False


class RDRSFileEventHandler(FileSystemEventHandler):
    """Watchdog event handler that parses and filters file system events."""

    def __init__(self, callback: Optional[Callable[[FileEvent], None]] = None):
        super().__init__()
        self.callback = callback
        self.event_count = 0

    def _should_ignore(self, path_str: str) -> bool:
        """Filter out temporary files and internal databases."""
        path = Path(path_str)
        for pattern in settings.monitor.ignore_patterns:
            if path.match(pattern) or pattern.replace("*", "") in path.name:
                return True
        return False

    def _process_event(self, event_type: str, src_path: str, dest_path: Optional[str] = None, is_dir: bool = False):
        if is_dir or self._should_ignore(src_path):
            return

        target_path = dest_path if dest_path else src_path
        extension = Path(target_path).suffix.lower()

        # Calculate Shannon entropy on created/modified files
        entropy_val = 0.0
        if event_type in ["created", "modified"] and Path(target_path).exists():
            entropy_val = calculate_file_entropy(
                target_path,
                sample_size=settings.detection.sample_size_bytes
            )

        event_obj = FileEvent(
            event_type=event_type,
            src_path=src_path,
            dest_path=dest_path,
            file_extension=extension,
            entropy=entropy_val,
            is_directory=is_dir
        )

        self.event_count += 1
        event_logger.info(
            f"[{self.event_count}] {event_type.upper()} -> {target_path} (Entropy: {entropy_val:.2f}, Ext: {extension})"
        )

        if self.callback:
            self.callback(event_obj)

    def on_created(self, event: FileSystemEvent):
        self._process_event("created", event.src_path, is_dir=event.is_directory)

    def on_modified(self, event: FileSystemEvent):
        self._process_event("modified", event.src_path, is_dir=event.is_directory)

    def on_deleted(self, event: FileSystemEvent):
        self._process_event("deleted", event.src_path, is_dir=event.is_directory)

    def on_moved(self, event: FileSystemEvent):
        self._process_event("renamed", event.src_path, dest_path=event.dest_path, is_dir=event.is_directory)


class FileMonitorService:
    """Service to manage directory observation lifecycle."""

    def __init__(self, callback: Optional[Callable[[FileEvent], None]] = None):
        self.observer = Observer()
        self.handler = RDRSFileEventHandler(callback=callback)

    def start(self):
        watch_paths = settings.monitor.watch_paths
        for p in watch_paths:
            path_obj = Path(p)
            path_obj.mkdir(parents=True, exist_ok=True)
            self.observer.schedule(
                self.handler,
                str(path_obj.resolve()),
                recursive=settings.monitor.recursive
            )
            system_logger.info(f"Monitoring initialized on path: {path_obj.resolve()}")

        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join()
        system_logger.info("File monitor observer stopped.")