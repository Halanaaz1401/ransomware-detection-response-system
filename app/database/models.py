"""SQLAlchemy database models for RDRS."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class FileEventModel(Base):
    """Stores all raw file events observed in monitored folders."""
    __tablename__ = "file_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(String(50), nullable=False)
    src_path = Column(Text, nullable=False)
    dest_path = Column(Text, nullable=True)
    file_extension = Column(String(50), nullable=True)
    entropy = Column(Float, default=0.0)


class ProcessSnapshotModel(Base):
    """Stores process telemetry captured via psutil."""
    __tablename__ = "process_snapshots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    pid = Column(Integer, nullable=False)
    name = Column(String(255), nullable=False)
    exe_path = Column(Text, nullable=True)
    cpu_percent = Column(Float, default=0.0)
    memory_percent = Column(Float, default=0.0)
    read_bytes = Column(Integer, default=0)
    write_bytes = Column(Integer, default=0)
    parent_pid = Column(Integer, nullable=True)
    is_suspicious = Column(Boolean, default=False)


class AlertModel(Base):
    """Stores generated threat alerts."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    severity = Column(String(50), nullable=False)
    score = Column(Float, nullable=False)
    rule_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    suspect_pid = Column(Integer, nullable=True)
    suspect_process = Column(String(255), nullable=True)


class IncidentModel(Base):
    """Stores confirmed incident records and quarantine evidence tracking."""
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    threat_score = Column(Float, nullable=False)
    status = Column(String(50), default="Investigating")
    affected_files_count = Column(Integer, default=0)
    suspect_process = Column(String(255), nullable=True)
    suspect_pid = Column(Integer, nullable=True)
    evidence_path = Column(Text, nullable=True)
    mitigation_action = Column(String(255), default="Simulated Quarantine")
