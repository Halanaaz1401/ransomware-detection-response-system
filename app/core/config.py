"""Configuration loader module using PyYAML and Pydantic."""
from pathlib import Path
from typing import List
import yaml
from pydantic import BaseModel, Field


class SystemConfig(BaseModel):
    app_name: str = "RDRS"
    version: str = "1.0.0"
    simulation_mode: bool = True


class MonitorConfig(BaseModel):
    watch_paths: List[str] = Field(default_factory=lambda: ["./data/sandbox"])
    recursive: bool = True
    ignore_patterns: List[str] = Field(default_factory=lambda: ["*.tmp", "*.log", "*.db"])


class BurstThresholds(BaseModel):
    modifications_per_minute: int = 20
    renames_per_minute: int = 10
    extension_changes_per_minute: int = 5
    entropy_spike_count: int = 5


class DetectionConfig(BaseModel):
    sliding_window_seconds: int = 60
    entropy_threshold: float = 7.2
    sample_size_bytes: int = 65536
    burst_thresholds: BurstThresholds = Field(default_factory=BurstThresholds)


class ScoringWeights(BaseModel):
    rapid_encryption: int = 40
    mass_rename: int = 30
    high_entropy: int = 25
    cpu_spike: int = 15
    unknown_program: int = 10


class ScoringBands(BaseModel):
    normal_max: int = 40
    warning_max: int = 70
    critical_min: int = 70


class ScoringConfig(BaseModel):
    weights: ScoringWeights = Field(default_factory=ScoringWeights)
    bands: ScoringBands = Field(default_factory=ScoringBands)


class ResponseConfig(BaseModel):
    quarantine_dir: str = "./data/quarantine"
    auto_isolate_process: bool = True


class AppConfig(BaseModel):
    system: SystemConfig = Field(default_factory=SystemConfig)
    monitor: MonitorConfig = Field(default_factory=MonitorConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    response: ResponseConfig = Field(default_factory=ResponseConfig)


def load_config(config_path: str = "config.yaml") -> AppConfig:
    """Safely loads and validates configuration from YAML file."""
    path = Path(config_path)
    if not path.exists():
        return AppConfig()
    
    with open(path, "r", encoding="utf-8") as f:
        raw_data = yaml.safe_load(f) or {}
    
    return AppConfig(**raw_data)


# Global config instance
settings = load_config()