"""Centralized rotating logging configuration using Loguru."""
import sys
from pathlib import Path
from loguru import logger

# Ensure logs directory exists
LOGS_DIR = Path("logs")
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Remove default handler
logger.remove()

# Console output format
logger.add(
    sys.stdout,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
    level="INFO",
    colorize=True,
)

# 1. System Log
logger.add(
    LOGS_DIR / "system.log",
    rotation="10 MB",
    retention="7 days",
    level="DEBUG",
    filter=lambda record: "system" in record["extra"].get("category", "system"),
)

# 2. Events Log
logger.add(
    LOGS_DIR / "events.log",
    rotation="10 MB",
    retention="7 days",
    level="INFO",
    filter=lambda record: "event" in record["extra"].get("category", ""),
)

# 3. Alerts Log
logger.add(
    LOGS_DIR / "alerts.log",
    rotation="10 MB",
    retention="30 days",
    level="WARNING",
    filter=lambda record: "alert" in record["extra"].get("category", ""),
)

# 4. Errors Log
logger.add(
    LOGS_DIR / "errors.log",
    rotation="10 MB",
    retention="14 days",
    level="ERROR",
)

# 5. Audit Log (Append-only)
logger.add(
    LOGS_DIR / "audit.log",
    rotation="50 MB",
    retention="1 year",
    level="INFO",
    filter=lambda record: "audit" in record["extra"].get("category", ""),
)


def get_logger(category: str = "system"):
    """Returns a contextual logger bounded to a specific category."""
    return logger.bind(category=category)