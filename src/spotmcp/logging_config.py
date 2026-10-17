"""Structured JSON logging."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        audit = getattr(record, "audit", None)
        if isinstance(audit, dict):
            entry.update(audit)
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


# Transport loggers that log full request URLs (query strings included) at INFO/DEBUG. In GET mode those
# carry caller-supplied saved-query parameters, which must never reach the logs.
_URL_LOGGERS = ("httpx", "httpcore")


def quiet_transport_loggers() -> None:
    for name in _URL_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    quiet_transport_loggers()
