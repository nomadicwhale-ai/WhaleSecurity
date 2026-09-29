"""Logging setup (spec §18): stderr only, optional JSON lines, redacting filter."""

from __future__ import annotations

import json
import logging
import sys
import time
from logging.handlers import RotatingFileHandler

from .redact import Redactor

ROOT_LOGGER = "whalescan"
LEVELS = {"error": logging.ERROR, "warning": logging.WARNING, "info": logging.INFO, "debug": logging.DEBUG}


class RedactingFilter(logging.Filter):
    """Applies the run's redaction sweep and hidden-character reveal to every record."""

    def __init__(self, redactor: Redactor) -> None:
        super().__init__()
        self.redactor = redactor

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self.redactor.finalize(record.getMessage())
        record.args = None
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        obj = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + "Z",
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key in ("file", "rule_id", "elapsed_ms"):
            if hasattr(record, key):
                obj[key] = getattr(record, key)
        return json.dumps(obj, ensure_ascii=False, sort_keys=True)


def setup(
    level: str = "warning",
    fmt: str = "text",
    file: str = "",
    redactor: Redactor | None = None,
) -> logging.Logger:
    """Configure the ``whalescan`` logger. Idempotent: replaces handlers it previously added."""
    logger = logging.getLogger(ROOT_LOGGER)
    for h in list(logger.handlers):
        if getattr(h, "_whalescan", False):
            logger.removeHandler(h)
    logger.setLevel(LEVELS.get(level, logging.WARNING))
    logger.propagate = False
    formatter: logging.Formatter = (
        JsonFormatter() if fmt == "json" else logging.Formatter("whalescan: %(levelname)s: %(message)s")
    )
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if file:
        handlers.append(RotatingFileHandler(file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"))
    for h in handlers:
        h.setFormatter(formatter)
        if redactor is not None:
            h.addFilter(RedactingFilter(redactor))
        h._whalescan = True  # type: ignore[attr-defined]
        logger.addHandler(h)
    return logger
