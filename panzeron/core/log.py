"""Structured (JSON lines) logging to stderr and a rotating file."""
from __future__ import annotations

import json
import logging
import logging.handlers
from pathlib import Path


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {"ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"), "level": record.levelname,
               "logger": record.name, "msg": record.getMessage()}
        extra = getattr(record, "ctx", None)
        if extra:
            out["ctx"] = extra
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out, default=str)


def setup_logging(log_dir: Path | None = None, level: int = logging.INFO) -> logging.Logger:
    root = logging.getLogger("panzeron")
    if root.handlers:
        return root
    root.setLevel(level)
    import sys
    if sys.stderr is not None:  # windowed (no-console) builds have no stderr
        sh = logging.StreamHandler()
        sh.setFormatter(JsonFormatter())
        root.addHandler(sh)
    if log_dir:
        fh = logging.handlers.RotatingFileHandler(Path(log_dir) / "panzeron.log", maxBytes=1_000_000, backupCount=3)
        fh.setFormatter(JsonFormatter())
        root.addHandler(fh)
    return root


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"panzeron.{name}")
