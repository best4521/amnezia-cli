"""Central logging configuration.

Two sinks:

* A rotating file handler (``config.log_path``) at ``INFO`` — the durable operational
  record, complements the ``audit_log`` DB table.
* A console (stderr) handler at ``WARNING`` by default, or ``DEBUG`` with ``--verbose``.

All modules log through ``logging.getLogger("amnezia_cli")`` or a child of it.
"""
from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

LOGGER_NAME = "amnezia_cli"

_FILE_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
_CONSOLE_FORMAT = "%(levelname)s: %(message)s"

_configured = False


def configure_logging(
    log_path: str,
    *,
    verbose: bool = False,
    max_bytes: int = 2_000_000,
    backup_count: int = 3,
) -> logging.Logger:
    """Configure and return the package logger. Safe to call more than once."""
    global _configured
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG)

    if _configured:
        # Only adjust console verbosity on repeat calls.
        for handler in logger.handlers:
            if getattr(handler, "_amnezia_console", False):
                handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
        return logger

    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console.setFormatter(logging.Formatter(_CONSOLE_FORMAT))
    console._amnezia_console = True  # type: ignore[attr-defined]
    logger.addHandler(console)

    try:
        Path(log_path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            Path(log_path).expanduser(),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(logging.Formatter(_FILE_FORMAT))
        logger.addHandler(file_handler)
    except OSError as exc:  # pragma: no cover - unusual FS permission issue
        logger.warning("file logging disabled: cannot open %s (%s)", log_path, exc)

    _configured = True
    return logger


def get_logger(suffix: str | None = None) -> logging.Logger:
    """Return the package logger, or a named child of it."""
    return logging.getLogger(LOGGER_NAME if not suffix else f"{LOGGER_NAME}.{suffix}")
