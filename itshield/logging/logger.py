"""Logging bootstrap for ITShield.

Provides a single ``get_logger(name)`` factory that every module uses so
log format and level stay consistent across the codebase.
"""

from __future__ import annotations

import logging
from typing import Optional

from itshield.config.settings import get_settings

_initialized: bool = False


def init_logging(level: Optional[str] = None) -> None:
    """Configure root logger once. Safe to call multiple times."""
    global _initialized
    if _initialized:
        return

    settings = get_settings()
    logging.basicConfig(
        level=level or settings.log_level,
        format=settings.log_format,
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    _initialized = True


def get_logger(name: str) -> logging.Logger:
    """Return a logger; initialize root config on first call."""
    if not _initialized:
        init_logging()
    return logging.getLogger(name)
