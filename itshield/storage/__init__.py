"""Storage package for ITShield."""

from itshield.storage.database import Database
from itshield.storage.migrations import run_migrations

__all__ = ["Database", "run_migrations"]
