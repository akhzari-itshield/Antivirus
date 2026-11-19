"""SQLite wrapper for ITShield.

A thin thread-safe wrapper around :mod:`sqlite3` that:
    * opens a single connection per Database instance
    * enables WAL mode and reasonable PRAGMAs for an antivirus workload
    * exposes ``execute``, ``executemany`` and ``fetchone/all`` helpers
    * serves as the single entry point Storage Layer modules use

Section 12 of the architecture document names SQLite as the chosen store
for the first version. The Repository Pattern is sketched but not enforced;
:mod:`itshield.storage.migrations` owns schema creation.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence, Union

from itshield.logging.logger import get_logger

logger = get_logger(__name__)

Params = Union[Sequence[Any], dict]


class Database:
    """Thread-safe wrapper around a single sqlite3 connection.

    The connection is opened with ``check_same_thread=False`` and guarded by
    a reentrant lock so IPC handlers running on different threads can use it
    safely. ``WAL`` journal mode is enabled which is the right default for a
    long-running service that mixes reads and writes.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self.path),
            check_same_thread=False,
            isolation_level=None,  # autocommit; we manage transactions explicitly
            timeout=30.0,
        )
        self._conn.row_factory = sqlite3.Row
        self._apply_pragmas()

    def _apply_pragmas(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA synchronous=NORMAL;")
            cur.execute("PRAGMA foreign_keys=ON;")
            cur.execute("PRAGMA temp_store=MEMORY;")
            cur.close()

    def execute(self, sql: str, params: Params = ()) -> sqlite3.Cursor:
        with self._lock:
            try:
                cur = self._conn.execute(sql, params)
                return cur
            except sqlite3.Error:
                logger.exception("SQLite execute failed: %s", sql)
                raise

    def executemany(
        self, sql: str, params_seq: Iterable[Params]
    ) -> sqlite3.Cursor:
        with self._lock:
            try:
                return self._conn.executemany(sql, params_seq)
            except sqlite3.Error:
                logger.exception("SQLite executemany failed: %s", sql)
                raise

    def fetchone(self, sql: str, params: Params = ()) -> Optional[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def fetchall(self, sql: str, params: Params = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def executescript(self, script: str) -> None:
        """Execute a multi-statement SQL script (used for migrations)."""
        with self._lock:
            self._conn.executescript(script)

    def transaction(self) -> "_Transaction":
        """Context manager wrapping BEGIN/COMMIT/ROLLBACK."""
        return _Transaction(self)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class _Transaction:
    """Manual transaction context manager (autocommit mode)."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def __enter__(self) -> "_Transaction":
        self._db.execute("BEGIN")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is None:
            self._db.execute("COMMIT")
        else:
            self._db.execute("ROLLBACK")
