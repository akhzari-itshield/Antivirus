"""ScanReportStore - persistence layer for scan jobs and per-file results.

Section 12 of the architecture document notes that this store currently lives
independently of the main Storage Layer; the long-term goal is to fold it
into a unified :class:`IStorageRepository`. The class here is the first
concrete implementation of that repository for the scanner domain.

Every public method is transactional and thread-safe through the underlying
:class:`Database` lock.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from itshield.logging.logger import get_logger
from itshield.storage.database import Database

logger = get_logger(__name__)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class ScanReportStore:
    """CRUD operations for scan jobs and their results."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def create_job(self, target_path: str) -> str:
        """Insert a new scan job in PENDING state and return its id."""
        job_id = str(uuid.uuid4())
        self._db.execute(
            """
            INSERT INTO scan_jobs (id, target_path, state, started_at)
            VALUES (?, ?, 'PENDING', ?)
            """,
            (job_id, str(target_path), _utcnow()),
        )
        logger.info("Created scan job %s for %s", job_id, target_path)
        return job_id

    def mark_job_running(self, job_id: str) -> None:
        self._db.execute(
            "UPDATE scan_jobs SET state='RUNNING' WHERE id=?", (job_id,)
        )

    def mark_job_completed(self, job_id: str, error: Optional[str] = None) -> None:
        state = "FAILED" if error else "COMPLETED"
        self._db.execute(
            "UPDATE scan_jobs SET state=?, finished_at=?, error=? WHERE id=?",
            (state, _utcnow(), error, job_id),
        )

    def mark_job_cancelled(self, job_id: str) -> None:
        self._db.execute(
            "UPDATE scan_jobs SET state='CANCELLED', finished_at=? WHERE id=?",
            (_utcnow(), job_id),
        )

    def update_job_counts(
        self,
        job_id: str,
        files_total: int,
        files_scanned: int,
        files_malicious: int,
        files_suspicious: int,
        files_clean: int,
        files_unknown: int,
        files_skipped: int,
    ) -> None:
        self._db.execute(
            """
            UPDATE scan_jobs
            SET files_total=?, files_scanned=?, files_malicious=?,
                files_suspicious=?, files_clean=?, files_unknown=?, files_skipped=?
            WHERE id=?
            """,
            (
                files_total,
                files_scanned,
                files_malicious,
                files_suspicious,
                files_clean,
                files_unknown,
                files_skipped,
                job_id,
            ),
        )

    def add_result(
        self,
        job_id: str,
        file_path: str,
        file_size: Optional[int],
        file_type: Optional[str],
        sha256: Optional[str],
        detection: str,
        matched_rules: Optional[List[str]],
        reason: Optional[str],
    ) -> None:
        self._db.execute(
            """
            INSERT INTO scan_results
                (job_id, file_path, file_size, file_type, sha256,
                 detection, matched_rules, reason, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job_id,
                str(file_path),
                file_size,
                file_type,
                sha256,
                detection,
                ",".join(matched_rules) if matched_rules else None,
                reason,
                _utcnow(),
            ),
        )

    def list_jobs(self, limit: int = 50) -> List[Dict[str, Any]]:
        rows = self._db.fetchall(
            "SELECT * FROM scan_jobs ORDER BY started_at DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in rows]

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        row = self._db.fetchone(
            "SELECT * FROM scan_jobs WHERE id=?", (job_id,)
        )
        return dict(row) if row else None

    def get_results(self, job_id: str) -> List[Dict[str, Any]]:
        rows = self._db.fetchall(
            "SELECT * FROM scan_results WHERE job_id=? ORDER BY id ASC",
            (job_id,),
        )
        return [dict(r) for r in rows]

    def get_results_by_detection(
        self, job_id: str, detection: str
    ) -> List[Dict[str, Any]]:
        rows = self._db.fetchall(
            "SELECT * FROM scan_results WHERE job_id=? AND detection=?",
            (job_id, detection),
        )
        return [dict(r) for r in rows]

    def delete_job(self, job_id: str) -> int:
        cur = self._db.execute(
            "DELETE FROM scan_jobs WHERE id=?", (job_id,)
        )
        return cur.rowcount
