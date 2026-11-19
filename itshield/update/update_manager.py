"""Update Manager - orchestrates signature bank updates with rollback (Phase 8).

Section 18 of the architecture document.

Workflow:
    1. ``check_for_updates(source)`` reads a candidate bank from a source
       (local file or directory; HTTP is stubbed) and returns an
       :class:`UpdateInfo` describing the new version + verification status.
    2. ``apply_update(info)`` validates the candidate, backs up the
       current bank, atomically swaps the files, and records the
       operation in ``update_history``.
    3. ``rollback()`` restores the most recent backup if the new bank
       turns out to be broken.

The manager is intentionally paranoid: every step is logged, every
failure leaves the system in a consistent state, and the previous bank
is never deleted until the new one has been verified in place.
"""

from __future__ import annotations

import json
import shutil
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from itshield.logging.logger import get_logger
from itshield.storage.database import Database
from itshield.update.verifier import (
    SignatureVerifier,
    VerificationResult,
    VerificationStatus,
)

logger = get_logger(__name__)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class UpdateInfo:
    """Describes a candidate update discovered by ``check_for_updates``."""

    source_path: str
    new_version: Optional[int]
    new_signature_count: int
    new_sha256: str
    current_version: Optional[int]
    current_signature_count: int
    current_sha256: str
    verification: VerificationResult

    @property
    def has_update(self) -> bool:
        """True if the new version is strictly greater than the current."""
        if self.verification.status != VerificationStatus.OK:
            return False
        if self.new_version is None:
            return False
        if self.current_version is None:
            return True
        return self.new_version > self.current_version

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["verification"] = self.verification.to_dict()
        d["has_update"] = self.has_update
        return d


@dataclass
class UpdateResult:
    """Outcome of an apply_update or rollback operation."""

    success: bool
    component: str
    from_version: Optional[int]
    to_version: Optional[int]
    status: str
    details: str = ""
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class UpdateSource:
    """Abstract source of candidate updates."""

    def discover(self) -> List[Path]:
        """Return a list of candidate bank paths."""
        raise NotImplementedError

    def fetch(self, candidate: Path) -> Path:
        """Fetch the candidate to a local path (default: already local)."""
        return candidate


class LocalUpdateSource(UpdateSource):
    """Reads candidate banks from a local directory.

    A candidate is any ``*.json`` file in ``directory`` whose first
    ``version`` field is an integer greater than the current bank's.
    """

    def __init__(self, directory: str | Path, pattern: str = "*.json") -> None:
        self.directory = Path(directory)
        self.pattern = pattern

    def discover(self) -> List[Path]:
        if not self.directory.exists():
            return []
        candidates = sorted(self.directory.glob(self.pattern))
        return [c for c in candidates if c.is_file()]

    def fetch(self, candidate: Path) -> Path:
        return candidate


class UpdateManager:
    """Coordinates the verify → backup → swap → record → rollback flow."""

    COMPONENT = "signature_bank"

    def __init__(
        self,
        db: Database,
        current_bank_path: str | Path,
        backup_dir: str | Path,
        verifier: Optional[SignatureVerifier] = None,
    ) -> None:
        self._db = db
        self.current_bank_path = Path(current_bank_path)
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.verifier = verifier or SignatureVerifier()

    def check_for_updates(
        self,
        source: UpdateSource,
        expected_sha256: Optional[str] = None,
    ) -> List[UpdateInfo]:
        """Discover and verify every candidate from ``source``."""
        candidates = source.discover()
        results: List[UpdateInfo] = []
        current_version, current_count, current_sha = self._read_current_bank()

        for cand in candidates:
            fetched = source.fetch(cand)
            verification = self.verifier.verify_bank_file(fetched, expected_sha256)
            new_version = verification.bank_version
            new_count = verification.signature_count
            try:
                new_sha = self.verifier.hash_file(fetched)
            except Exception:
                new_sha = ""

            results.append(UpdateInfo(
                source_path=str(fetched),
                new_version=new_version,
                new_signature_count=new_count,
                new_sha256=new_sha,
                current_version=current_version,
                current_signature_count=current_count,
                current_sha256=current_sha,
                verification=verification,
            ))
        return results

    def latest_update(self, source: UpdateSource) -> Optional[UpdateInfo]:
        """Return the highest-version candidate that passed verification."""
        candidates = self.check_for_updates(source)
        if not candidates:
            return None
        verified = [c for c in candidates if c.verification.ok]
        if not verified:
            return candidates[0]
        verified.sort(key=lambda c: c.new_version or 0, reverse=True)
        return verified[0]

    def apply_update(
        self,
        info: UpdateInfo,
        expected_sha256: Optional[str] = None,
    ) -> UpdateResult:
        """Apply a single :class:`UpdateInfo`.

        Steps (all logged, all atomic-ish):
            1. Re-verify the candidate file (paranoia).
            2. Back up the current bank to ``backup_dir/<timestamp>.json``.
            3. Copy the candidate over the current bank.
            4. Re-verify the now-installed bank.
            5. Record the operation in ``update_history``.

        If any step fails, ``rollback()`` is called automatically and
        the failure is reported.
        """
        timestamp = _utcnow()
        candidate = Path(info.source_path)
        if not candidate.exists():
            return self._record_failure(
                info, timestamp, "candidate file disappeared",
            )

        re_verify = self.verifier.verify_bank_file(candidate, expected_sha256)
        if not re_verify.ok:
            return self._record_failure(
                info, timestamp,
                f"candidate verification failed: {re_verify.status.value}",
            )

        backup_path: Optional[Path] = None
        if self.current_bank_path.exists():
            backup_path = self.backup_dir / f"bank_backup_{int(time.time())}.json"
            try:
                shutil.copy2(self.current_bank_path, backup_path)
                logger.info("Backed up current bank to %s", backup_path)
            except OSError as exc:
                return self._record_failure(
                    info, timestamp, f"backup failed: {exc}",
                )

        try:
            shutil.copy2(candidate, self.current_bank_path)
        except OSError as exc:
            if backup_path is not None and backup_path.exists():
                shutil.copy2(backup_path, self.current_bank_path)
            return self._record_failure(
                info, timestamp, f"swap failed: {exc}",
            )

        in_place = self.verifier.verify_bank_file(self.current_bank_path)
        if not in_place.ok:
            if backup_path is not None and backup_path.exists():
                shutil.copy2(backup_path, self.current_bank_path)
                logger.warning("Rolled back due to in-place verification failure")
            return self._record_failure(
                info, timestamp,
                f"in-place verification failed: {in_place.status.value}",
            )

        result = UpdateResult(
            success=True,
            component=self.COMPONENT,
            from_version=info.current_version,
            to_version=info.new_version,
            status="APPLIED",
            details=f"verified sha256={in_place.actual_sha256[:12]}.., "
                    f"{in_place.signature_count} signatures",
            timestamp=timestamp,
        )
        self._record_history(result)
        logger.info(
            "Update applied: v%s -> v%s (%d signatures)",
            info.current_version, info.new_version, in_place.signature_count,
        )
        return result

    def rollback(self) -> UpdateResult:
        """Restore the most recent backup."""
        backups = sorted(
            self.backup_dir.glob("bank_backup_*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        timestamp = _utcnow()
        if not backups:
            return UpdateResult(
                success=False,
                component=self.COMPONENT,
                from_version=None,
                to_version=None,
                status="NO_BACKUP",
                details="no backup files found in backup_dir",
                timestamp=timestamp,
            )
        latest = backups[0]
        try:
            shutil.copy2(latest, self.current_bank_path)
        except OSError as exc:
            return UpdateResult(
                success=False,
                component=self.COMPONENT,
                from_version=None,
                to_version=None,
                status="ROLLBACK_FAILED",
                details=f"could not restore backup: {exc}",
                timestamp=timestamp,
            )
        re_verify = self.verifier.verify_bank_file(self.current_bank_path)
        result = UpdateResult(
            success=True,
            component=self.COMPONENT,
            from_version=None,
            to_version=re_verify.bank_version,
            status="ROLLED_BACK",
            details=f"restored from {latest.name}",
            timestamp=timestamp,
        )
        self._record_history(result)
        logger.info("Rolled back to %s (v%s)", latest.name, re_verify.bank_version)
        return result

    def list_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        rows = self._db.fetchall(
            "SELECT applied_at, component, from_version, to_version, status, details "
            "FROM update_history ORDER BY applied_at DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in rows]

    def _read_current_bank(self) -> tuple[Optional[int], int, str]:
        """Return (version, signature_count, sha256) of the current bank."""
        if not self.current_bank_path.exists():
            return None, 0, ""
        try:
            data = json.loads(self.current_bank_path.read_text(encoding="utf-8"))
            version = data.get("version")
            count = len(data.get("signatures") or [])
        except (json.JSONDecodeError, OSError):
            return None, 0, ""
        try:
            sha = self.verifier.hash_file(self.current_bank_path)
        except Exception:
            sha = ""
        return version, count, sha

    def _record_failure(self, info: UpdateInfo, timestamp: str, detail: str) -> UpdateResult:
        result = UpdateResult(
            success=False,
            component=self.COMPONENT,
            from_version=info.current_version,
            to_version=info.new_version,
            status="FAILED",
            details=detail,
            timestamp=timestamp,
        )
        self._record_history(result)
        logger.error("Update failed: %s", detail)
        return result

    def _record_history(self, result: UpdateResult) -> None:
        try:
            self._db.execute(
                """
                INSERT INTO update_history
                    (applied_at, component, from_version, to_version, status, details)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    result.timestamp,
                    result.component,
                    str(result.from_version) if result.from_version is not None else None,
                    str(result.to_version) if result.to_version is not None else None,
                    result.status,
                    result.details,
                ),
            )
        except Exception:
            logger.exception("Could not record update_history row")
