"""Quarantine Engine for ITShield.

Section 15 of the architecture document.

A file flagged as MALICIOUS is moved to a dedicated quarantine directory
with restrictive permissions and a metadata record in the ``quarantine``
SQLite table. The original path, SHA-256, size and timestamp are recorded
so the file can be:

    * listed   - :meth:`QuarantineEngine.list_quarantined`
    * restored - :meth:`QuarantineEngine.restore`  (only with explicit
                  confirmation; restoration writes to a user-chosen path
                  and re-hashes the file to confirm integrity)
    * deleted  - :meth:`QuarantineEngine.delete_permanent`

Security considerations (section 19 of the document):
    * The quarantine directory is created with mode 0700.
    * Files inside are stored with mode 0400 (read-only, no exec).
    * The original file path is recorded but the file is moved with
      ``os.replace`` (atomic on the same filesystem) and then ``chmod``'d
      so it cannot be executed by accident.
    * Restoration writes the file back with mode 0600 and requires the
      SHA-256 of the quarantined copy to match the recorded one.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from itshield.logging.logger import get_logger
from itshield.storage.database import Database

logger = get_logger(__name__)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class QuarantineEntry:
    """A quarantined file record."""

    quarantine_id: str
    original_path: str
    quarantined_path: str
    sha256: str
    size: int
    reason: str
    quarantined_at: str
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        return data


class QuarantineEngine:
    """Move malicious files to a safe location and track them."""

    def __init__(
        self,
        db: Database,
        quarantine_dir: Optional[str | Path] = None,
    ) -> None:
        self._db = db
        if quarantine_dir is None:
            from itshield.config.settings import get_settings
            settings = get_settings()
            quarantine_dir = settings.data_dir / "quarantine"
        self.quarantine_dir = Path(quarantine_dir).resolve()
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.quarantine_dir, stat.S_IRWXU)
        except OSError as exc:
            logger.warning("Could not chmod quarantine dir %s: %s",
                           self.quarantine_dir, exc)

    def quarantine(
        self,
        file_path: str | Path,
        sha256: str,
        reason: str,
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> QuarantineEntry:
        """Move ``file_path`` into the quarantine directory.

        Returns the :class:`QuarantineEntry` recording the operation.
        Raises ``FileNotFoundError`` if the file is missing and
        ``IsADirectoryError`` if it is not a regular file.
        """
        src = Path(file_path)
        if src.is_symlink():
            raise ValueError(
                f"Refusing to quarantine a symlink: {src} "
                "(potential TOCTOU / path traversal attack)"
            )
        try:
            fd = os.open(str(src), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as exc:
            if exc.errno == 40:  # ELOOP = symlink
                raise ValueError(f"Refusing to quarantine a symlink: {src}")
            raise FileNotFoundError(f"Cannot open file for quarantine: {src}: {exc}")
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise IsADirectoryError(f"Not a regular file: {src}")
            size = st.st_size
        finally:
            os.close(fd)

        quarantine_id = str(uuid.uuid4())
        dest = self.quarantine_dir / f"{quarantine_id}.bin"
        meta = dict(extra_metadata or {})
        meta["original_name"] = src.name

        dest_fd = os.open(
            str(dest),
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            stat.S_IRUSR,  # 0400 - read-only, no execute
        )
        os.close(dest_fd)

        try:
            os.replace(src, dest)
        except OSError:
            logger.debug("Cross-device move; falling back to copy+delete for %s", src)
            shutil.copyfile(src, dest)
            os.chmod(dest, stat.S_IRUSR)
            src.unlink()

        try:
            os.chmod(dest, stat.S_IRUSR)
        except OSError as exc:
            logger.warning("Could not chmod quarantined file %s: %s", dest, exc)

        actual_sha = self._hash_file(dest)
        integrity_ok = (actual_sha == sha256.lower())
        if not integrity_ok:
            logger.warning(
                "Quarantine integrity mismatch for %s: expected=%s actual=%s",
                src, sha256, actual_sha,
            )
            meta["integrity_mismatch"] = True
            meta["actual_sha256"] = actual_sha

        entry = QuarantineEntry(
            quarantine_id=quarantine_id,
            original_path=str(src.resolve()),
            quarantined_path=str(dest),
            sha256=sha256.lower(),
            size=size,
            reason=reason,
            quarantined_at=_utcnow(),
            metadata=meta,
        )

        import json
        self._db.execute(
            """
            INSERT INTO quarantine
                (quarantined_at, original_path, sha256, size, metadata)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                entry.quarantined_at,
                entry.original_path,
                entry.sha256,
                entry.size,
                json.dumps(entry.metadata),
            ),
        )

        meta["quarantine_id"] = quarantine_id
        meta["quarantined_path"] = str(dest)
        self._db.execute(
            "UPDATE quarantine SET metadata=? WHERE rowid=last_insert_rowid()",
            (json.dumps(meta),),
        )

        logger.info(
            "Quarantined %s -> %s (id=%s, sha256=%s, size=%d, integrity_ok=%s)",
            src, dest, quarantine_id, sha256[:12], size, integrity_ok,
        )
        return entry

    def list_quarantined(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return all quarantined entries, most-recent first."""
        import json
        rows = self._db.fetchall(
            "SELECT rowid AS id, quarantined_at, original_path, sha256, size, metadata "
            "FROM quarantine ORDER BY quarantined_at DESC LIMIT ?",
            (limit,),
        )
        result = []
        for r in rows:
            item = dict(r)
            try:
                item["metadata"] = json.loads(item["metadata"]) if item["metadata"] else {}
            except (TypeError, ValueError):
                item["metadata"] = {}
            result.append(item)
        return result

    def get_entry(self, row_id: int) -> Optional[Dict[str, Any]]:
        """Return details for a single quarantined entry by row id."""
        import json
        row = self._db.fetchone(
            "SELECT rowid AS id, quarantined_at, original_path, sha256, size, metadata "
            "FROM quarantine WHERE rowid=?",
            (row_id,),
        )
        if not row:
            return None
        item = dict(row)
        try:
            item["metadata"] = json.loads(item["metadata"]) if item["metadata"] else {}
        except (TypeError, ValueError):
            item["metadata"] = {}
        return item

    _FORBIDDEN_RESTORE_PATHS = (
        "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64",
        "/boot", "/proc", "/sys", "/dev",
        "C:\\Windows", "C:\\Program Files", "C:\\System32",
    )

    def restore(self, row_id: int, target_path: str | Path) -> Dict[str, Any]:
        """Restore a quarantined file to ``target_path``.

        Re-hashes the quarantined copy and refuses to restore if the
        SHA-256 doesn't match the recorded one (tamper detection).
        Also refuses to restore to system directories (path traversal
        protection) and verifies the quarantined_path is inside the
        quarantine directory (DB tampering protection).
        """
        entry = self.get_entry(row_id)
        if entry is None:
            raise ValueError(f"No quarantined entry with id {row_id}")

        src_path = entry["metadata"].get("quarantined_path")
        if not src_path:
            raise FileNotFoundError("Quarantined file path missing from metadata")

        src_resolved = Path(src_path).resolve()
        qdir_resolved = self.quarantine_dir.resolve()
        try:
            src_resolved.relative_to(qdir_resolved)
        except ValueError:
            raise ValueError(
                f"Security violation: quarantined_path {src_path} is outside "
                f"the quarantine directory {qdir_resolved}. Possible DB tampering."
            )

        if not src_resolved.exists():
            raise FileNotFoundError(f"Quarantined file missing on disk: {src_path}")

        actual_sha = self._hash_file(src_resolved)
        if actual_sha != entry["sha256"]:
            raise RuntimeError(
                f"Integrity check failed: quarantined file sha256={actual_sha} "
                f"does not match recorded sha256={entry['sha256']}. Refusing to restore."
            )

        target = Path(target_path).expanduser().resolve()
        target_str = str(target)
        for forbidden in self._FORBIDDEN_RESTORE_PATHS:
            if target_str.startswith(forbidden):
                raise ValueError(
                    f"Security violation: refusing to restore to system path {target} "
                    f"(matches forbidden prefix {forbidden})"
                )
        if target.exists():
            raise ValueError(
                f"Target file already exists: {target}. "
                "Remove it first or choose a different path."
            )

        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src_resolved, target)
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)

        import json
        self._db.execute(
            "INSERT INTO audit_logs (timestamp, actor, action, target, details) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                _utcnow(),
                os.environ.get("USER", "unknown"),
                "quarantine.restore",
                str(target),
                json.dumps({"row_id": row_id, "original_path": entry["original_path"]}),
            ),
        )

        logger.info("Restored quarantined id=%d to %s", row_id, target)
        return {
            "row_id": row_id,
            "restored_to": str(target),
            "original_path": entry["original_path"],
            "sha256": entry["sha256"],
        }

    def delete_permanent(self, row_id: int) -> Dict[str, Any]:
        """Permanently delete a quarantined file and its metadata."""
        entry = self.get_entry(row_id)
        if entry is None:
            raise ValueError(f"No quarantined entry with id {row_id}")

        src_path = entry["metadata"].get("quarantined_path")
        if src_path and Path(src_path).exists():
            try:
                self._secure_delete(Path(src_path))
            except OSError as exc:
                logger.warning("Secure delete failed for %s: %s", src_path, exc)
                Path(src_path).unlink(missing_ok=True)

        self._db.execute("DELETE FROM quarantine WHERE rowid=?", (row_id,))

        import json
        self._db.execute(
            "INSERT INTO audit_logs (timestamp, actor, action, target, details) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                _utcnow(),
                os.environ.get("USER", "unknown"),
                "quarantine.delete",
                entry["original_path"],
                json.dumps({"row_id": row_id, "sha256": entry["sha256"]}),
            ),
        )

        logger.info("Permanently deleted quarantined id=%d", row_id)
        return {"row_id": row_id, "deleted": True}

    @staticmethod
    def _hash_file(path, chunk_size: int = 1024 * 1024) -> str:
        """Hash a file given a str or Path; converts internally."""
        p = Path(path) if not isinstance(path, Path) else path
        h = hashlib.sha256()
        with p.open("rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _secure_delete(path: Path, passes: int = 1) -> None:
        """Overwrite ``path`` with random bytes then unlink.

        Note: on modern SSDs and copy-on-write filesystems this is not a
        strong guarantee; the goal here is to prevent trivial recovery.
        """
        size = path.stat().st_size
        with path.open("r+b") as fh:
            for _ in range(passes):
                fh.seek(0)
                fh.write(os.urandom(size))
                fh.flush()
                os.fsync(fh.fileno())
        path.unlink()
