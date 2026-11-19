"""Unit tests for itshield.quarantine.engine.QuarantineEngine."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from itshield.storage.database import Database
from itshield.storage.migrations import run_migrations
from itshield.quarantine.engine import QuarantineEngine


@pytest.fixture
def qengine(tmp_project: Path) -> QuarantineEngine:
    db_path = tmp_project / "data" / "qtest.db"
    db = Database(db_path)
    run_migrations(db)
    qdir = tmp_project / "quarantine"
    yield QuarantineEngine(db=db, quarantine_dir=qdir)
    db.close()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_quarantine_moves_file_and_records(qengine: QuarantineEngine,
                                            tmp_project: Path) -> None:
    src = tmp_project / "malware.bin"
    payload = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    src.write_bytes(payload)
    sha = _sha256(payload)

    entry = qengine.quarantine(file_path=src, sha256=sha, reason="test signature match")
    assert entry.sha256 == sha
    assert entry.original_path == str(src.resolve())
    assert not src.exists()                      # file was moved away
    assert Path(entry.quarantined_path).exists() # ...and into quarantine
    assert entry.size == len(payload)

    listed = qengine.list_quarantined()
    assert len(listed) == 1
    assert listed[0]["sha256"] == sha


def test_quarantine_missing_file_raises(qengine: QuarantineEngine,
                                         tmp_project: Path) -> None:
    with pytest.raises(FileNotFoundError):
        qengine.quarantine(tmp_project / "nope.bin", "0" * 64, "missing")


def test_quarantine_directory_raises(qengine: QuarantineEngine,
                                      tmp_project: Path) -> None:
    with pytest.raises(IsADirectoryError):
        qengine.quarantine(tmp_project, "0" * 64, "is dir")


def test_restore_writes_to_target(qengine: QuarantineEngine,
                                   tmp_project: Path) -> None:
    src = tmp_project / "evil.txt"
    payload = b"evil content"
    src.write_bytes(payload)
    sha = _sha256(payload)

    qengine.quarantine(file_path=src, sha256=sha, reason="test")
    entries = qengine.list_quarantined()
    row_id = entries[0]["id"]

    target = tmp_project / "restored.txt"
    result = qengine.restore(row_id, target)
    assert target.exists()
    assert target.read_bytes() == payload
    assert result["restored_to"] == str(target.resolve())


def test_restore_refuses_on_integrity_mismatch(qengine: QuarantineEngine,
                                                tmp_project: Path) -> None:
    """Tamper with the quarantined file -> restore must raise."""
    src = tmp_project / "evil2.txt"
    payload = b"original"
    src.write_bytes(payload)
    sha = _sha256(payload)
    qengine.quarantine(file_path=src, sha256=sha, reason="test")

    entries = qengine.list_quarantined()
    row_id = entries[0]["id"]
    qpath = entries[0]["metadata"]["quarantined_path"]
    import os as _os, stat as _stat
    _os.chmod(qpath, _stat.S_IRUSR | _stat.S_IWUSR)
    Path(qpath).write_bytes(b"TAMPERED")

    with pytest.raises(RuntimeError, match="Integrity check failed"):
        qengine.restore(row_id, tmp_project / "out.txt")


def test_delete_permanent_removes_file_and_row(qengine: QuarantineEngine,
                                                 tmp_project: Path) -> None:
    src = tmp_project / "deleteme.bin"
    payload = b"doomed"
    src.write_bytes(payload)
    sha = _sha256(payload)
    qengine.quarantine(file_path=src, sha256=sha, reason="test")
    entries = qengine.list_quarantined()
    row_id = entries[0]["id"]
    qpath = entries[0]["metadata"]["quarantined_path"]

    result = qengine.delete_permanent(row_id)
    assert result["deleted"] is True
    assert not Path(qpath).exists()
    assert qengine.get_entry(row_id) is None
