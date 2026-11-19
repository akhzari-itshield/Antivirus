"""Unit tests for itshield.update.* (Phase 8)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from itshield.storage.database import Database
from itshield.storage.migrations import run_migrations
from itshield.update.verifier import (
    SignatureVerifier,
    VerificationStatus,
)
from itshield.update.update_manager import (
    UpdateManager,
    LocalUpdateSource,
)


@pytest.fixture
def db(tmp_project: Path) -> Database:
    database = Database(tmp_project / "data" / "upd.db")
    run_migrations(database)
    yield database
    database.close()


@pytest.fixture
def bank_dir(tmp_project: Path) -> Path:
    d = tmp_project / "banks"
    d.mkdir()
    return d


@pytest.fixture
def current_bank(tmp_project: Path) -> Path:
    """Write a v1 bank at signatures/hashes.json (already created by conftest)."""
    p = tmp_project / "signatures" / "hashes.json"
    if p.exists():
        return p
    p.write_text(json.dumps({
        "version": 1,
        "generated_at": "2026-01-01T00:00:00Z",
        "signatures": [
            {"sha256": "a" * 64, "name": "TestSig"},
        ],
    }))
    return p


@pytest.fixture
def backup_dir(tmp_project: Path) -> Path:
    d = tmp_project / "backups"
    d.mkdir()
    return d


def _make_bank(path: Path, version: int, count: int = 3) -> str:
    """Write a signature bank file with the given version and return its sha256."""
    data = {
        "version": version,
        "generated_at": "2026-01-01T00:00:00Z",
        "signatures": [
            {"sha256": f"{i:064x}", "name": f"sig_{i}"} for i in range(count)
        ],
    }
    path.write_text(json.dumps(data))
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_verifier_hash_bytes() -> None:
    v = SignatureVerifier()
    import hashlib
    assert v.hash_bytes(b"hello") == hashlib.sha256(b"hello").hexdigest()


def test_verifier_hash_file(tmp_project: Path) -> None:
    v = SignatureVerifier()
    p = tmp_project / "f.bin"
    p.write_bytes(b"data")
    import hashlib
    assert v.hash_file(p) == hashlib.sha256(b"data").hexdigest()


def test_verifier_verify_file_ok(tmp_project: Path) -> None:
    v = SignatureVerifier()
    p = tmp_project / "f.bin"
    p.write_bytes(b"data")
    import hashlib
    expected = hashlib.sha256(b"data").hexdigest()
    result = v.verify_file(p, expected)
    assert result.ok
    assert result.status == VerificationStatus.OK


def test_verifier_verify_file_mismatch(tmp_project: Path) -> None:
    v = SignatureVerifier()
    p = tmp_project / "f.bin"
    p.write_bytes(b"data")
    result = v.verify_file(p, "0" * 64)
    assert result.status == VerificationStatus.HASH_MISMATCH
    assert not result.ok


def test_verifier_missing_file(tmp_project: Path) -> None:
    v = SignatureVerifier()
    result = v.verify_file(tmp_project / "missing.bin", "0" * 64)
    assert result.status == VerificationStatus.FILE_NOT_FOUND


def test_verifier_validate_schema_ok() -> None:
    v = SignatureVerifier()
    result = v.validate_schema({
        "version": 1,
        "generated_at": "2026",
        "signatures": [{"sha256": "x" * 64, "name": "n"}],
    })
    assert result.ok
    assert result.bank_version == 1
    assert result.signature_count == 1


def test_verifier_validate_schema_missing_field() -> None:
    v = SignatureVerifier()
    result = v.validate_schema({"version": 1})
    assert result.status == VerificationStatus.SCHEMA_ERROR


def test_verifier_validate_schema_signatures_not_list() -> None:
    v = SignatureVerifier()
    result = v.validate_schema({
        "version": 1, "generated_at": "x", "signatures": "not a list",
    })
    assert result.status == VerificationStatus.SCHEMA_ERROR


def test_verifier_verify_bank_file_ok(tmp_project: Path) -> None:
    v = SignatureVerifier()
    p = tmp_project / "bank.json"
    p.write_text(json.dumps({
        "version": 2,
        "generated_at": "2026",
        "signatures": [{"sha256": "a" * 64, "name": "x"}],
    }))
    import hashlib
    expected = hashlib.sha256(p.read_bytes()).hexdigest()
    result = v.verify_bank_file(p, expected)
    assert result.ok
    assert result.bank_version == 2
    assert result.signature_count == 1


def test_verifier_verify_bank_file_bad_json(tmp_project: Path) -> None:
    v = SignatureVerifier()
    p = tmp_project / "bank.json"
    p.write_text("not json")
    result = v.verify_bank_file(p)
    assert result.status == VerificationStatus.PARSE_ERROR


def test_local_source_discovers_files(bank_dir: Path) -> None:
    _make_bank(bank_dir / "v1.json", 1)
    _make_bank(bank_dir / "v2.json", 2)
    src = LocalUpdateSource(directory=bank_dir)
    candidates = src.discover()
    assert len(candidates) == 2


def test_local_source_missing_dir(tmp_project: Path) -> None:
    src = LocalUpdateSource(directory=tmp_project / "nope")
    assert src.discover() == []


def test_check_for_updates_finds_higher_version(
    db: Database, current_bank: Path, backup_dir: Path, bank_dir: Path,
) -> None:
    _make_bank(bank_dir / "v2.json", 2, count=5)
    mgr = UpdateManager(db=db, current_bank_path=current_bank, backup_dir=backup_dir)
    source = LocalUpdateSource(directory=bank_dir)
    infos = mgr.check_for_updates(source)
    assert len(infos) == 1
    info = infos[0]
    assert info.new_version == 2
    assert info.verification.ok
    assert info.has_update


def test_check_for_updates_ignores_same_version(
    db: Database, current_bank: Path, backup_dir: Path, bank_dir: Path,
) -> None:
    _make_bank(bank_dir / "v1.json", 1)
    mgr = UpdateManager(db=db, current_bank_path=current_bank, backup_dir=backup_dir)
    source = LocalUpdateSource(directory=bank_dir)
    infos = mgr.check_for_updates(source)
    assert len(infos) == 1
    assert not infos[0].has_update


def test_apply_update_swaps_and_records_history(
    db: Database, current_bank: Path, backup_dir: Path, bank_dir: Path,
) -> None:
    _make_bank(bank_dir / "v2.json", 2, count=5)
    mgr = UpdateManager(db=db, current_bank_path=current_bank, backup_dir=backup_dir)
    source = LocalUpdateSource(directory=bank_dir)
    infos = mgr.check_for_updates(source)
    info = infos[0]
    result = mgr.apply_update(info)
    assert result.success
    assert result.to_version == 2
    assert result.status == "APPLIED"

    data = json.loads(current_bank.read_text())
    assert data["version"] == 2
    assert len(data["signatures"]) == 5

    backups = list(backup_dir.glob("bank_backup_*.json"))
    assert len(backups) == 1

    history = mgr.list_history()
    assert len(history) == 1
    assert history[0]["status"] == "APPLIED"
    assert history[0]["to_version"] == "2"


def test_rollback_restores_previous(
    db: Database, current_bank: Path, backup_dir: Path, bank_dir: Path,
) -> None:
    _make_bank(bank_dir / "v2.json", 2, count=5)
    mgr = UpdateManager(db=db, current_bank_path=current_bank, backup_dir=backup_dir)
    source = LocalUpdateSource(directory=bank_dir)
    infos = mgr.check_for_updates(source)
    mgr.apply_update(infos[0])

    data = json.loads(current_bank.read_text())
    assert data["version"] == 2

    result = mgr.rollback()
    assert result.success
    assert result.status == "ROLLED_BACK"

    data = json.loads(current_bank.read_text())
    assert data["version"] == 1


def test_rollback_without_backup_fails(
    db: Database, current_bank: Path, backup_dir: Path,
) -> None:
    """No updates have ever been applied, so no backups exist."""
    mgr = UpdateManager(db=db, current_bank_path=current_bank, backup_dir=backup_dir)
    result = mgr.rollback()
    assert not result.success
    assert result.status == "NO_BACKUP"


def test_apply_update_with_invalid_candidate_fails_gracefully(
    db: Database, current_bank: Path, backup_dir: Path, bank_dir: Path,
) -> None:
    (bank_dir / "bad.json").write_text("not json")
    mgr = UpdateManager(db=db, current_bank_path=current_bank, backup_dir=backup_dir)
    source = LocalUpdateSource(directory=bank_dir)
    infos = mgr.check_for_updates(source)
    assert len(infos) == 1
    info = infos[0]
    assert not info.verification.ok
    result = mgr.apply_update(info)
    assert not result.success
    assert result.status == "FAILED"
    data = json.loads(current_bank.read_text())
    assert data["version"] == 1
