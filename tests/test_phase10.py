"""Unit tests for Phase 10: HashBankDownloader + ReportGenerator."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from itshield.storage.database import Database
from itshield.storage.migrations import run_migrations
from itshield.update.hash_downloader import (
    HashBankDownloader,
    HashSource,
    MalwareBazaarSource,
)
from itshield.reporting.report_generator import (
    ReportGenerator, ReportFormat,
)
from itshield.scanner.report_store import ScanReportStore


@pytest.fixture
def db(tmp_project: Path) -> Database:
    database = Database(tmp_project / "data" / "p10.db")
    run_migrations(database)
    yield database
    database.close()


@pytest.fixture
def bank_path(tmp_project: Path) -> Path:
    """A fresh hash bank file (the conftest one may be reused; we make a fresh one)."""
    p = tmp_project / "signatures" / "test_bank.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({
        "version": 1,
        "generated_at": "2026-01-01T00:00:00Z",
        "signatures": [
            {"sha256": "a" * 64, "name": "ExistingSig", "source": "test"},
        ],
    }))
    return p


@pytest.fixture
def backup_dir(tmp_project: Path) -> Path:
    d = tmp_project / "backups"
    d.mkdir()
    return d


class _StubHashSource(HashSource):
    """Returns a fixed list of hashes for deterministic tests."""

    name = "TestSource"

    def __init__(self, hashes: List[Dict[str, Any]]) -> None:
        self._hashes = hashes

    def fetch_hashes(self, limit: int = 1000) -> List[Dict[str, Any]]:
        return self._hashes[:limit]


def _make_hash(sha: str, name: str = "TestMalware") -> Dict[str, Any]:
    return {
        "sha256": sha.lower(),
        "name": f"TestSource:{name}",
        "family": name,
        "severity": "HIGH",
        "source": "TestSource",
        "tags": ["test"],
        "first_seen": "2026-01-01T00:00:00Z",
    }


def test_hash_downloader_merges_new_hashes(
    db: Database, bank_path: Path, backup_dir: Path,
) -> None:
    """New hashes get added; bank version is incremented."""
    source = _StubHashSource([
        _make_hash("b" * 64, "MalwareB"),
        _make_hash("c" * 64, "MalwareC"),
    ])
    dl = HashBankDownloader(
        db=db, bank_path=bank_path, backup_dir=backup_dir, source=source,
    )
    result = dl.download_and_merge()
    assert result.success
    assert result.hashes_fetched == 2
    assert result.hashes_added == 2
    assert result.hashes_duplicate == 0
    assert result.bank_version_before == 1
    assert result.bank_version_after == 2
    assert result.bank_size_before == 1
    assert result.bank_size_after == 3

    data = json.loads(bank_path.read_text())
    assert data["version"] == 2
    shas = {s["sha256"] for s in data["signatures"]}
    assert "a" * 64 in shas  # original
    assert "b" * 64 in shas  # new
    assert "c" * 64 in shas  # new

    backups = list(backup_dir.glob("hashes_backup_*.json"))
    assert len(backups) == 1


def test_hash_downloader_skips_duplicates(
    db: Database, bank_path: Path, backup_dir: Path,
) -> None:
    """Hashes already in the bank are counted as duplicates."""
    source = _StubHashSource([
        _make_hash("a" * 64, "ExistingSig"),  # already in the bank
        _make_hash("d" * 64, "NewOne"),
    ])
    dl = HashBankDownloader(
        db=db, bank_path=bank_path, backup_dir=backup_dir, source=source,
    )
    result = dl.download_and_merge()
    assert result.success
    assert result.hashes_fetched == 2
    assert result.hashes_added == 1
    assert result.hashes_duplicate == 1


def test_hash_downloader_no_new_hashes(
    db: Database, bank_path: Path, backup_dir: Path,
) -> None:
    """When all fetched hashes are already present, status is NO_NEW_HASHES."""
    source = _StubHashSource([_make_hash("a" * 64)])
    dl = HashBankDownloader(
        db=db, bank_path=bank_path, backup_dir=backup_dir, source=source,
    )
    result = dl.download_and_merge()
    assert not result.success
    assert result.status == "NO_NEW_HASHES"
    assert result.hashes_added == 0
    assert result.hashes_duplicate == 1


def test_hash_downloader_records_history(
    db: Database, bank_path: Path, backup_dir: Path,
) -> None:
    source = _StubHashSource([_make_hash("e" * 64)])
    dl = HashBankDownloader(
        db=db, bank_path=bank_path, backup_dir=backup_dir, source=source,
    )
    dl.download_and_merge()
    rows = db.fetchall(
        "SELECT component, status FROM update_history "
        "WHERE component='hash_bank' ORDER BY applied_at DESC LIMIT 1"
    )
    assert len(rows) == 1
    assert rows[0]["component"] == "hash_bank"
    assert rows[0]["status"] == "APPLIED"


def test_hash_downloader_handles_fetch_error(
    db: Database, bank_path: Path, backup_dir: Path,
) -> None:
    class _FailingSource(HashSource):
        name = "Failing"
        def fetch_hashes(self, limit: int = 1000):
            raise RuntimeError("network down")
    dl = HashBankDownloader(
        db=db, bank_path=bank_path, backup_dir=backup_dir, source=_FailingSource(),
    )
    result = dl.download_and_merge()
    assert not result.success
    assert result.status == "FETCH_ERROR"
    rows = db.fetchall(
        "SELECT status FROM update_history WHERE component='hash_bank'"
    )
    assert any(r["status"] == "FAILED_FETCH" for r in rows)


def test_hash_downloader_creates_bank_if_missing(
    db: Database, tmp_project: Path, backup_dir: Path,
) -> None:
    """If the bank file doesn't exist, the downloader creates it from scratch."""
    new_bank = tmp_project / "new_bank.json"
    assert not new_bank.exists()
    source = _StubHashSource([_make_hash("f" * 64)])
    dl = HashBankDownloader(
        db=db, bank_path=new_bank, backup_dir=backup_dir, source=source,
    )
    result = dl.download_and_merge()
    assert result.success
    assert result.bank_version_before == 0
    assert result.bank_version_after == 1
    assert new_bank.exists()
    data = json.loads(new_bank.read_text())
    assert data["version"] == 1
    assert len(data["signatures"]) == 1


def test_malwarebazaar_source_name() -> None:
    src = MalwareBazaarSource()
    assert src.name == "MalwareBazaar"
    assert "abuse.ch" in src.API_URL


@pytest.fixture
def populated_db(tmp_project: Path) -> Database:
    """A database with one scan job containing 3 file results."""
    db = Database(tmp_project / "data" / "report.db")
    run_migrations(db)
    store = ScanReportStore(db)
    job_id = store.create_job("/tmp/scan_target")
    store.mark_job_running(job_id)
    store.add_result(
        job_id=job_id, file_path="/tmp/clean.txt", file_size=10,
        file_type="UNKNOWN", sha256="a" * 64, detection="CLEAN",
        matched_rules=None, reason="no signals",
    )
    store.add_result(
        job_id=job_id, file_path="/tmp/bad.exe", file_size=2048,
        file_type="PE", sha256="b" * 64, detection="MALICIOUS",
        matched_rules=["EICAR"], reason="signature match: EICAR",
    )
    store.add_result(
        job_id=job_id, file_path="/tmp/susp.py", file_size=100,
        file_type="SHEBANG", sha256="c" * 64, detection="SUSPICIOUS",
        matched_rules=["shebang"], reason="YARA matched: shebang",
    )
    store.update_job_counts(
        job_id=job_id, files_total=3, files_scanned=3,
        files_malicious=1, files_suspicious=1, files_clean=1,
        files_unknown=0, files_skipped=0,
    )
    store.mark_job_completed(job_id)
    yield db
    db.close()


def test_report_generator_loads_job(populated_db: Database, tmp_project: Path) -> None:
    store = ScanReportStore(populated_db)
    job_id = store.list_jobs()[0]["id"]
    gen = ReportGenerator(db=populated_db, reports_dir=tmp_project / "reports")
    report = gen.load_job(job_id)
    assert report is not None
    assert report.job_id == job_id
    assert report.target_path == "/tmp/scan_target"
    assert report.state == "COMPLETED"
    assert len(report.results) == 3
    assert len(report.threats) == 2  # MALICIOUS + SUSPICIOUS


def test_report_generator_html(populated_db: Database, tmp_project: Path) -> None:
    store = ScanReportStore(populated_db)
    job_id = store.list_jobs()[0]["id"]
    reports_dir = tmp_project / "reports"
    gen = ReportGenerator(db=populated_db, reports_dir=reports_dir)
    path = gen.generate(job_id, fmt=ReportFormat.HTML)
    assert path.exists()
    content = path.read_text(encoding="utf-8")
    assert "<html" in content
    assert "رخداد" not in content or "گزارش" in content  # report header text
    assert "/tmp/bad.exe" in content  # the malicious file path
    assert "MALICIOUS" in content


def test_report_generator_json(populated_db: Database, tmp_project: Path) -> None:
    store = ScanReportStore(populated_db)
    job_id = store.list_jobs()[0]["id"]
    gen = ReportGenerator(db=populated_db, reports_dir=tmp_project / "reports")
    path = gen.generate(job_id, fmt=ReportFormat.JSON)
    assert path.exists()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["job_id"] == job_id
    assert data["files_total"] == 3
    assert data["files_malicious"] == 1
    assert data["files_suspicious"] == 1
    assert data["files_clean"] == 1
    assert len(data["results"]) == 3
    assert len(data["threats"]) == 2


def test_report_generator_text(populated_db: Database, tmp_project: Path) -> None:
    store = ScanReportStore(populated_db)
    job_id = store.list_jobs()[0]["id"]
    gen = ReportGenerator(db=populated_db, reports_dir=tmp_project / "reports")
    path = gen.generate(job_id, fmt=ReportFormat.TEXT)
    assert path.exists()
    content = path.read_text(encoding="utf-8")
    assert "ITShield Antivirus - Scan Report" in content
    assert "/tmp/scan_target" in content
    assert "MALICIOUS" in content


def test_report_generator_unknown_job_raises(populated_db: Database, tmp_project: Path) -> None:
    gen = ReportGenerator(db=populated_db, reports_dir=tmp_project / "reports")
    with pytest.raises(ValueError, match="No scan job"):
        gen.generate("nonexistent-job-id", fmt=ReportFormat.HTML)


def test_report_generator_missing_job_returns_none(populated_db: Database, tmp_project: Path) -> None:
    gen = ReportGenerator(db=populated_db, reports_dir=tmp_project / "reports")
    report = gen.load_job("nonexistent")
    assert report is None
