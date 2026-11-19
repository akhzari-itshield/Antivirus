"""Unit tests for itshield.storage.* (Database, migrations, ScanReportStore)."""

from __future__ import annotations

from pathlib import Path

import pytest

from itshield.storage.database import Database
from itshield.storage.migrations import run_migrations
from itshield.scanner.report_store import ScanReportStore


@pytest.fixture
def db(tmp_project: Path) -> Database:
    settings_db = tmp_project / "data" / "test.db"
    database = Database(settings_db)
    run_migrations(database)
    yield database
    database.close()


def test_migrations_create_tables(db: Database) -> None:
    tables = db.fetchall(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    names = {row["name"] for row in tables}
    assert "scan_jobs" in names
    assert "scan_results" in names
    assert "signatures" in names
    assert "audit_logs" in names
    assert "process_events" in names


def test_scan_report_store_create_job(db: Database) -> None:
    store = ScanReportStore(db)
    job_id = store.create_job("/tmp/test")
    assert isinstance(job_id, str) and len(job_id) > 0

    job = store.get_job(job_id)
    assert job is not None
    assert job["target_path"] == "/tmp/test"
    assert job["state"] == "PENDING"


def test_scan_report_store_add_results_and_query(db: Database) -> None:
    store = ScanReportStore(db)
    job_id = store.create_job("/tmp/test")
    store.mark_job_running(job_id)

    store.add_result(
        job_id=job_id,
        file_path="/tmp/test/a.txt",
        file_size=10,
        file_type="UNKNOWN",
        sha256="abc",
        detection="CLEAN",
        matched_rules=None,
        reason="no signals",
    )
    store.add_result(
        job_id=job_id,
        file_path="/tmp/test/b.exe",
        file_size=2048,
        file_type="PE",
        sha256="def",
        detection="MALICIOUS",
        matched_rules=["rule1", "rule2"],
        reason="signature match",
    )

    results = store.get_results(job_id)
    assert len(results) == 2
    malicious = store.get_results_by_detection(job_id, "MALICIOUS")
    assert len(malicious) == 1
    assert malicious[0]["matched_rules"] == "rule1,rule2"


def test_scan_report_store_complete_job(db: Database) -> None:
    store = ScanReportStore(db)
    job_id = store.create_job("/tmp/test")
    store.mark_job_running(job_id)
    store.update_job_counts(
        job_id=job_id,
        files_total=10,
        files_scanned=8,
        files_malicious=1,
        files_suspicious=2,
        files_clean=5,
        files_unknown=0,
        files_skipped=2,
    )
    store.mark_job_completed(job_id)

    job = store.get_job(job_id)
    assert job["state"] == "COMPLETED"
    assert job["files_total"] == 10
    assert job["files_malicious"] == 1


def test_scan_report_store_failed_job(db: Database) -> None:
    store = ScanReportStore(db)
    job_id = store.create_job("/tmp/test")
    store.mark_job_completed(job_id, error="scan crashed")
    job = store.get_job(job_id)
    assert job["state"] == "FAILED"
    assert job["error"] == "scan crashed"


def test_scan_report_store_list_jobs(db: Database) -> None:
    store = ScanReportStore(db)
    for i in range(3):
        store.create_job(f"/tmp/test{i}")
    jobs = store.list_jobs(limit=10)
    assert len(jobs) == 3
    assert jobs[0]["target_path"] in {"/tmp/test0", "/tmp/test1", "/tmp/test2"}


def test_scan_report_store_delete_job(db: Database) -> None:
    store = ScanReportStore(db)
    job_id = store.create_job("/tmp/test")
    assert store.delete_job(job_id) == 1
    assert store.get_job(job_id) is None
