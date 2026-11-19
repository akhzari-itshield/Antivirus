"""Integration test for ITShield Phase 14 - end-to-end pipeline test.

Exercises the full detection pipeline:
    1. Create a test directory with EICAR + clean + script files
    2. Run the FileScanner on it
    3. Verify scan results (EICAR -> MALICIOUS, clean -> CLEAN, script -> SUSPICIOUS)
    4. Store results via ScanReportStore
    5. Generate an HTML report via ReportGenerator
    6. Quarantine the malicious file via QuarantineEngine
    7. Verify quarantine integrity (hash matches)
    8. Run the RiskEngine on the EICAR result (score should be CRITICAL)
    9. Verify the full chain: scan -> detect -> quarantine -> report

This test does NOT test network features (IPC, real-time protection) -
those are covered by their individual unit tests. This test focuses on
the scanner -> storage -> report -> quarantine pipeline.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from itshield.scanner.file_analyzer import FileAnalyzer
from itshield.scanner.hash_engine import HashEngine
from itshield.scanner.models import DetectionVerdict, ScanRequest
from itshield.scanner.report_store import ScanReportStore
from itshield.scanner.scanner import FileScanner
from itshield.scanner.signature_engine import SignatureEngine
from itshield.scanner.yara_engine import YaraEngine
from itshield.storage.database import Database
from itshield.storage.migrations import run_migrations
from itshield.quarantine.engine import QuarantineEngine
from itshield.reporting.report_generator import ReportGenerator, ReportFormat
from itshield.detection.risk_engine import RiskEngine, RiskInput


EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@pytest.fixture
def integration_env(tmp_project: Path):
    """Set up a full test environment: DB, scanner, quarantine, report generator."""
    db = Database(tmp_project / "data" / "integration.db")
    run_migrations(db)

    scanner = FileScanner(
        hash_engine=HashEngine(),
        signature_engine=SignatureEngine(),
        yara_engine=YaraEngine(),
        analyzer=FileAnalyzer(),
    )
    store = ScanReportStore(db)
    quarantine = QuarantineEngine(db=db)
    report_gen = ReportGenerator(db=db, reports_dir=tmp_project / "reports")
    risk_engine = RiskEngine()

    yield {
        "db": db,
        "scanner": scanner,
        "store": store,
        "quarantine": quarantine,
        "report_gen": report_gen,
        "risk_engine": risk_engine,
        "tmp_dir": tmp_project,
    }
    db.close()


def test_full_pipeline_scan_detect_quarantine_report(integration_env):
    """End-to-end: scan files, detect EICAR, quarantine it, generate report."""
    env = integration_env
    scan_dir = env["tmp_dir"] / "scan_target"
    scan_dir.mkdir()

    eicar_path = scan_dir / "eicar.txt"
    eicar_path.write_bytes(EICAR)

    clean_path = scan_dir / "clean.txt"
    clean_path.write_bytes(b"Hello ITShield\n")

    script_path = scan_dir / "script.py"
    script_path.write_text("#!/usr/bin/python3\nprint('hello')\n")

    request = ScanRequest.from_path(scan_dir)
    stats = env["scanner"].scan(request)

    assert stats.files_total == 3
    assert stats.files_scanned == 3
    assert stats.files_malicious == 1  # EICAR
    assert stats.files_clean == 1      # clean.txt
    assert stats.files_suspicious == 1 # script.py (YARA shebang match)

    eicar_result = env["scanner"].scan_file(eicar_path)
    assert eicar_result.verdict == DetectionVerdict.MALICIOUS
    assert eicar_result.sha256 == EICAR_SHA256
    assert eicar_result.matched_signature == "EICAR-Test-File"

    job_id = env["store"].create_job(str(scan_dir))
    env["store"].mark_job_running(job_id)
    env["store"].add_result(
        job_id=job_id, file_path=eicar_result.file_path,
        file_size=eicar_result.file_size, file_type=eicar_result.file_type,
        sha256=eicar_result.sha256, detection=eicar_result.verdict.value,
        matched_rules=eicar_result.matched_yara_rules, reason=eicar_result.reason,
    )
    env["store"].update_job_counts(
        job_id=job_id, files_total=3, files_scanned=3,
        files_malicious=1, files_suspicious=1, files_clean=1,
        files_unknown=0, files_skipped=0,
    )
    env["store"].mark_job_completed(job_id)

    risk = env["risk_engine"].assess(RiskInput(
        sha256=eicar_result.sha256,
        signature_name=eicar_result.matched_signature,
        yara_rules=eicar_result.matched_yara_rules,
        file_type=eicar_result.file_type,
    ))
    assert risk.verdict == DetectionVerdict.MALICIOUS
    assert risk.score >= 75
    assert risk.level.value == "CRITICAL"

    q_entry = env["quarantine"].quarantine(
        file_path=eicar_path,
        sha256=eicar_result.sha256,
        reason=eicar_result.reason,
    )
    assert q_entry.sha256 == EICAR_SHA256
    assert not eicar_path.exists()  # file was moved

    q_list = env["quarantine"].list_quarantined()
    assert len(q_list) == 1

    report_path = env["report_gen"].generate(job_id, fmt=ReportFormat.HTML)
    assert report_path.exists()
    report_content = report_path.read_text(encoding="utf-8")
    assert "eicar" in report_content.lower()
    assert "MALICIOUS" in report_content

    json_path = env["report_gen"].generate(job_id, fmt=ReportFormat.JSON)
    json_data = json.loads(json_path.read_text(encoding="utf-8"))
    assert json_data["files_malicious"] == 1
    assert json_data["files_total"] == 3


def test_pipeline_quarantine_integrity_check(integration_env):
    """Quarantined file hash must match the recorded SHA-256."""
    env = integration_env
    scan_dir = env["tmp_dir"] / "integrity_test"
    scan_dir.mkdir()
    eicar_path = scan_dir / "eicar.txt"
    eicar_path.write_bytes(EICAR)

    result = env["scanner"].scan_file(eicar_path)
    entry = env["quarantine"].quarantine(
        file_path=eicar_path, sha256=result.sha256, reason=result.reason,
    )

    q_list = env["quarantine"].list_quarantined()
    assert len(q_list) == 1
    assert q_list[0]["sha256"] == EICAR_SHA256

    restored = env["tmp_dir"] / "restored_eicar.txt"
    restore_result = env["quarantine"].restore(q_list[0]["id"], restored)
    assert restored.exists()
    assert restored.read_bytes() == EICAR
    assert restore_result["sha256"] == EICAR_SHA256


def test_pipeline_risk_engine_combines_signals(integration_env):
    """RiskEngine should combine multiple weak signals into a strong verdict."""
    env = integration_env
    risk_engine = env["risk_engine"]

    result = risk_engine.assess(RiskInput(
        sha256="abc",
        signature_name="TestMalware",
        entropy=7.5,
    ))
    assert result.score == 95
    assert result.verdict == DetectionVerdict.MALICIOUS
    assert result.level.value == "CRITICAL"

    result2 = risk_engine.assess(RiskInput(
        sha256="xyz",
        yara_rules=["suspicious_rule"],
        file_type="UNKNOWN",
    ))
    assert result2.score == 30
    assert result2.verdict == DetectionVerdict.UNKNOWN


def test_pipeline_database_persistence(integration_env):
    """Scan results must survive a database close + reopen."""
    env = integration_env
    db_path = env["db"].path

    store = env["store"]
    job_id = store.create_job("/tmp/persist_test")
    store.mark_job_running(job_id)
    store.add_result(
        job_id=job_id, file_path="/tmp/test.txt", file_size=100,
        file_type="UNKNOWN", sha256="abc123", detection="CLEAN",
        matched_rules=None, reason="no signals",
    )
    store.mark_job_completed(job_id)
    env["db"].close()

    db2 = Database(db_path)
    store2 = ScanReportStore(db2)
    jobs = store2.list_jobs()
    assert len(jobs) == 1
    assert jobs[0]["id"] == job_id
    assert jobs[0]["state"] == "COMPLETED"

    results = store2.get_results(job_id)
    assert len(results) == 1
    assert results[0]["file_path"] == "/tmp/test.txt"
    db2.close()
