"""Integration tests for itshield.scanner.scanner.FileScanner."""

from __future__ import annotations

import threading
from pathlib import Path

from itshield.scanner.models import DetectionVerdict, ScanRequest
from itshield.scanner.scanner import FileScanner


def _build() -> FileScanner:
    return FileScanner()


def test_scan_eicar_returns_malicious(tmp_project: Path, eicar_file: Path) -> None:
    scanner = _build()
    result = scanner.scan_file(eicar_file)
    assert result.verdict == DetectionVerdict.MALICIOUS
    assert result.sha256 == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    assert result.matched_signature == "EICAR-Test-File"


def test_scan_clean_returns_clean(tmp_project: Path, clean_file: Path) -> None:
    scanner = _build()
    result = scanner.scan_file(clean_file)
    assert result.verdict == DetectionVerdict.CLEAN
    assert result.matched_signature is None
    assert result.matched_yara_rules == []


def test_scan_script_returns_suspicious(tmp_project: Path, script_file: Path) -> None:
    scanner = _build()
    result = scanner.scan_file(script_file)
    assert result.verdict == DetectionVerdict.SUSPICIOUS
    assert len(result.matched_yara_rules) > 0


def test_scan_directory_recursively(scan_dir: Path) -> None:
    scanner = _build()
    request = ScanRequest.from_path(scan_dir)
    cancel = threading.Event()
    progress_calls = []
    stats = scanner.scan(request,
                         progress_callback=lambda p: progress_calls.append(p),
                         cancellation_event=cancel)
    assert stats.files_total == 3
    assert stats.files_scanned == 3
    assert stats.files_malicious == 1
    assert stats.files_clean == 1
    assert stats.files_suspicious == 1
    assert len(progress_calls) == 3


def test_cancellation_event_stops_scan(scan_dir: Path) -> None:
    scanner = _build()
    request = ScanRequest.from_path(scan_dir)
    cancel = threading.Event()
    cancel.set()
    stats = scanner.scan(request, cancellation_event=cancel)
    assert stats.error == "cancelled"
    assert stats.files_scanned == 0
