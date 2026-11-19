"""Unit tests for itshield.scanner.file_analyzer.FileAnalyzer."""

from __future__ import annotations

from pathlib import Path

from itshield.scanner.file_analyzer import FileAnalyzer


def test_identifies_python_script(tmp_project: Path, script_file: Path) -> None:
    fa = FileAnalyzer()
    info = fa.identify(script_file)
    assert info.file_type == "SHEBANG"
    assert info.is_script


def test_identifies_clean_text_as_unknown(tmp_project: Path, clean_file: Path) -> None:
    fa = FileAnalyzer()
    info = fa.identify(clean_file)
    assert info.file_type == "UNKNOWN"


def test_identifies_pe_file(tmp_project: Path) -> None:
    p = tmp_project / "fake.exe"
    p.write_bytes(b"MZ" + b"\x00" * 64)
    fa = FileAnalyzer()
    info = fa.identify(p)
    assert info.file_type == "PE"
    assert info.is_executable


def test_identifies_zip_file(tmp_project: Path) -> None:
    p = tmp_project / "fake.zip"
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 64)
    fa = FileAnalyzer()
    info = fa.identify(p)
    assert info.file_type == "ZIP"
    assert info.is_archive


def test_missing_file_returns_unknown(tmp_project: Path) -> None:
    fa = FileAnalyzer()
    info = fa.identify(tmp_project / "missing.bin")
    assert info.file_type == "UNKNOWN"
