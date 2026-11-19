"""Scanner package for ITShield."""

from itshield.scanner.models import (
    DetectionVerdict,
    FileResult,
    ScanProgress,
    ScanRequest,
    ScanStats,
)
from itshield.scanner.hash_engine import HashEngine
from itshield.scanner.signature_engine import SignatureEngine
from itshield.scanner.yara_engine import YaraEngine
from itshield.scanner.file_analyzer import FileAnalyzer
from itshield.scanner.scanner import FileScanner
from itshield.scanner.report_store import ScanReportStore

__all__ = [
    "DetectionVerdict",
    "FileResult",
    "ScanProgress",
    "ScanRequest",
    "ScanStats",
    "HashEngine",
    "SignatureEngine",
    "YaraEngine",
    "FileAnalyzer",
    "FileScanner",
    "ScanReportStore",
]
