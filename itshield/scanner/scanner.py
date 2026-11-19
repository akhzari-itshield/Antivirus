"""File Scanner - orchestrates hash, signature, YARA and analyzer passes.

Section 9.1 of the architecture document.

The scanner walks a target path (file or directory) recursively, calls each
detection sub-engine, and yields :class:`FileResult` objects. A
``progress_callback`` and a ``cancellation_event`` (``threading.Event``)
mirror the documented ``Progress Callback`` and ``Cancellation Event``
features.

A reference Detection Engine (:mod:`itshield.scanner.detection`) is wired
in to convert raw signals (signature match, YARA match, file type) into the
final :class:`DetectionVerdict`.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Callable, Iterator, List, Optional

from itshield.config.settings import get_settings
from itshield.logging.logger import get_logger
from itshield.scanner.file_analyzer import FileAnalyzer
from itshield.scanner.hash_engine import HashEngine
from itshield.scanner.models import (
    DetectionVerdict,
    FileResult,
    ScanProgress,
    ScanRequest,
    ScanStats,
)
from itshield.scanner.signature_engine import SignatureEngine
from itshield.scanner.yara_engine import YaraEngine

logger = get_logger(__name__)

ProgressCallback = Callable[[ScanProgress], None]


class FileScanner:
    """Walks a target path and emits :class:`FileResult` for each file.

    Designed to be reusable across CLI, IPC and GUI front-ends. The scanner
    itself is stateless between runs; persistent state (job ids, results)
    lives in :class:`ScanReportStore`.
    """

    def __init__(
        self,
        hash_engine: Optional[HashEngine] = None,
        signature_engine: Optional[SignatureEngine] = None,
        yara_engine: Optional[YaraEngine] = None,
        analyzer: Optional[FileAnalyzer] = None,
        max_file_size: Optional[int] = None,
    ) -> None:
        settings = get_settings()
        self.hash_engine = hash_engine or HashEngine()
        self.signature_engine = signature_engine or SignatureEngine()
        self.yara_engine = yara_engine or YaraEngine()
        self.analyzer = analyzer or FileAnalyzer()
        self.max_file_size = max_file_size or settings.scanner_max_file_size
        self.follow_symlinks = settings.scanner_follow_symlinks

    def _iter_files(self, root: Path) -> Iterator[Path]:
        """Recursively yield regular files under ``root`` (or just ``root``)."""
        if root.is_file():
            yield root
            return

        for dirpath, dirnames, filenames in os.walk(
            root,
            topdown=True,
            followlinks=self.follow_symlinks,
        ):
            if not self.follow_symlinks:
                dirnames[:] = [
                    d for d in dirnames
                    if not Path(dirpath, d).is_symlink()
                ]
            for fname in filenames:
                fpath = Path(dirpath) / fname
                if not self.follow_symlinks and fpath.is_symlink():
                    continue
                yield fpath

    def scan_file(self, path: str | Path) -> FileResult:
        """Scan a single file with every sub-engine and return the result."""
        path = Path(path).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        if not path.is_file():
            raise IsADirectoryError(f"Not a regular file: {path}")

        try:
            size = path.stat().st_size
        except OSError as exc:
            return FileResult(
                file_path=str(path),
                verdict=DetectionVerdict.SKIPPED,
                reason=f"stat error: {exc}",
            )

        if size > self.max_file_size:
            return FileResult(
                file_path=str(path),
                file_size=size,
                verdict=DetectionVerdict.SKIPPED,
                reason=f"file exceeds max scan size ({size} > {self.max_file_size})",
            )

        try:
            info = self.analyzer.identify(path)
        except Exception as exc:
            logger.debug("FileAnalyzer failed for %s: %s", path, exc)
            info = None

        file_type = info.file_type if info else "UNKNOWN"

        sha256: Optional[str] = None
        try:
            sha256 = self.hash_engine.hash_file(path, max_file_size=self.max_file_size)
        except ValueError as exc:
            return FileResult(
                file_path=str(path), file_size=size, file_type=file_type,
                verdict=DetectionVerdict.SKIPPED, reason=str(exc),
            )
        except Exception as exc:
            logger.debug("Hash failed for %s: %s", path, exc)
            return FileResult(
                file_path=str(path), file_size=size, file_type=file_type,
                verdict=DetectionVerdict.SKIPPED, reason=f"hash error: {exc}",
            )

        sig_match = self.signature_engine.lookup(sha256) if sha256 else None

        yara_rules: List[str] = []
        try:
            yara_matches = self.yara_engine.scan_file(path)
            yara_rules = [m.rule for m in yara_matches]
        except Exception as exc:
            logger.debug("YARA scan failed for %s: %s", path, exc)
            if not sig_match:
                return FileResult(
                    file_path=str(path), file_size=size, file_type=file_type,
                    sha256=sha256, verdict=DetectionVerdict.UNKNOWN,
                    reason=f"YARA scan error: {exc}",
                )

        if sig_match:
            verdict = DetectionVerdict.MALICIOUS
            reason = (
                f"signature match: {sig_match.name}"
                + (f" (family={sig_match.family})" if sig_match.family else "")
            )
        elif yara_rules:
            verdict = DetectionVerdict.SUSPICIOUS
            reason = f"YARA matched: {', '.join(yara_rules)}"
        else:
            verdict = DetectionVerdict.CLEAN
            reason = "no signals"

        return FileResult(
            file_path=str(path),
            file_size=size,
            file_type=file_type,
            sha256=sha256,
            verdict=verdict,
            matched_signature=sig_match.name if sig_match else None,
            matched_yara_rules=yara_rules,
            reason=reason,
        )

    def scan(
        self,
        request: ScanRequest,
        progress_callback: Optional[ProgressCallback] = None,
        cancellation_event: Optional[threading.Event] = None,
    ) -> ScanStats:
        """Scan ``request.target_path`` and return aggregate stats.

        ``progress_callback`` is invoked with a live :class:`ScanProgress`
        after every file. ``cancellation_event`` lets the caller stop the
        scan cleanly between files.
        """
        target = Path(request.target_path).expanduser().resolve()
        if not target.exists():
            raise FileNotFoundError(f"Scan target does not exist: {target}")

        started_at = time.time()
        started_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started_at))

        file_list: List[Path] = []
        for p in self._iter_files(target):
            file_list.append(p)

        stats = ScanStats(
            job_id=request.job_id,
            target_path=str(target),
            files_total=len(file_list),
            started_at=started_iso,
        )

        for idx, fpath in enumerate(file_list, start=1):
            if cancellation_event is not None and cancellation_event.is_set():
                logger.info("Scan %s cancelled by caller at file %d/%d",
                            request.job_id, idx, stats.files_total)
                stats.error = "cancelled"
                break

            try:
                result = self.scan_file(fpath)
            except Exception as exc:
                logger.exception("Unexpected error scanning %s", fpath)
                stats.files_skipped += 1
                continue

            stats.files_scanned += 1
            if result.verdict == DetectionVerdict.MALICIOUS:
                stats.files_malicious += 1
            elif result.verdict == DetectionVerdict.SUSPICIOUS:
                stats.files_suspicious += 1
            elif result.verdict == DetectionVerdict.CLEAN:
                stats.files_clean += 1
            elif result.verdict == DetectionVerdict.UNKNOWN:
                stats.files_unknown += 1
            elif result.verdict == DetectionVerdict.SKIPPED:
                stats.files_skipped += 1

            if progress_callback is not None:
                progress = ScanProgress(
                    job_id=request.job_id,
                    files_total=stats.files_total,
                    files_scanned=stats.files_scanned,
                    files_skipped=stats.files_skipped,
                    current_path=str(fpath),
                    bytes_processed=result.file_size,
                    percent=round(
                        100.0 * stats.files_scanned / max(stats.files_total, 1), 2
                    ),
                )
                try:
                    progress_callback(progress)
                except Exception:
                    logger.exception("Progress callback raised; continuing")

        finished_at = time.time()
        stats.finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(finished_at))
        stats.duration_seconds = round(finished_at - started_at, 3)
        return stats

    def iter_results(
        self,
        request: ScanRequest,
        cancellation_event: Optional[threading.Event] = None,
    ) -> Iterator[FileResult]:
        """Yield :class:`FileResult` lazily for memory-efficient iteration."""
        target = Path(request.target_path).expanduser().resolve()
        if not target.exists():
            raise FileNotFoundError(f"Scan target does not exist: {target}")

        for fpath in self._iter_files(target):
            if cancellation_event is not None and cancellation_event.is_set():
                break
            try:
                yield self.scan_file(fpath)
            except Exception as exc:
                logger.exception("Error scanning %s", fpath)
                yield FileResult(
                    file_path=str(fpath),
                    verdict=DetectionVerdict.SKIPPED,
                    reason=f"scan error: {exc}",
                )
