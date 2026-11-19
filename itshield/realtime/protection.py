"""Real-Time Protection - combines FileWatcher + Scanner + Quarantine.

When a file is created or modified inside a watched directory, the
protection layer scans it immediately. Files flagged as MALICIOUS are:

    * published as a THREAT_DETECTED event
    * (optionally) quarantined via the QuarantineEngine

SUSPICIOUS files are also reported but not auto-quarantined; the user
should review them.
"""

from __future__ import annotations

import threading
import time
import uuid
from pathlib import Path
from typing import Callable, Optional

from itshield.events.bus import EventBus
from itshield.events.models import Event, EventType, Severity
from itshield.logging.logger import get_logger
from itshield.realtime.watcher import FileWatcher
from itshield.scanner.models import DetectionVerdict, FileResult
from itshield.scanner.scanner import FileScanner

logger = get_logger(__name__)


class RealTimeProtection:
    """High-level real-time protection orchestrator.

    Wraps a :class:`FileWatcher` (inotify) and a :class:`FileScanner`.
    Subscribes to FILE_CREATED / FILE_MODIFIED events on the bus and
    runs a scan for each new/modified regular file.

    Auto-quarantine can be enabled with ``auto_quarantine=True``.
    """

    name = "realtime_protection"
    dependencies: tuple[str, ...] = ("event_bus", "file_watcher")

    def __init__(
        self,
        bus: EventBus,
        scanner: FileScanner,
        watch_root: str | Path,
        auto_quarantine: bool = False,
        quarantine_engine=None,
        max_scan_size: int = 64 * 1024 * 1024,
    ) -> None:
        self._bus = bus
        self._scanner = scanner
        self._watch_root = Path(watch_root).expanduser().resolve()
        self._auto_quarantine = auto_quarantine
        self._quarantine = quarantine_engine
        self._max_scan_size = max_scan_size
        self._watcher = FileWatcher(bus=bus, root=self._watch_root, recursive=True)
        self._unsubscribe: Optional[Callable[[], None]] = None
        self._stop_event = threading.Event()
        self._scan_thread: Optional[threading.Thread] = None
        self._pending_queue: list[str] = []
        self._queue_lock = threading.Lock()
        self._scanned_count = 0
        self._threats_count = 0
        self._quarantined_count = 0

    def start(self) -> None:
        self._watcher.start()

        def _on_event(event: Event) -> None:
            if event.file_path is None:
                return
            if event.metadata.get("is_directory"):
                return  # skip directory events; we care about files
            self._enqueue_scan(event.file_path)

        self._unsubscribe = self._bus.subscribe(
            _on_event,
            [EventType.FILE_CREATED, EventType.FILE_MODIFIED],
        )

        self._stop_event.clear()
        self._scan_thread = threading.Thread(
            target=self._scan_loop, name="rtp-scan", daemon=True
        )
        self._scan_thread.start()
        logger.info(
            "RealTimeProtection started on %s (auto_quarantine=%s)",
            self._watch_root, self._auto_quarantine,
        )

    def stop(self) -> None:
        self._stop_event.set()
        if self._scan_thread is not None:
            self._scan_thread.join(timeout=3.0)
            self._scan_thread = None
        if self._unsubscribe is not None:
            self._unsubscribe()
            self._unsubscribe = None
        self._watcher.stop()
        logger.info(
            "RealTimeProtection stopped (scanned=%d, threats=%d, quarantined=%d)",
            self._scanned_count, self._threats_count, self._quarantined_count,
        )

    def health(self) -> dict:
        return {
            "running": self._scan_thread is not None and self._scan_thread.is_alive(),
            "watch_root": str(self._watch_root),
            "scanned_count": self._scanned_count,
            "threats_count": self._threats_count,
            "quarantined_count": self._quarantined_count,
            "pending_queue": len(self._pending_queue),
            "watcher_health": self._watcher.health(),
        }

    def _enqueue_scan(self, file_path: str) -> None:
        with self._queue_lock:
            if file_path not in self._pending_queue:
                self._pending_queue.append(file_path)

    def _scan_loop(self) -> None:
        while not self._stop_event.is_set():
            with self._queue_lock:
                if not self._pending_queue:
                    pending: list[str] = []
                else:
                    pending = self._pending_queue[:]
                    self._pending_queue.clear()
            for path in pending:
                if self._stop_event.is_set():
                    break
                self._scan_and_act(path)
            self._stop_event.wait(0.2)

    def _scan_and_act(self, file_path: str) -> Optional[FileResult]:
        """Scan one file and publish the appropriate events."""
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            return None
        try:
            if path.stat().st_size > self._max_scan_size:
                logger.debug("Skipping oversized file in RTP: %s", path)
                return None
            result = self._scanner.scan_file(path)
        except Exception:
            logger.exception("RTP scan failed for %s", path)
            return None

        self._scanned_count += 1

        if result.verdict == DetectionVerdict.MALICIOUS:
            self._threats_count += 1
            self._bus.publish(Event(
                event_type=EventType.THREAT_DETECTED,
                source=self.name,
                severity=Severity.CRITICAL,
                file_path=str(path),
                file_hash=result.sha256,
                metadata={
                    "verdict": result.verdict.value,
                    "reason": result.reason,
                    "matched_signature": result.matched_signature,
                    "matched_yara_rules": result.matched_yara_rules,
                },
            ))
            if self._auto_quarantine and self._quarantine is not None and result.sha256:
                try:
                    self._quarantine.quarantine(
                        file_path=path,
                        sha256=result.sha256,
                        reason=result.reason,
                        extra_metadata={
                            "source": "realtime_protection",
                            "matched_signature": result.matched_signature,
                        },
                    )
                    self._quarantined_count += 1
                except Exception:
                    logger.exception("Auto-quarantine failed for %s", path)

        elif result.verdict == DetectionVerdict.SUSPICIOUS:
            self._bus.publish(Event(
                event_type=EventType.SECURITY_ALERT,
                source=self.name,
                severity=Severity.WARNING,
                file_path=str(path),
                file_hash=result.sha256,
                metadata={
                    "verdict": result.verdict.value,
                    "reason": result.reason,
                    "matched_yara_rules": result.matched_yara_rules,
                },
            ))

        return result
