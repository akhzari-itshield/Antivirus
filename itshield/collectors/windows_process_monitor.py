"""Windows Process Monitor using Toolhelp32 API (Phase 15).

Section 17 of the architecture document - Process Monitoring on Windows.

Uses ``pywin32`` to call CreateToolhelp32Snapshot / Process32First /
Process32Next, which enumerates every running process with its pid,
ppid, name, and executable path.

This is the Windows counterpart of
:class:`~itshield.collectors.process_monitor.ProcessMonitor` which reads
/proc on Linux.

The monitor takes periodic snapshots and diffs them to emit
PROCESS_CREATED / PROCESS_TERMINATED events, exactly like the Linux
version.
"""

from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from itshield.events.bus import EventBus
from itshield.events.models import Event, EventType, Severity
from itshield.logging.logger import get_logger

logger = get_logger(__name__)

_IS_WINDOWS = sys.platform == "win32"

if _IS_WINDOWS:
    try:
        import win32api
        import win32process
        import win32con
        import pywintypes
        _PYWIN32_AVAILABLE = True
    except ImportError:
        _PYWIN32_AVAILABLE = False
else:
    _PYWIN32_AVAILABLE = False


@dataclass
class WindowsProcessInfo:
    """Snapshot of one Windows process."""

    pid: int
    ppid: int
    name: str
    exe_path: str = ""
    threads: int = 0

    def to_metadata(self) -> dict:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "exe_path": self.exe_path,
            "threads": self.threads,
        }


class WindowsProcessMonitor:
    """Toolhelp32-based process monitor for Windows.

    Implements the same interface as the Linux ProcessMonitor so the
    Correlation Engine and Behavior Analyzer don't need to know which
    platform they're running on.
    """

    name = "windows_process_monitor"
    dependencies: tuple[str, ...] = ("event_bus",)

    def __init__(
        self,
        bus: EventBus,
        interval_seconds: float = 1.0,
    ) -> None:
        self._bus = bus
        self.interval = interval_seconds
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._last_snapshot: Dict[int, WindowsProcessInfo] = {}
        self._snapshot_count = 0
        self._events_emitted = 0

    def start(self) -> None:
        if not _IS_WINDOWS or not _PYWIN32_AVAILABLE:
            raise RuntimeError(
                "WindowsProcessMonitor requires Windows with pywin32."
            )
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, name="win-proc-monitor", daemon=True
        )
        self._thread.start()
        logger.info("WindowsProcessMonitor started (interval=%.2fs)", self.interval)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        logger.info("WindowsProcessMonitor stopped")

    def health(self) -> dict:
        return {
            "running": self._thread is not None and self._thread.is_alive(),
            "snapshots": self._snapshot_count,
            "events_emitted": self._events_emitted,
            "last_process_count": len(self._last_snapshot),
        }

    def snapshot(self) -> Dict[int, WindowsProcessInfo]:
        """Take a single snapshot using Toolhelp32."""
        if not _PYWIN32_AVAILABLE:
            return {}
        result: Dict[int, WindowsProcessInfo] = {}
        try:
            snapshot = win32process.CreateToolhelp32Snapshot(
                win32process.TH32CS_SNAPPROCESS, 0
            )
            entry = win32process.Process32First(snapshot)
            while entry is not None:
                pid = entry.th32ProcessID
                ppid = entry.th32ParentProcessID
                name = entry.szExeFile or ""
                exe_path = ""
                try:
                    exe_path = win32process.GetModuleFileNameEx(pid, 0) or ""
                except Exception:
                    pass
                result[pid] = WindowsProcessInfo(
                    pid=pid, ppid=ppid, name=name,
                    exe_path=exe_path, threads=entry.cntThreads,
                )
                try:
                    entry = win32process.Process32Next(snapshot)
                except Exception:
                    break
            win32api.CloseHandle(snapshot)
        except Exception:
            logger.exception("Windows process snapshot failed")
        return result

    def list_processes(self) -> List[WindowsProcessInfo]:
        """One-shot: return a list of every running process."""
        return list(self.snapshot().values())

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                current = self.snapshot()
                self._snapshot_count += 1
                self._diff_and_publish(self._last_snapshot, current)
                self._last_snapshot = current
            except Exception:
                logger.exception("Windows process monitor cycle failed")
            self._stop_event.wait(self.interval)

    def _diff_and_publish(
        self,
        previous: Dict[int, WindowsProcessInfo],
        current: Dict[int, WindowsProcessInfo],
    ) -> None:
        for pid, info in current.items():
            if pid not in previous:
                self._bus.publish(Event(
                    event_type=EventType.PROCESS_CREATED,
                    source=self.name,
                    severity=Severity.INFO,
                    process_id=pid,
                    process_name=info.name,
                    parent_process_id=info.ppid,
                    metadata=info.to_metadata(),
                ))
                self._events_emitted += 1
        for pid, info in previous.items():
            if pid not in current:
                self._bus.publish(Event(
                    event_type=EventType.PROCESS_TERMINATED,
                    source=self.name,
                    severity=Severity.INFO,
                    process_id=pid,
                    process_name=info.name,
                    parent_process_id=info.ppid,
                    metadata=info.to_metadata(),
                ))
                self._events_emitted += 1
