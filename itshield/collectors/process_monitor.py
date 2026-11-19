"""Process Monitor - reads /proc to enumerate processes (Linux).

Section 17 of the architecture document (Process Monitoring, roadmap item).

The monitor takes periodic snapshots of /proc/[pid]/ and diffs them to
emit:
    * PROCESS_CREATED  - a pid appeared since the last snapshot
    * PROCESS_TERMINATED - a pid disappeared since the last snapshot

Each event carries pid, ppid, name, cmdline and uid in the ``metadata``
field so the Correlation Engine can later chain events together.

The collector is Linux-only. On other platforms it raises at start()
time so the Core can degrade gracefully.

This module is intentionally minimal: it does NOT yet do continuous
fork() tracking (would need eBPF or netlink connector). The snapshot
interval is configurable (default 1 second).
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional

from itshield.events.bus import EventBus
from itshield.events.models import Event, EventType, Severity
from itshield.logging.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ProcessInfo:
    """Snapshot of a single process at one moment in time."""

    pid: int
    ppid: int
    name: str
    cmdline: str
    uid: int
    state: str

    def to_metadata(self) -> dict:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "cmdline": self.cmdline,
            "uid": self.uid,
            "state": self.state,
        }


class ProcessMonitor:
    """Periodic /proc snapshotter.

    Implements the Core's ModuleProtocol informally (start/stop/health).
    Register via :class:`itshield.service._CollectorModule` adapter or
    use standalone.
    """

    name = "process_monitor"
    dependencies: tuple[str, ...] = ("event_bus",)

    def __init__(
        self,
        bus: EventBus,
        interval_seconds: float = 1.0,
        proc_root: str = "/proc",
    ) -> None:
        self._bus = bus
        self.interval = interval_seconds
        self._proc_root = Path(proc_root)
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._last_snapshot: Dict[int, ProcessInfo] = {}
        self._snapshot_count = 0
        self._events_emitted = 0

    def start(self) -> None:
        if not self._proc_root.exists():
            raise RuntimeError(
                f"ProcessMonitor requires /proc; {self._proc_root} not found. "
                "This collector is Linux-only."
            )
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, name="proc-monitor", daemon=True
        )
        self._thread.start()
        logger.info("ProcessMonitor started (interval=%.2fs)", self.interval)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        logger.info("ProcessMonitor stopped (snapshots=%d, events=%d)",
                    self._snapshot_count, self._events_emitted)

    def health(self) -> dict:
        return {
            "running": self._thread is not None and self._thread.is_alive(),
            "snapshots": self._snapshot_count,
            "events_emitted": self._events_emitted,
            "last_process_count": len(self._last_snapshot),
            "interval_seconds": self.interval,
        }

    def snapshot(self) -> Dict[int, ProcessInfo]:
        """Take a single snapshot of every running process."""
        result: Dict[int, ProcessInfo] = {}
        for entry in self._proc_root.iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            info = self._read_process(pid)
            if info is not None:
                result[pid] = info
        return result

    def _read_process(self, pid: int) -> Optional[ProcessInfo]:
        """Read /proc/[pid]/status and /proc/[pid]/cmdline."""
        base = self._proc_root / str(pid)
        try:
            stat_text = (base / "stat").read_text()
            lp = stat_text.rfind(")")
            if lp < 0:
                return None
            pre = stat_text[:lp + 1]
            post = stat_text[lp + 2:].split()
            name = pre[pre.find("(") + 1:lp]
            ppid = int(post[1])  # post[0] is state, post[1] is ppid
            state = post[0]

            try:
                cmdline_bytes = (base / "cmdline").read_bytes()
                cmdline = " ".join(
                    a.decode("utf-8", errors="replace")
                    for a in cmdline_bytes.split(b"\x00") if a
                )
            except OSError:
                cmdline = name

            uid = -1
            try:
                for line in (base / "status").read_text().splitlines():
                    if line.startswith("Uid:"):
                        uid = int(line.split()[1])
                        break
            except (OSError, ValueError):
                pass

            return ProcessInfo(
                pid=pid, ppid=ppid, name=name, cmdline=cmdline, uid=uid, state=state,
            )
        except (OSError, ValueError, IndexError):
            return None

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                current = self.snapshot()
                self._snapshot_count += 1
                self._diff_and_publish(self._last_snapshot, current)
                self._last_snapshot = current
            except Exception:
                logger.exception("ProcessMonitor snapshot failed")
            self._stop_event.wait(self.interval)

    def _diff_and_publish(
        self,
        previous: Dict[int, ProcessInfo],
        current: Dict[int, ProcessInfo],
    ) -> None:
        """Publish PROCESS_CREATED / PROCESS_TERMINATED for the diff."""
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

    def list_processes(self) -> list[ProcessInfo]:
        """Return a list of every running process (single snapshot)."""
        return list(self.snapshot().values())
