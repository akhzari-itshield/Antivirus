"""Behavior Analyzer - detects anomalous process behavior (Phase 7 + 11).

Section 16 of the architecture document.

Subscribes to PROCESS_CREATED / PROCESS_TERMINATED events and tracks
per-process behavior counters. When a counter crosses a threshold, an
anomaly string is recorded. The Correlation Engine or Risk Engine can
then consume these anomalies.

Anomalies detected:
    Phase 7:
    * rapid_spawning      - a parent creates > 5 children in 10s
    * short_lived         - process exits within 2s of creation (sandbox escape)
    * suspicious_name     - process name matches common malware naming patterns

    Phase 11 (advanced):
    * mass_file_creation  - a process creates > 50 files in 30s (ransomware-like)
    * mass_file_modification - a process modifies > 100 files in 60s (encryption)
    * persistence_install - process writes to known autostart locations
      (/etc/cron.*, ~/.config/autostart, systemd user units, ~/.bashrc)
    * suspicious_children - process spawns interpreters (python/perl/powershell)
      as children, common in living-off-the-land attacks

The analyzer publishes a SECURITY_ALERT event whenever an anomaly is
detected so the GUI can show it in real time.
"""

from __future__ import annotations

import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional

from itshield.events.bus import EventBus
from itshield.events.models import Event, EventType, Severity
from itshield.logging.logger import get_logger

logger = get_logger(__name__)


_SUSPICIOUS_NAME_RE = re.compile(
    r"("
    r"\.exe\.exe$|"           # double extension
    r"\.scr\.exe$|"
    r"\.pdf\.exe$|"
    r"\.doc\.exe$|"
    r"^[a-z0-9]{10,}\.exe$|"  # long random-looking name
    r"^[a-z0-9]{10,}\.scr$|"
    r"^[a-z0-9]{10,}\.bat$"
    r")",
    re.IGNORECASE,
)


_SUSPICIOUS_CHILD_NAMES = {
    "python", "python2", "python3", "python3.10", "python3.11", "python3.12",
    "perl", "perl5",
    "ruby",
    "node", "nodejs",
    "powershell", "pwsh",
    "cmd.exe", "command.exe",
    "bash", "sh", "zsh", "dash",
    "wget", "curl",
    "nc", "ncat", "netcat",
}

_PERSISTENCE_PATHS = (
    "/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.hourly/",
    "/etc/cron.weekly/", "/etc/cron.monthly/",
    "/etc/systemd/system/",
    "/etc/init.d/",
    "/etc/rc.local",
    "/etc/profile.d/",
    "~/.config/autostart/",
    "~/.local/share/systemd/user/",
    "~/.bashrc", "~/.bash_profile", "~/.profile",
    "~/.zshrc",
    "/etc/sudoers", "/etc/sudoers.d/",
)


@dataclass
class ProcessRecord:
    """A tracked process and its behavior counters."""

    pid: int
    ppid: int
    name: str
    started_at: float
    terminated_at: Optional[float] = None
    children_pids: List[int] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)
    files_created: List[tuple[float, str]] = field(default_factory=list)   # (ts, path)
    files_modified: List[tuple[float, str]] = field(default_factory=list)
    persistence_writes: List[str] = field(default_factory=list)

    @property
    def lifetime_seconds(self) -> Optional[float]:
        if self.terminated_at is None:
            return None
        return self.terminated_at - self.started_at


class BehaviorAnalyzer:
    """Tracks process behavior and flags anomalies."""

    name = "behavior_analyzer"
    dependencies: tuple[str, ...] = ("event_bus",)

    def __init__(
        self,
        bus: EventBus,
        child_threshold: int = 5,
        child_window_seconds: float = 10.0,
        short_lived_seconds: float = 2.0,
        mass_create_threshold: int = 50,
        mass_create_window: float = 30.0,
        mass_modify_threshold: int = 100,
        mass_modify_window: float = 60.0,
    ) -> None:
        self._bus = bus
        self._child_threshold = child_threshold
        self._child_window_seconds = child_window_seconds
        self._short_lived_seconds = short_lived_seconds
        self._mass_create_threshold = mass_create_threshold
        self._mass_create_window = mass_create_window
        self._mass_modify_threshold = mass_modify_threshold
        self._mass_modify_window = mass_modify_window

        self._lock = threading.RLock()
        self._processes: Dict[int, ProcessRecord] = {}
        self._parent_children: Dict[int, Deque[tuple[float, int]]] = defaultdict(deque)
        self._events_processed = 0
        self._anomalies_detected = 0

    def start(self) -> None:
        self._unsubscribe = self._bus.subscribe(self._on_event)
        logger.info("BehaviorAnalyzer started (child_threshold=%d)", self._child_threshold)

    def stop(self) -> None:
        if self._unsubscribe is not None:
            self._unsubscribe()
            self._unsubscribe = None
        logger.info(
            "BehaviorAnalyzer stopped (events_processed=%d, anomalies=%d)",
            self._events_processed, self._anomalies_detected,
        )

    def health(self) -> dict:
        with self._lock:
            return {
                "running": self._unsubscribe is not None,
                "tracked_processes": len(self._processes),
                "events_processed": self._events_processed,
                "anomalies_detected": self._anomalies_detected,
            }

    def _on_event(self, event: Event) -> None:
        if event.event_type == EventType.PROCESS_CREATED:
            self._handle_created(event)
        elif event.event_type == EventType.PROCESS_TERMINATED:
            self._handle_terminated(event)
        elif event.event_type == EventType.FILE_CREATED:
            self._handle_file_created(event)
        elif event.event_type == EventType.FILE_MODIFIED:
            self._handle_file_modified(event)

    def _handle_created(self, event: Event) -> None:
        with self._lock:
            self._events_processed += 1
            pid = event.process_id or 0
            ppid = event.parent_process_id or 0
            name = event.process_name or ""
            ts = _parse_iso_to_epoch(event.timestamp) or time.time()

            record = ProcessRecord(pid=pid, ppid=ppid, name=name, started_at=ts)
            self._processes[pid] = record

            if ppid:
                self._parent_children[ppid].append((ts, pid))
                self._purge_parent_window(ppid, ts)
                parent = self._processes.get(ppid)
                if parent:
                    parent.children_pids.append(pid)
                    children_in_window = len(self._parent_children[ppid])
                    if children_in_window > self._child_threshold:
                        self._record_anomaly(
                            parent,
                            f"rapid_spawning: {children_in_window} children in "
                            f"{self._child_window_seconds:.0f}s",
                            event,
                        )
                    child_basename = name.lower()
                    if "/" in child_basename:
                        child_basename = child_basename.rsplit("/", 1)[-1]
                    if child_basename in _SUSPICIOUS_CHILD_NAMES:
                        self._record_anomaly(
                            parent,
                            f"suspicious_child: spawned {child_basename!r} "
                            f"(living-off-the-land interpreter)",
                            event,
                        )

            if name and _SUSPICIOUS_NAME_RE.search(name):
                self._record_anomaly(
                    record,
                    f"suspicious_name: {name!r} matches malware-like pattern",
                    event,
                )

    def _handle_file_created(self, event: Event) -> None:
        with self._lock:
            self._events_processed += 1
            pid = event.process_id or 0
            record = self._processes.get(pid)
            if record is None:
                return
            ts = _parse_iso_to_epoch(event.timestamp) or time.time()
            path = event.file_path or ""
            record.files_created.append((ts, path))

            self._check_persistence(record, path, event)

            cutoff = ts - self._mass_create_window
            recent = [p for (t, p) in record.files_created if t >= cutoff]
            if len(recent) >= self._mass_create_threshold:
                self._record_anomaly(
                    record,
                    f"mass_file_creation: {len(recent)} files created in "
                    f"{self._mass_create_window:.0f}s (ransomware-like)",
                    event,
                )

    def _handle_file_modified(self, event: Event) -> None:
        with self._lock:
            self._events_processed += 1
            pid = event.process_id or 0
            record = self._processes.get(pid)
            if record is None:
                return
            ts = _parse_iso_to_epoch(event.timestamp) or time.time()
            path = event.file_path or ""
            record.files_modified.append((ts, path))

            self._check_persistence(record, path, event)

            cutoff = ts - self._mass_modify_window
            recent = [p for (t, p) in record.files_modified if t >= cutoff]
            if len(recent) >= self._mass_modify_threshold:
                self._record_anomaly(
                    record,
                    f"mass_file_modification: {len(recent)} files modified in "
                    f"{self._mass_modify_window:.0f}s (mass encryption)",
                    event,
                )

    def _check_persistence(self, record: ProcessRecord, path: str, event: Event) -> None:
        """Phase 11: detect writes to known autostart/persistence locations."""
        if not path:
            return
        import os
        home = os.environ.get("HOME", "")
        expanded = path.replace("~", home, 1) if path.startswith("~") else path
        for pfx in _PERSISTENCE_PATHS:
            pfx_expanded = pfx.replace("~", home, 1) if pfx.startswith("~") else pfx
            if expanded.startswith(pfx_expanded) or path.startswith(pfx):
                if pfx not in record.persistence_writes:
                    record.persistence_writes.append(pfx)
                    self._record_anomaly(
                        record,
                        f"persistence_install: wrote to {path!r} "
                        f"(autostart location: {pfx})",
                        event,
                    )
                    return

    def _handle_terminated(self, event: Event) -> None:
        with self._lock:
            pid = event.process_id or 0
            ts = _parse_iso_to_epoch(event.timestamp) or time.time()
            record = self._processes.get(pid)
            if record is None:
                return
            record.terminated_at = ts
            life = record.lifetime_seconds
            if life is not None and life < self._short_lived_seconds:
                self._record_anomaly(
                    record,
                    f"short_lived: process exited after {life:.2f}s "
                    f"(threshold={self._short_lived_seconds}s)",
                    event,
                )

    def _record_anomaly(self, record: ProcessRecord, message: str, event: Event) -> None:
        record.anomalies.append(message)
        self._anomalies_detected += 1
        logger.info("Behavior anomaly: pid=%d name=%s msg=%s", record.pid, record.name, message)
        self._bus.publish(Event(
            event_type=EventType.SECURITY_ALERT,
            source=self.name,
            severity=Severity.WARNING,
            process_id=record.pid,
            process_name=record.name,
            parent_process_id=record.ppid,
            metadata={
                "anomaly": message,
                "pid": record.pid,
                "ppid": record.ppid,
                "name": record.name,
                "linked_event_id": event.event_id,
            },
        ))

    def _purge_parent_window(self, ppid: int, now: float) -> None:
        cutoff = now - self._child_window_seconds
        window = self._parent_children[ppid]
        while window and window[0][0] < cutoff:
            window.popleft()

    def list_tracked(self) -> List[Dict]:
        with self._lock:
            return [
                {
                    "pid": r.pid,
                    "ppid": r.ppid,
                    "name": r.name,
                    "started_at": r.started_at,
                    "terminated_at": r.terminated_at,
                    "lifetime_seconds": r.lifetime_seconds,
                    "children_count": len(r.children_pids),
                    "anomalies": list(r.anomalies),
                }
                for r in self._processes.values()
            ]

    def get_anomalies(self) -> List[Dict]:
        with self._lock:
            out = []
            for r in self._processes.values():
                for a in r.anomalies:
                    out.append({
                        "pid": r.pid,
                        "ppid": r.ppid,
                        "name": r.name,
                        "anomaly": a,
                    })
            return out


def _parse_iso_to_epoch(iso: str) -> Optional[float]:
    try:
        s = iso.rstrip("Z")
        dt = time.strptime(s, "%Y-%m-%dT%H:%M:%S.%f")
        return time.mktime(dt) - time.timezone
    except Exception:
        try:
            dt = time.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
            return time.mktime(dt) - time.timezone
        except Exception:
            return None
