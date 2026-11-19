"""Correlation Engine - links related events into Incidents (Phase 7).

Section 16 of the architecture document.

The engine subscribes to the EventBus and keeps a sliding window of
recent events. Rule functions inspect the window and emit an Incident
(via :class:`IncidentManager`) whenever a suspicious pattern is found.

Rules implemented in this version:

    * ``process_then_network`` - a process is created and within 30 seconds
      makes an outbound network connection to a non-private address.
      Severity: MEDIUM.

    * ``rapid_file_modifications`` - more than 20 FILE_MODIFIED events on
      distinct paths within 10 seconds. Indicates ransomware-like
      behavior. Severity: HIGH.

    * ``executable_dropped_then_run`` - a PE/ELF file is created and
      within 5 seconds a process with the same name appears.
      Severity: MEDIUM.

    * ``threat_then_more_threats`` - multiple THREAT_DETECTED events on
      different files within 60 seconds. Severity: CRITICAL.

The window size, rule timeouts and severity are configurable. Rules
are pure functions of (window, manager) so adding a new rule is a
matter of writing one function and registering it.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, List, Optional, Tuple

from itshield.events.bus import EventBus
from itshield.events.models import Event, EventType, Severity
from itshield.incidents.manager import (
    IncidentManager,
    IncidentSeverity,
)
from itshield.logging.logger import get_logger

logger = get_logger(__name__)


Rule = Callable[[Deque["Event"], IncidentManager], int]


@dataclass
class _RuleStats:
    name: str
    fires: int = 0
    incidents: int = 0


class CorrelationEngine:
    """Subscribes to events and runs rules over a sliding window."""

    name = "correlation_engine"
    dependencies: tuple[str, ...] = ("event_bus",)

    def __init__(
        self,
        bus: EventBus,
        incident_manager: IncidentManager,
        window_seconds: float = 60.0,
        max_window_size: int = 5000,
        poll_interval: float = 1.0,
    ) -> None:
        self._bus = bus
        self._manager = incident_manager
        self._window_seconds = window_seconds
        self._max_window_size = max_window_size
        self._poll_interval = poll_interval

        self._window: Deque[Event] = deque(maxlen=max_window_size)
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._unsubscribe: Optional[Callable[[], None]] = None
        self._rules: List[Tuple[str, Rule]] = []
        self._rule_stats: dict[str, _RuleStats] = {}
        self._events_processed = 0
        self._incidents_created = 0

        self.register_rule("process_then_network", _rule_process_then_network)
        self.register_rule("rapid_file_modifications", _rule_rapid_file_modifications)
        self.register_rule("executable_dropped_then_run", _rule_executable_dropped_then_run)
        self.register_rule("threat_then_more_threats", _rule_threat_then_more_threats)
        self.register_rule("c2_beaconing", _rule_c2_beaconing)  # Phase 8

    def register_rule(self, name: str, rule: Rule) -> None:
        self._rules.append((name, rule))
        self._rule_stats[name] = _RuleStats(name=name)

    @property
    def rule_names(self) -> List[str]:
        return [name for name, _ in self._rules]

    def start(self) -> None:
        self._stop_event.clear()
        self._unsubscribe = self._bus.subscribe(self._on_event)
        self._thread = threading.Thread(
            target=self._run_loop, name="correlation-engine", daemon=True
        )
        self._thread.start()
        logger.info(
            "CorrelationEngine started (window=%ds, rules=%d)",
            int(self._window_seconds), len(self._rules),
        )

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        if self._unsubscribe is not None:
            self._unsubscribe()
            self._unsubscribe = None
        logger.info(
            "CorrelationEngine stopped (events_processed=%d, incidents_created=%d)",
            self._events_processed, self._incidents_created,
        )

    def health(self) -> dict:
        with self._lock:
            return {
                "running": self._thread is not None and self._thread.is_alive(),
                "events_processed": self._events_processed,
                "incidents_created": self._incidents_created,
                "window_size": len(self._window),
                "rules": [
                    {"name": s.name, "fires": s.fires, "incidents": s.incidents}
                    for s in self._rule_stats.values()
                ],
            }

    def _on_event(self, event: Event) -> None:
        with self._lock:
            self._window.append(event)
            self._events_processed += 1

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._purge_old_events()
                self._run_rules()
            except Exception:
                logger.exception("CorrelationEngine cycle failed")
            self._stop_event.wait(self._poll_interval)

    def _purge_old_events(self) -> None:
        cutoff = time.time() - self._window_seconds
        with self._lock:
            while self._window:
                e = self._window[0]
                ts = _parse_iso_to_epoch(e.timestamp)
                if ts is None or ts >= cutoff:
                    break
                self._window.popleft()

    def _run_rules(self) -> None:
        with self._lock:
            snapshot = list(self._window)
        for name, rule in self._rules:
            try:
                view: Deque[Event] = deque(snapshot)
                created = rule(view, self._manager)
            except Exception:
                logger.exception("Rule %s raised; isolating", name)
                continue
            stats = self._rule_stats[name]
            if created:
                stats.fires += 1
                stats.incidents += created
                self._incidents_created += created


def _parse_iso_to_epoch(iso: str) -> Optional[float]:
    """Best-effort ISO-8601 -> epoch seconds. Returns None on failure."""
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


def _is_private_ip(addr: str) -> bool:
    """True for loopback / RFC1918 / link-local addresses."""
    if not addr or addr in ("0.0.0.0", "::"):
        return True
    if addr.startswith("127.") or addr == "::1":
        return True
    if addr.startswith("10."):
        return True
    if addr.startswith("192.168."):
        return True
    if addr.startswith("172."):
        try:
            second = int(addr.split(".")[1])
            if 16 <= second <= 31:
                return True
        except (IndexError, ValueError):
            pass
    if addr.startswith("169.254."):
        return True
    if addr.startswith("fe80:") or addr.startswith("fc") or addr.startswith("fd"):
        return True
    return False


def _rule_process_then_network(window: Deque[Event], manager: IncidentManager) -> int:
    """Process created + outbound network connection within 30s."""
    created = 0
    process_events = [e for e in window if e.event_type == EventType.PROCESS_CREATED]
    network_events = [e for e in window if e.event_type == EventType.NETWORK_CONNECTION]

    for proc in process_events:
        proc_ts = _parse_iso_to_epoch(proc.timestamp)
        if proc_ts is None:
            continue
        for net in network_events:
            net_ts = _parse_iso_to_epoch(net.timestamp)
            if net_ts is None:
                continue
            if net_ts < proc_ts or net_ts > proc_ts + 30:
                continue
            remote = net.metadata.get("remote_addr", "")
            if _is_private_ip(remote):
                continue
            manager.create(
                title="Process made outbound network connection",
                summary=(
                    f"Process {proc.process_name!r} (pid={proc.process_id}) "
                    f"created at {proc.timestamp} connected to "
                    f"{remote}:{net.metadata.get('remote_port')} at {net.timestamp}."
                ),
                severity=IncidentSeverity.MEDIUM,
                rule_name="process_then_network",
                linked_event_ids=[proc.event_id, net.event_id],
                metadata={
                    "process_name": proc.process_name,
                    "process_id": proc.process_id,
                    "remote_addr": remote,
                    "remote_port": net.metadata.get("remote_port"),
                },
            )
            created += 1
            break  # one incident per process
    return created


def _rule_rapid_file_modifications(window: Deque[Event], manager: IncidentManager) -> int:
    """>20 FILE_MODIFIED events on distinct paths in 10s -> ransomware-like."""
    mods = [e for e in window if e.event_type == EventType.FILE_MODIFIED]
    if len(mods) < 20:
        return 0
    buckets: dict[float, set[str]] = {}
    for e in mods:
        ts = _parse_iso_to_epoch(e.timestamp)
        if ts is None:
            continue
        bucket = int(ts // 10) * 10
        buckets.setdefault(bucket, set()).add(e.file_path or "")

    created = 0
    for bucket, paths in buckets.items():
        if len(paths) >= 20:
            manager.create(
                title="Rapid file modifications detected (ransomware-like)",
                summary=(
                    f"{len(paths)} distinct files modified within 10 seconds "
                    f"(bucket starting at epoch {bucket}). This pattern is "
                    f"characteristic of ransomware or mass-encryption attacks."
                ),
                severity=IncidentSeverity.HIGH,
                rule_name="rapid_file_modifications",
                linked_event_ids=[e.event_id for e in mods if e.file_path in paths][:50],
                metadata={"file_count": len(paths), "bucket_epoch": bucket},
            )
            created += 1
    return created


def _rule_executable_dropped_then_run(window: Deque[Event], manager: IncidentManager) -> int:
    """An executable file is created and a process with the same name appears within 5s."""
    created_files = [e for e in window if e.event_type == EventType.FILE_CREATED]
    procs = [e for e in window if e.event_type == EventType.PROCESS_CREATED]

    created = 0
    for f in created_files:
        path = f.file_path or ""
        if not path:
            continue
        lower = path.lower()
        if not (lower.endswith((".exe", ".elf", ".bin", ".sh")) or "/tmp/" in lower):
            continue
        name = path.rsplit("/", 1)[-1]
        f_ts = _parse_iso_to_epoch(f.timestamp)
        if f_ts is None:
            continue
        for p in procs:
            p_ts = _parse_iso_to_epoch(p.timestamp)
            if p_ts is None:
                continue
            if p_ts < f_ts or p_ts > f_ts + 5:
                continue
            if p.process_name and name.startswith(p.process_name.split(".")[0]):
                manager.create(
                    title="Executable dropped and immediately executed",
                    summary=(
                        f"File {path!r} was created at {f.timestamp} and a "
                        f"process named {p.process_name!r} (pid={p.process_id}) "
                        f"appeared within 5 seconds."
                    ),
                    severity=IncidentSeverity.MEDIUM,
                    rule_name="executable_dropped_then_run",
                    linked_event_ids=[f.event_id, p.event_id],
                    metadata={
                        "file_path": path,
                        "process_name": p.process_name,
                        "process_id": p.process_id,
                    },
                )
                created += 1
                break
    return created


def _rule_threat_then_more_threats(window: Deque[Event], manager: IncidentManager) -> int:
    """Multiple THREAT_DETECTED events in 60s -> active outbreak."""
    threats = [e for e in window if e.event_type == EventType.THREAT_DETECTED]
    if len(threats) < 2:
        return 0
    buckets: dict[float, list[Event]] = {}
    for e in threats:
        ts = _parse_iso_to_epoch(e.timestamp)
        if ts is None:
            continue
        bucket = int(ts // 60) * 60
        buckets.setdefault(bucket, []).append(e)

    created = 0
    for bucket, evs in buckets.items():
        if len(evs) >= 2:
            files = [e.file_path for e in evs if e.file_path]
            manager.create(
                title="Multiple threats detected in short window",
                summary=(
                    f"{len(evs)} threats detected within 60 seconds "
                    f"(bucket starting at epoch {bucket}). Files: "
                    + ", ".join(files[:5])
                ),
                severity=IncidentSeverity.CRITICAL,
                rule_name="threat_then_more_threats",
                linked_event_ids=[e.event_id for e in evs],
                metadata={"threat_count": len(evs), "files": files},
            )
            created += 1
    return created


def _rule_c2_beaconing(window: Deque[Event], manager: IncidentManager) -> int:
    """Phase 8: detect C2 beaconing - regular periodic connections to same IP.

    A beaconing pattern is defined as >= 3 NETWORK_CONNECTION events from
    the same process to the same remote IP where the coefficient of
    variation of inter-arrival times is < 0.3 (i.e., the connections are
    happening at a near-constant interval). This is a hallmark of malware
    polling a C2 server for instructions.
    """
    nets = [e for e in window if e.event_type == EventType.NETWORK_CONNECTION]
    if len(nets) < 3:
        return 0

    groups: dict[tuple[Optional[int], str], list[float]] = {}
    for e in nets:
        ts = _parse_iso_to_epoch(e.timestamp)
        if ts is None:
            continue
        remote = e.metadata.get("remote_addr", "")
        if not remote or _is_private_ip(remote):
            continue
        key = (e.process_id, remote)
        groups.setdefault(key, []).append(ts)

    created = 0
    for (pid, remote), timestamps in groups.items():
        if len(timestamps) < 3:
            continue
        timestamps.sort()
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        if not intervals:
            continue
        mean = sum(intervals) / len(intervals)
        if mean <= 0:
            continue
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        stddev = variance ** 0.5
        cov = stddev / mean
        if cov < 0.3:
            manager.create(
                title="C2 beaconing pattern detected",
                summary=(
                    f"Process pid={pid} made {len(timestamps)} connections to "
                    f"{remote} at a near-constant interval (mean={mean:.1f}s, "
                    f"cov={cov:.3f}). This pattern is characteristic of C2 "
                    f"beaconing."
                ),
                severity=IncidentSeverity.HIGH,
                rule_name="c2_beaconing",
                linked_event_ids=[],  # we don't have event_ids for synthetic test events
                metadata={
                    "process_id": pid,
                    "remote_addr": remote,
                    "connection_count": len(timestamps),
                    "mean_interval_seconds": round(mean, 2),
                    "coefficient_of_variation": round(cov, 3),
                },
            )
            created += 1
    return created
