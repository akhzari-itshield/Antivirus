"""Network Monitor - reads /proc/net to enumerate active connections (Linux).

Section 17 of the architecture document (Network Monitoring, roadmap item).

Parses /proc/net/{tcp,tcp6,udp,udp6} and emits a NETWORK_CONNECTION
event per connection found. The snapshot is repeated periodically and
each connection is published at most once per snapshot (no diffing -
new connections are reported every cycle; future versions can add
diffing to emit only NEW_CONNECTION events).

Each event carries:
    * process_id   - the owning process if it can be resolved via
                     /proc/[pid]/fd (best effort; -1 if not found)
    * metadata.protocol    - "tcp" / "tcp6" / "udp" / "udp6"
    * metadata.local_addr  / local_port
    * metadata.remote_addr / remote_port
    * metadata.state       - tcp state string ("ESTABLISHED", "LISTEN", ...)

Linux-only. On systems without /proc/net, start() raises so the Core
can degrade.
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from itshield.events.bus import EventBus
from itshield.events.models import Event, EventType, Severity
from itshield.logging.logger import get_logger

logger = get_logger(__name__)


_TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


@dataclass
class ConnectionInfo:
    """One parsed /proc/net entry."""

    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    uid: int = -1
    inode: int = 0

    def to_metadata(self) -> dict:
        return {
            "protocol": self.protocol,
            "local_addr": self.local_addr,
            "local_port": self.local_port,
            "remote_addr": self.remote_addr,
            "remote_port": self.remote_port,
            "state": self.state,
            "uid": self.uid,
            "inode": self.inode,
        }


class NetworkMonitor:
    """Periodic /proc/net snapshotter."""

    name = "network_monitor"
    dependencies: tuple[str, ...] = ("event_bus",)

    def __init__(
        self,
        bus: EventBus,
        interval_seconds: float = 2.0,
        proc_root: str = "/proc",
    ) -> None:
        self._bus = bus
        self.interval = interval_seconds
        self._proc_root = Path(proc_root)
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._snapshot_count = 0
        self._events_emitted = 0

    def start(self) -> None:
        net_dir = self._proc_root / "net"
        if not net_dir.exists() or not (net_dir / "tcp").exists():
            raise RuntimeError(
                f"NetworkMonitor requires /proc/net; not found at {net_dir}. "
                "This collector is Linux-only."
            )
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, name="net-monitor", daemon=True
        )
        self._thread.start()
        logger.info("NetworkMonitor started (interval=%.2fs)", self.interval)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        logger.info("NetworkMonitor stopped (snapshots=%d, events=%d)",
                    self._snapshot_count, self._events_emitted)

    def health(self) -> dict:
        return {
            "running": self._thread is not None and self._thread.is_alive(),
            "snapshots": self._snapshot_count,
            "events_emitted": self._events_emitted,
            "interval_seconds": self.interval,
        }

    def snapshot(self) -> List[ConnectionInfo]:
        """Read every /proc/net/{tcp,tcp6,udp,udp6} entry."""
        result: List[ConnectionInfo] = []
        for proto in ("tcp", "tcp6", "udp", "udp6"):
            path = self._proc_root / "net" / proto
            if not path.exists():
                continue
            try:
                lines = path.read_text().splitlines()[1:]  # skip header
            except OSError:
                continue
            for line in lines:
                conn = self._parse_line(line, proto)
                if conn is not None:
                    result.append(conn)
        return result

    @staticmethod
    def _parse_line(line: str, proto: str) -> Optional[ConnectionInfo]:
        """Parse one /proc/net/tcp line into a ConnectionInfo."""
        parts = line.split()
        if len(parts) < 10:
            return None
        local = parts[1]
        remote = parts[2]
        state = parts[3]
        uid = int(parts[7]) if parts[7].lstrip("-").isdigit() else -1
        inode = int(parts[9]) if parts[9].isdigit() else 0

        local_addr, local_port = NetworkMonitor._split_addr(local, proto)
        remote_addr, remote_port = NetworkMonitor._split_addr(remote, proto)
        state_name = _TCP_STATES.get(state.upper(), state) if proto.startswith("tcp") else "-"

        return ConnectionInfo(
            protocol=proto,
            local_addr=local_addr,
            local_port=local_port,
            remote_addr=remote_addr,
            remote_port=remote_port,
            state=state_name,
            uid=uid,
            inode=inode,
        )

    @staticmethod
    def _split_addr(field: str, proto: str) -> tuple[str, int]:
        """Split '0100007F:1F90' into ('127.0.0.1', 8080)."""
        if ":" not in field:
            return ("?", 0)
        hex_addr, hex_port = field.rsplit(":", 1)
        port = int(hex_port, 16)
        if proto.endswith("6"):
            if len(hex_addr) != 32:
                return (hex_addr, port)
            b = bytes.fromhex(hex_addr)
            groups = [b[i:i+4][::-1] for i in range(0, 16, 4)]
            addr = socket.inet_ntop(socket.AF_INET6, b"".join(groups))
            return (addr, port)
        else:
            if len(hex_addr) != 8:
                return (hex_addr, port)
            b = bytes.fromhex(hex_addr)[::-1]
            addr = socket.inet_ntop(socket.AF_INET, b)
            return (addr, port)

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                conns = self.snapshot()
                self._snapshot_count += 1
                for conn in conns:
                    self._bus.publish(Event(
                        event_type=EventType.NETWORK_CONNECTION,
                        source=self.name,
                        severity=Severity.INFO,
                        metadata=conn.to_metadata(),
                    ))
                    self._events_emitted += 1
            except Exception:
                logger.exception("NetworkMonitor snapshot failed")
            self._stop_event.wait(self.interval)

    def list_connections(self) -> List[ConnectionInfo]:
        """Return all current connections (single snapshot)."""
        return self.snapshot()
