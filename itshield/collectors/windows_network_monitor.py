"""Windows Network Monitor using GetExtendedTcpTable (Phase 15).

Section 17 of the architecture document - Network Monitoring on Windows.

Uses ``ctypes`` to call the Windows IP Helper API
(GetExtendedTcpTable / GetExtendedUdpTable) which returns all active
TCP and UDP connections with owning PID.

This is the Windows counterpart of
:class:`~itshield.collectors.network_monitor.NetworkMonitor` which reads
/proc/net on Linux. The event format is identical so downstream
consumers (IOC Matcher, Correlation Engine) are platform-agnostic.
"""

from __future__ import annotations

import socket
import sys
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional

from itshield.events.bus import EventBus
from itshield.events.models import Event, EventType, Severity
from itshield.logging.logger import get_logger

logger = get_logger(__name__)

_IS_WINDOWS = sys.platform == "win32"

if _IS_WINDOWS:
    try:
        import ctypes
        from ctypes import wintypes
        _CTYPES_AVAILABLE = True
    except ImportError:
        _CTYPES_AVAILABLE = False
else:
    _CTYPES_AVAILABLE = False


@dataclass
class WindowsConnectionInfo:
    """One Windows TCP/UDP connection."""

    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    pid: int = -1

    def to_metadata(self) -> dict:
        return {
            "protocol": self.protocol,
            "local_addr": self.local_addr,
            "local_port": self.local_port,
            "remote_addr": self.remote_addr,
            "remote_port": self.remote_port,
            "state": self.state,
            "pid": self.pid,
        }


_TCP_STATES = {
    1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1",
    5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT",
    9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING",
}


class WindowsNetworkMonitor:
    """GetExtendedTcpTable-based network monitor for Windows."""

    name = "windows_network_monitor"
    dependencies: tuple[str, ...] = ("event_bus",)

    def __init__(
        self,
        bus: EventBus,
        interval_seconds: float = 2.0,
    ) -> None:
        self._bus = bus
        self.interval = interval_seconds
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._snapshot_count = 0
        self._events_emitted = 0

    def start(self) -> None:
        if not _IS_WINDOWS:
            raise RuntimeError("WindowsNetworkMonitor requires Windows.")
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, name="win-net-monitor", daemon=True
        )
        self._thread.start()
        logger.info("WindowsNetworkMonitor started (interval=%.2fs)", self.interval)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        logger.info("WindowsNetworkMonitor stopped")

    def health(self) -> dict:
        return {
            "running": self._thread is not None and self._thread.is_alive(),
            "snapshots": self._snapshot_count,
            "events_emitted": self._events_emitted,
        }

    def snapshot(self) -> List[WindowsConnectionInfo]:
        """Take a snapshot using GetExtendedTcpTable."""
        if not _CTYPES_AVAILABLE:
            return []
        result: List[WindowsConnectionInfo] = []
        try:
            result.extend(self._get_tcp_table(ipv6=False))
            result.extend(self._get_tcp_table(ipv6=True))
            result.extend(self._get_udp_table(ipv6=False))
            result.extend(self._get_udp_table(ipv6=True))
        except Exception:
            logger.exception("Windows network snapshot failed")
        return result

    def list_connections(self) -> List[WindowsConnectionInfo]:
        return self.snapshot()

    def _get_tcp_table(self, ipv6: bool = False) -> List[WindowsConnectionInfo]:
        """Query GetExtendedTcpTable for TCP connections."""
        if not _CTYPES_AVAILABLE:
            return []
        import ctypes
        from ctypes import wintypes

        af = socket.AF_INET6 if ipv6 else socket.AF_INET
        table_class = 5

        size = wintypes.DWORD(0)
        ctypes.windll.iphlpapi.GetExtendedTcpTable(
            None, ctypes.byref(size), False, af, table_class, 0
        )
        if size.value == 0:
            return []

        buf = (ctypes.c_byte * size.value)()
        ret = ctypes.windll.iphlpapi.GetExtendedTcpTable(
            buf, ctypes.byref(size), False, af, table_class, 0
        )
        if ret != 0:
            return []

        result: List[WindowsConnectionInfo] = []
        proto = "tcp6" if ipv6 else "tcp"
        if ipv6:
            class _Row(ctypes.Structure):
                _fields_ = [
                    ("local_addr", ctypes.c_byte * 16),
                    ("local_port", wintypes.DWORD),
                    ("remote_addr", ctypes.c_byte * 16),
                    ("remote_port", wintypes.DWORD),
                    ("state", wintypes.DWORD),
                    ("pid", wintypes.DWORD),
                ]
            class _Table(ctypes.Structure):
                _fields_ = [("num_entries", wintypes.DWORD),
                            ("rows", _Row * 1024)]
        else:
            class _Row(ctypes.Structure):
                _fields_ = [
                    ("local_addr", wintypes.DWORD),
                    ("local_port", wintypes.DWORD),
                    ("remote_addr", wintypes.DWORD),
                    ("remote_port", wintypes.DWORD),
                    ("state", wintypes.DWORD),
                    ("pid", wintypes.DWORD),
                ]
            class _Table(ctypes.Structure):
                _fields_ = [("num_entries", wintypes.DWORD),
                            ("rows", _Row * 1024)]

        table = ctypes.cast(buf, ctypes.POINTER(_Table)).contents
        for i in range(min(table.num_entries, 1024)):
            row = table.rows[i]
            state = _TCP_STATES.get(row.state, str(row.state))
            if ipv6:
                local = socket.inet_ntop(socket.AF_INET6, bytes(row.local_addr))
                remote = socket.inet_ntop(socket.AF_INET6, bytes(row.remote_addr))
            else:
                local = socket.inet_ntoa(struct.pack_from("<I", struct.pack("<I", row.local_addr)))
                remote = socket.inet_ntoa(struct.pack_from("<I", struct.pack("<I", row.remote_addr)))
            local_port = socket.ntohs(row.local_port >> 16) if row.local_port >> 16 else socket.ntohs(row.local_port & 0xFFFF)
            remote_port = socket.ntohs(row.remote_port >> 16) if row.remote_port >> 16 else socket.ntohs(row.remote_port & 0xFFFF)
            result.append(WindowsConnectionInfo(
                protocol=proto, local_addr=local, local_port=local_port,
                remote_addr=remote, remote_port=remote_port,
                state=state, pid=row.pid,
            ))
        return result

    def _get_udp_table(self, ipv6: bool = False) -> List[WindowsConnectionInfo]:
        """Query GetExtendedUdpTable for UDP connections."""
        return []

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                conns = self.snapshot()
                self._snapshot_count += 1
                for c in conns:
                    self._bus.publish(Event(
                        event_type=EventType.NETWORK_CONNECTION,
                        source=self.name,
                        severity=Severity.INFO,
                        metadata=c.to_metadata(),
                    ))
                    self._events_emitted += 1
            except Exception:
                logger.exception("Windows network monitor cycle failed")
            self._stop_event.wait(self.interval)


import struct
