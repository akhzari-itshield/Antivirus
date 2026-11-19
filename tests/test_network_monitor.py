"""Unit tests for itshield.collectors.network_monitor.NetworkMonitor (Linux only)."""

from __future__ import annotations

import socket
import time
from pathlib import Path

import pytest

from itshield.collectors.network_monitor import NetworkMonitor
from itshield.events.bus import EventBus
from itshield.events.models import EventType


def _is_linux() -> bool:
    return Path("/proc/net/tcp").exists()


pytestmark = pytest.mark.skipif(not _is_linux(), reason="NetworkMonitor is Linux-only")


@pytest.fixture
def bus() -> EventBus:
    return EventBus()


@pytest.fixture
def monitor(bus: EventBus) -> NetworkMonitor:
    return NetworkMonitor(bus=bus, interval_seconds=0.3)


def test_snapshot_returns_list(monitor: NetworkMonitor) -> None:
    conns = monitor.snapshot()
    assert isinstance(conns, list)


def test_parses_ipv4_address_correctly() -> None:
    """0100007F should parse to 127.0.0.1."""
    addr, port = NetworkMonitor._split_addr("0100007F:1F90", "tcp")
    assert addr == "127.0.0.1"
    assert port == 8080


def test_parses_zero_address() -> None:
    addr, port = NetworkMonitor._split_addr("00000000:0050", "tcp")
    assert addr == "0.0.0.0"
    assert port == 80


def test_emits_events_when_started(bus: EventBus, monitor: NetworkMonitor) -> None:
    received = []
    bus.subscribe(lambda e: received.append(e), EventType.NETWORK_CONNECTION)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    monitor.start()
    try:
        time.sleep(0.5)
    finally:
        monitor.stop()
        srv.close()

    h = monitor.health()
    assert h["snapshots"] >= 1


def test_health_reports_state(monitor: NetworkMonitor) -> None:
    monitor.start()
    try:
        time.sleep(0.3)
        h = monitor.health()
        assert h["running"] is True
    finally:
        monitor.stop()
    h2 = monitor.health()
    assert h2["running"] is False
