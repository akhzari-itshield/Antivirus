"""Unit tests for itshield.collectors.process_monitor.ProcessMonitor (Linux only)."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from itshield.collectors.process_monitor import ProcessMonitor
from itshield.events.bus import EventBus
from itshield.events.models import EventType


def _is_linux() -> bool:
    return Path("/proc").exists() and Path("/proc/self").exists()


pytestmark = pytest.mark.skipif(not _is_linux(), reason="ProcessMonitor is Linux-only")


@pytest.fixture
def bus() -> EventBus:
    return EventBus()


@pytest.fixture
def monitor(bus: EventBus) -> ProcessMonitor:
    return ProcessMonitor(bus=bus, interval_seconds=0.2)


def test_snapshot_returns_self_process(monitor: ProcessMonitor) -> None:
    snap = monitor.snapshot()
    assert os.getpid() in snap
    info = snap[os.getpid()]
    assert info.pid == os.getpid()
    assert info.ppid > 0
    assert info.name  # non-empty


def test_list_processes_is_non_empty(monitor: ProcessMonitor) -> None:
    procs = monitor.list_processes()
    assert len(procs) > 1
    pids = {p.pid for p in procs}
    assert 1 in pids or os.getpid() in pids


def test_emits_process_events_on_diff(bus: EventBus, monitor: ProcessMonitor) -> None:
    received = []
    bus.subscribe(lambda e: received.append(e), EventType.PROCESS_CREATED)
    monitor.start()
    import subprocess
    child = subprocess.Popen(["sleep", "2"])
    try:
        time.sleep(0.7)
    finally:
        child.terminate()
        child.wait()
        monitor.stop()

    types = {e.event_type for e in received}
    assert EventType.PROCESS_CREATED in types


def test_health_reports_running(monitor: ProcessMonitor) -> None:
    monitor.start()
    try:
        time.sleep(0.3)
        h = monitor.health()
        assert h["running"] is True
        assert h["snapshots"] >= 1
    finally:
        monitor.stop()
