"""Unit tests for itshield.detection.correlation_engine.CorrelationEngine."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from itshield.detection.correlation_engine import (
    CorrelationEngine,
    _is_private_ip,
    _rule_process_then_network,
    _rule_rapid_file_modifications,
    _rule_threat_then_more_threats,
)
from itshield.events.bus import EventBus
from itshield.events.models import Event, EventType, Severity
from itshield.incidents.manager import IncidentManager, IncidentSeverity, IncidentState
from itshield.storage.database import Database
from itshield.storage.migrations import run_migrations


@pytest.fixture
def bus() -> EventBus:
    return EventBus()


@pytest.fixture
def manager(tmp_project: Path) -> IncidentManager:
    db = Database(tmp_project / "data" / "corr.db")
    run_migrations(db)
    yield IncidentManager(db=db)
    db.close()


def _ts(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def test_is_private_ip() -> None:
    assert _is_private_ip("127.0.0.1")
    assert _is_private_ip("10.0.0.1")
    assert _is_private_ip("192.168.1.1")
    assert _is_private_ip("172.16.0.1")
    assert _is_private_ip("169.254.1.1")
    assert _is_private_ip("::1")
    assert not _is_private_ip("8.8.8.8")
    assert not _is_private_ip("1.1.1.1")


def test_rule_process_then_network_creates_incident(manager: IncidentManager) -> None:
    t0 = time.time()
    proc = Event(
        event_type=EventType.PROCESS_CREATED,
        source="test",
        process_id=1234,
        process_name="bad.exe",
        parent_process_id=1,
        timestamp=_ts(t0),
    )
    net = Event(
        event_type=EventType.NETWORK_CONNECTION,
        source="test",
        timestamp=_ts(t0 + 5),
        metadata={"remote_addr": "8.8.8.8", "remote_port": 443},
    )
    window = [proc, net]
    created = _rule_process_then_network(window, manager)
    assert created == 1
    incidents = manager.list_incidents()
    assert len(incidents) == 1
    assert incidents[0]["severity"] == "MEDIUM"


def test_rule_process_then_network_ignores_private(manager: IncidentManager) -> None:
    t0 = time.time()
    proc = Event(
        event_type=EventType.PROCESS_CREATED, source="test",
        process_id=1, process_name="ok",
        timestamp=_ts(t0),
    )
    net = Event(
        event_type=EventType.NETWORK_CONNECTION, source="test",
        timestamp=_ts(t0 + 5),
        metadata={"remote_addr": "127.0.0.1", "remote_port": 80},
    )
    assert _rule_process_then_network([proc, net], manager) == 0


def test_rule_rapid_file_modifications_triggers_at_threshold(manager: IncidentManager) -> None:
    t0 = time.time()
    mods = [
        Event(
            event_type=EventType.FILE_MODIFIED,
            source="test",
            file_path=f"/tmp/file_{i}.txt",
            timestamp=_ts(t0),
        )
        for i in range(25)
    ]
    created = _rule_rapid_file_modifications(mods, manager)
    assert created == 1
    incidents = manager.list_incidents()
    assert incidents[0]["severity"] == "HIGH"


def test_rule_rapid_file_modifications_below_threshold(manager: IncidentManager) -> None:
    t0 = time.time()
    mods = [
        Event(event_type=EventType.FILE_MODIFIED, source="test",
              file_path=f"/tmp/f{i}.txt", timestamp=_ts(t0))
        for i in range(10)
    ]
    assert _rule_rapid_file_modifications(mods, manager) == 0


def test_rule_threat_then_more_threats_triggers(manager: IncidentManager) -> None:
    t0 = time.time()
    threats = [
        Event(
            event_type=EventType.THREAT_DETECTED, source="test",
            file_path=f"/tmp/mal{i}.exe", severity=Severity.CRITICAL,
            timestamp=_ts(t0),
        )
        for i in range(3)
    ]
    created = _rule_threat_then_more_threats(threats, manager)
    assert created == 1
    incidents = manager.list_incidents()
    assert incidents[0]["severity"] == "CRITICAL"


def test_rule_threat_single_does_not_trigger(manager: IncidentManager) -> None:
    t0 = time.time()
    single = [Event(
        event_type=EventType.THREAT_DETECTED, source="test",
        file_path="/tmp/x.exe", severity=Severity.CRITICAL,
        timestamp=_ts(t0),
    )]
    assert _rule_threat_then_more_threats(single, manager) == 0


def test_engine_starts_and_stops(bus: EventBus, manager: IncidentManager) -> None:
    engine = CorrelationEngine(bus=bus, incident_manager=manager, poll_interval=0.2)
    engine.start()
    try:
        time.sleep(0.3)
        h = engine.health()
        assert h["running"] is True
        assert "process_then_network" in [r["name"] for r in h["rules"]]
    finally:
        engine.stop()
    assert engine.health()["running"] is False


def test_engine_processes_published_event(bus: EventBus, manager: IncidentManager) -> None:
    engine = CorrelationEngine(bus=bus, incident_manager=manager, poll_interval=0.2)
    engine.start()
    try:
        bus.publish(Event(
            event_type=EventType.NETWORK_CONNECTION,
            source="test",
            metadata={"remote_addr": "1.2.3.4", "remote_port": 443},
        ))
        time.sleep(0.5)
        assert engine.health()["events_processed"] >= 1
    finally:
        engine.stop()
