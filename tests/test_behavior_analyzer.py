"""Unit tests for itshield.detection.behavior_analyzer.BehaviorAnalyzer."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from itshield.detection.behavior_analyzer import BehaviorAnalyzer
from itshield.events.bus import EventBus
from itshield.events.models import Event, EventType, Severity


@pytest.fixture
def bus() -> EventBus:
    return EventBus()


@pytest.fixture
def analyzer(bus: EventBus) -> BehaviorAnalyzer:
    return BehaviorAnalyzer(bus=bus, child_threshold=3, child_window_seconds=10.0)


def _ts(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def test_starts_and_stops(analyzer: BehaviorAnalyzer) -> None:
    analyzer.start()
    try:
        assert analyzer.health()["running"] is True
    finally:
        analyzer.stop()
    assert analyzer.health()["running"] is False


def test_records_process_creation(analyzer: BehaviorAnalyzer) -> None:
    analyzer.start()
    try:
        analyzer._on_event(Event(
            event_type=EventType.PROCESS_CREATED,
            source="test", process_id=100, parent_process_id=1,
            process_name="test_proc", timestamp=_ts(time.time()),
        ))
        tracked = analyzer.list_tracked()
        assert len(tracked) == 1
        assert tracked[0]["pid"] == 100
        assert tracked[0]["name"] == "test_proc"
    finally:
        analyzer.stop()


def test_detects_rapid_spawning(analyzer: BehaviorAnalyzer, bus: EventBus) -> None:
    """Parent spawns > threshold children -> anomaly."""
    alerts: list = []
    bus.subscribe(lambda e: alerts.append(e), EventType.SECURITY_ALERT)
    analyzer.start()
    try:
        t0 = time.time()
        analyzer._on_event(Event(
            event_type=EventType.PROCESS_CREATED, source="test",
            process_id=1000, parent_process_id=1, process_name="parent",
            timestamp=_ts(t0),
        ))
        for i in range(4):
            analyzer._on_event(Event(
                event_type=EventType.PROCESS_CREATED, source="test",
                process_id=2000 + i, parent_process_id=1000,
                process_name=f"child_{i}", timestamp=_ts(t0 + i * 0.1),
            ))
        assert len(alerts) >= 1
        assert "rapid_spawning" in alerts[0].metadata["anomaly"]
    finally:
        analyzer.stop()


def test_detects_short_lived(analyzer: BehaviorAnalyzer, bus: EventBus) -> None:
    """Process exits within 2s of creation -> short_lived anomaly."""
    alerts: list = []
    bus.subscribe(lambda e: alerts.append(e), EventType.SECURITY_ALERT)
    analyzer.start()
    try:
        t0 = time.time()
        analyzer._on_event(Event(
            event_type=EventType.PROCESS_CREATED, source="test",
            process_id=500, parent_process_id=1, process_name="flash",
            timestamp=_ts(t0),
        ))
        analyzer._on_event(Event(
            event_type=EventType.PROCESS_TERMINATED, source="test",
            process_id=500, process_name="flash",
            timestamp=_ts(t0 + 0.5),
        ))
        assert any("short_lived" in a.metadata["anomaly"] for a in alerts)
    finally:
        analyzer.stop()


def test_detects_suspicious_name(analyzer: BehaviorAnalyzer, bus: EventBus) -> None:
    """Process name matching a malware-like pattern triggers anomaly."""
    alerts: list = []
    bus.subscribe(lambda e: alerts.append(e), EventType.SECURITY_ALERT)
    analyzer.start()
    try:
        analyzer._on_event(Event(
            event_type=EventType.PROCESS_CREATED, source="test",
            process_id=700, parent_process_id=1,
            process_name="invoice.pdf.exe",  # double extension
            timestamp=_ts(time.time()),
        ))
        assert any("suspicious_name" in a.metadata["anomaly"] for a in alerts)
    finally:
        analyzer.stop()


def test_normal_process_does_not_trigger(analyzer: BehaviorAnalyzer, bus: EventBus) -> None:
    alerts: list = []
    bus.subscribe(lambda e: alerts.append(e), EventType.SECURITY_ALERT)
    analyzer.start()
    try:
        analyzer._on_event(Event(
            event_type=EventType.PROCESS_CREATED, source="test",
            process_id=800, parent_process_id=1, process_name="firefox",
            timestamp=_ts(time.time()),
        ))
        assert len(alerts) == 0
    finally:
        analyzer.stop()
