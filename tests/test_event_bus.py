"""Unit tests for itshield.events.bus.EventBus and itshield.events.models."""

from __future__ import annotations

from itshield.events.bus import EventBus
from itshield.events.models import Event, EventType, Severity


def test_event_serializes_to_dict_and_back() -> None:
    e = Event(
        event_type=EventType.PROCESS_CREATED,
        source="process_monitor",
        severity=Severity.INFO,
        process_id=1234,
        process_name="example.exe",
        parent_process_id=500,
    )
    d = e.to_dict()
    assert d["event_type"] == "PROCESS_CREATED"
    assert d["severity"] == "INFO"
    assert d["process_id"] == 1234

    e2 = Event.from_dict(d)
    assert e2.event_type == EventType.PROCESS_CREATED
    assert e2.process_name == "example.exe"


def test_eventbus_subscribe_and_publish() -> None:
    bus = EventBus()
    received = []
    bus.subscribe(lambda e: received.append(e))

    e = Event(event_type=EventType.FILE_CREATED, source="t")
    bus.publish(e)
    assert len(received) == 1
    assert received[0].event_type == EventType.FILE_CREATED


def test_eventbus_subscribe_specific_type() -> None:
    bus = EventBus()
    file_events = []
    proc_events = []
    bus.subscribe(lambda e: file_events.append(e), EventType.FILE_CREATED)
    bus.subscribe(lambda e: proc_events.append(e), EventType.PROCESS_CREATED)

    bus.publish(Event(event_type=EventType.FILE_CREATED, source="t"))
    bus.publish(Event(event_type=EventType.PROCESS_CREATED, source="t"))
    bus.publish(Event(event_type=EventType.FILE_DELETED, source="t"))

    assert len(file_events) == 1
    assert len(proc_events) == 1


def test_eventbus_subscriber_failure_isolated() -> None:
    bus = EventBus()
    good_calls = []

    def bad(_):
        raise RuntimeError("boom")

    bus.subscribe(bad)
    bus.subscribe(lambda e: good_calls.append(e))

    bus.publish(Event(event_type=EventType.FILE_CREATED, source="t"))
    assert len(good_calls) == 1  # second subscriber still got the event


def test_eventbus_unsubscribe() -> None:
    bus = EventBus()
    received = []
    unsub = bus.subscribe(lambda e: received.append(e))
    bus.publish(Event(event_type=EventType.FILE_CREATED, source="t"))
    assert len(received) == 1
    unsub()
    bus.publish(Event(event_type=EventType.FILE_CREATED, source="t"))
    assert len(received) == 1  # no new event after unsubscribe


def test_eventbus_stats() -> None:
    bus = EventBus()
    bus.subscribe(lambda e: None)
    bus.publish(Event(event_type=EventType.FILE_CREATED, source="t"))
    s = bus.stats()
    assert s["published_total"] == 1
    assert s["delivered_total"] == 1
    assert s["subscribers"] == 1
