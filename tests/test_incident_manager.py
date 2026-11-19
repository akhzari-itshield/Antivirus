"""Unit tests for itshield.incidents.manager.IncidentManager."""

from __future__ import annotations

from pathlib import Path

import pytest

from itshield.incidents.manager import (
    IncidentManager,
    IncidentSeverity,
    IncidentState,
)
from itshield.storage.database import Database
from itshield.storage.migrations import run_migrations


@pytest.fixture
def manager(tmp_project: Path) -> IncidentManager:
    db = Database(tmp_project / "data" / "inc.db")
    run_migrations(db)
    yield IncidentManager(db=db)
    db.close()


def test_create_incident_returns_open(manager: IncidentManager) -> None:
    inc = manager.create(
        title="Test incident",
        summary="something happened",
        severity=IncidentSeverity.HIGH,
        rule_name="rule_one",
        linked_event_ids=["ev1", "ev2"],
    )
    assert inc.state == IncidentState.OPEN
    assert inc.severity == IncidentSeverity.HIGH
    assert inc.rule_name == "rule_one"
    assert len(inc.linked_event_ids) == 2


def list_incidents_returns_created(manager: IncidentManager) -> None:
    manager.create(title="t1", summary="s1", severity=IncidentSeverity.LOW)
    manager.create(title="t2", summary="s2", severity=IncidentSeverity.HIGH)
    incidents = manager.list_incidents()
    assert len(incidents) == 2


def test_list_incidents_returns_created(manager: IncidentManager) -> None:
    manager.create(title="t1", summary="s1", severity=IncidentSeverity.LOW)
    manager.create(title="t2", summary="s2", severity=IncidentSeverity.HIGH)
    incidents = manager.list_incidents()
    assert len(incidents) == 2


def test_state_transitions(manager: IncidentManager) -> None:
    inc = manager.create(title="t", summary="s", severity=IncidentSeverity.MEDIUM)
    assert manager.start_investigating(inc.id)
    assert manager.list_incidents()[0]["state"] == "INVESTIGATING"
    assert manager.resolve(inc.id)
    assert manager.list_incidents()[0]["state"] == "RESOLVED"


def test_filter_by_state(manager: IncidentManager) -> None:
    inc1 = manager.create(title="t1", summary="s1", severity=IncidentSeverity.LOW)
    manager.create(title="t2", summary="s2", severity=IncidentSeverity.LOW)
    manager.resolve(inc1.id)
    open_list = manager.list_incidents(state_filter=IncidentState.OPEN)
    resolved_list = manager.list_incidents(state_filter=IncidentState.RESOLVED)
    assert len(open_list) == 1
    assert len(resolved_list) == 1


def test_get_returns_linked_events(manager: IncidentManager) -> None:
    inc = manager.create(
        title="t", summary="s", severity=IncidentSeverity.HIGH,
        linked_event_ids=["ev1", "ev2", "ev3"],
    )
    got = manager.get(inc.id)
    assert got is not None
    assert len(got["linked_events"]) == 3


def test_count_by_state(manager: IncidentManager) -> None:
    manager.create(title="t1", summary="s", severity=IncidentSeverity.LOW)
    inc2 = manager.create(title="t2", summary="s", severity=IncidentSeverity.LOW)
    manager.resolve(inc2.id)
    counts = manager.count_by_state()
    assert counts.get("OPEN", 0) == 1
    assert counts.get("RESOLVED", 0) == 1


def test_dismiss_works(manager: IncidentManager) -> None:
    inc = manager.create(title="t", summary="s", severity=IncidentSeverity.LOW)
    assert manager.dismiss(inc.id)
    assert manager.list_incidents()[0]["state"] == "DISMISSED"
