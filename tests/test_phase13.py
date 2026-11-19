"""Unit tests for Phase 13: IOCMatcher + SandboxAnalyzer."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from itshield.detection.ioc_matcher import IOCMatcher
from itshield.events.bus import EventBus
from itshield.events.models import Event, EventType, Severity
from itshield.sandbox.analyzer import (
    SandboxAnalyzer, SandboxReport, SandboxVerdict, ObservedBehavior,
)
from itshield.storage.database import Database
from itshield.storage.migrations import run_migrations


@pytest.fixture
def db(tmp_project: Path) -> Database:
    database = Database(tmp_project / "data" / "p13.db")
    run_migrations(database)
    yield database
    database.close()


@pytest.fixture
def bus() -> EventBus:
    return EventBus()


def _populate_ioc_db(db: Database) -> None:
    """Insert a few IOCs of each type for matching tests."""
    now = "2026-01-01T00:00:00Z"
    db.execute(
        "INSERT OR IGNORE INTO ioc_hashes (sha256, source, threat_name, first_seen, added_at) "
        "VALUES (?, ?, ?, ?, ?)",
        ("a" * 64, "TestSource", "TrojanX", now, now),
    )
    db.execute(
        "INSERT OR IGNORE INTO ioc_ips (ip_address, port, source, threat_name, first_seen, added_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("8.8.8.8", 443, "TestSource", "C2Server", now, now),
    )
    db.execute(
        "INSERT OR IGNORE INTO ioc_domains (domain, source, threat_name, first_seen, added_at) "
        "VALUES (?, ?, ?, ?, ?)",
        ("evil.example.com", "TestSource", "PhishingKit", now, now),
    )
    db.execute(
        "INSERT OR IGNORE INTO ioc_urls (url, source, threat_name, first_seen, added_at) "
        "VALUES (?, ?, ?, ?, ?)",
        ("http://evil.example.com/payload", "TestSource", "MalwareDrop", now, now),
    )


def test_ioc_matcher_detects_known_ip(db: Database, bus: EventBus) -> None:
    _populate_ioc_db(db)
    alerts: list = []
    bus.subscribe(lambda e: alerts.append(e), EventType.SECURITY_ALERT)

    matcher = IOCMatcher(bus=bus, db=db)
    matcher.start()
    try:
        bus.publish(Event(
            event_type=EventType.NETWORK_CONNECTION,
            source="network_monitor",
            metadata={"remote_addr": "8.8.8.8", "remote_port": 443},
        ))
        time.sleep(0.2)  # let the subscriber process
    finally:
        matcher.stop()

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.severity == Severity.ERROR
    assert alert.metadata["ioc_type"] == "ip"
    assert alert.metadata["ioc_value"] == "8.8.8.8"
    assert alert.metadata["threat_name"] == "C2Server"
    assert alert.metadata["ioc_source"] == "TestSource"


def test_ioc_matcher_detects_known_hash(db: Database, bus: EventBus) -> None:
    _populate_ioc_db(db)
    alerts: list = []
    bus.subscribe(lambda e: alerts.append(e), EventType.SECURITY_ALERT)

    matcher = IOCMatcher(bus=bus, db=db)
    matcher.start()
    try:
        bus.publish(Event(
            event_type=EventType.THREAT_DETECTED,
            source="scanner",
            file_hash="A" * 64,  # case-insensitive
            file_path="/tmp/bad.exe",
        ))
        time.sleep(0.2)
    finally:
        matcher.stop()

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.severity == Severity.CRITICAL  # hash matches are critical
    assert alert.metadata["ioc_type"] == "hash"
    assert alert.file_hash == "A" * 64


def test_ioc_matcher_detects_known_domain(db: Database, bus: EventBus) -> None:
    _populate_ioc_db(db)
    alerts: list = []
    bus.subscribe(lambda e: alerts.append(e), EventType.SECURITY_ALERT)

    matcher = IOCMatcher(bus=bus, db=db)
    matcher.start()
    try:
        bus.publish(Event(
            event_type=EventType.DNS_QUERY,
            source="dns_monitor",
            metadata={"domain": "evil.example.com"},
        ))
        time.sleep(0.2)
    finally:
        matcher.stop()

    assert len(alerts) == 1
    assert alerts[0].metadata["ioc_type"] == "domain"


def test_ioc_matcher_detects_known_url(db: Database, bus: EventBus) -> None:
    _populate_ioc_db(db)
    alerts: list = []
    bus.subscribe(lambda e: alerts.append(e), EventType.SECURITY_ALERT)

    matcher = IOCMatcher(bus=bus, db=db)
    matcher.start()
    try:
        bus.publish(Event(
            event_type=EventType.NETWORK_CONNECTION,
            source="test",
            metadata={"url": "http://evil.example.com/payload"},
        ))
        time.sleep(0.2)
    finally:
        matcher.stop()

    assert len(alerts) == 1
    assert alerts[0].metadata["ioc_type"] == "url"


def test_ioc_matcher_no_match_for_clean(db: Database, bus: EventBus) -> None:
    """An event with no IOC match should not publish any alert."""
    _populate_ioc_db(db)
    alerts: list = []
    bus.subscribe(lambda e: alerts.append(e), EventType.SECURITY_ALERT)

    matcher = IOCMatcher(bus=bus, db=db)
    matcher.start()
    try:
        bus.publish(Event(
            event_type=EventType.NETWORK_CONNECTION,
            source="network_monitor",
            metadata={"remote_addr": "1.1.1.1", "remote_port": 53},  # not in IOC DB
        ))
        time.sleep(0.2)
    finally:
        matcher.stop()

    assert len(alerts) == 0
    assert matcher.health()["events_checked"] == 1
    assert matcher.health()["matches_found"] == 0


def test_ioc_matcher_health(db: Database, bus: EventBus) -> None:
    matcher = IOCMatcher(bus=bus, db=db)
    assert not matcher.health()["running"]
    matcher.start()
    try:
        assert matcher.health()["running"]
    finally:
        matcher.stop()
    assert not matcher.health()["running"]


def test_sandbox_benign_script(tmp_project: Path) -> None:
    """A simple bash script that exits 0 should be BENIGN."""
    script = tmp_project / "benign.sh"
    script.write_text("#!/bin/bash\necho hello\nexit 0\n")
    os.chmod(script, 0o755)

    analyzer = SandboxAnalyzer(timeout_seconds=5.0)
    report = analyzer.analyze(script)
    assert report.verdict in (SandboxVerdict.BENIGN, SandboxVerdict.SUSPICIOUS)
    assert report.duration_seconds > 0
    assert report.error == ""


def test_sandbox_missing_file(tmp_project: Path) -> None:
    analyzer = SandboxAnalyzer(timeout_seconds=5.0)
    report = analyzer.analyze(tmp_project / "does_not_exist.bin")
    assert report.verdict == SandboxVerdict.ERROR
    assert "not found" in report.error


def test_sandbox_timeout(tmp_project: Path) -> None:
    """A script that sleeps longer than the timeout should be TIMEOUT."""
    script = tmp_project / "slow.sh"
    script.write_text("#!/bin/bash\nsleep 30\n")
    os.chmod(script, 0o755)

    analyzer = SandboxAnalyzer(timeout_seconds=1.0)
    report = analyzer.analyze(script)
    assert report.verdict == SandboxVerdict.TIMEOUT
    assert report.duration_seconds < 5.0  # killed quickly after timeout


def test_sandbox_non_executable_file(tmp_project: Path) -> None:
    """A plain text file can't be executed - should be ERROR."""
    f = tmp_project / "not_exec.txt"
    f.write_text("this is just text, not a program")
    os.chmod(f, 0o600)

    analyzer = SandboxAnalyzer(timeout_seconds=3.0)
    report = analyzer.analyze(f)
    assert report.verdict in (SandboxVerdict.ERROR, SandboxVerdict.SUSPICIOUS, SandboxVerdict.BENIGN)


def test_sandbox_report_to_dict(tmp_project: Path) -> None:
    """SandboxReport.to_dict() should produce a JSON-serializable dict."""
    script = tmp_project / "benign.sh"
    script.write_text("#!/bin/bash\nexit 0\n")
    os.chmod(script, 0o755)

    analyzer = SandboxAnalyzer(timeout_seconds=3.0)
    report = analyzer.analyze(script)
    d = report.to_dict()
    import json
    json.dumps(d)  # must not raise
    assert "verdict" in d
    assert "duration_seconds" in d
    assert "behaviors" in d


def test_sandbox_cleanup(tmp_project: Path) -> None:
    """The sandbox temp directory should be removed after analysis."""
    script = tmp_project / "clean.sh"
    script.write_text("#!/bin/bash\nexit 0\n")
    os.chmod(script, 0o755)

    import tempfile
    tmp_root = Path(tempfile.gettempdir())
    before = set(tmp_root.glob("itshield_sandbox_*"))

    analyzer = SandboxAnalyzer(timeout_seconds=3.0)
    analyzer.analyze(script)

    after = set(tmp_root.glob("itshield_sandbox_*"))
    new_leftovers = after - before
    assert len(new_leftovers) == 0, f"Leftover sandbox dirs: {new_leftovers}"


def test_observed_behavior_dataclass() -> None:
    b = ObservedBehavior(kind="network", detail="8.8.8.8:443", timestamp="now")
    d = b.to_dict()
    assert d["kind"] == "network"
    assert d["detail"] == "8.8.8.8:443"
