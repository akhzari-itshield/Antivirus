"""Unit tests for itshield.realtime.* (FileWatcher + RealTimeProtection).

These tests create a temp directory, start a FileWatcher on it, create
files in it, and verify that FILE_CREATED events are published. We also
test RealTimeProtection end-to-end by writing an EICAR file into the
watched directory and expecting a THREAT_DETECTED event.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from itshield.events.bus import EventBus
from itshield.events.models import EventType
from itshield.realtime.watcher import FileWatcher
from itshield.realtime.protection import RealTimeProtection
from itshield.scanner.file_analyzer import FileAnalyzer
from itshield.scanner.hash_engine import HashEngine
from itshield.scanner.scanner import FileScanner
from itshield.scanner.signature_engine import SignatureEngine
from itshield.scanner.yara_engine import YaraEngine


def _has_inotify() -> bool:
    try:
        import inotify_simple  # noqa: F401
        return Path("/proc/sys/fs/inotify_max_user_watches").exists() or os.name == "posix"
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(not _has_inotify(),
                                 reason="requires inotify_simple + Linux")


@pytest.fixture
def scanner() -> FileScanner:
    return FileScanner(
        hash_engine=HashEngine(),
        signature_engine=SignatureEngine(),
        yara_engine=YaraEngine(),
        analyzer=FileAnalyzer(),
    )


def test_file_watcher_emits_create_event(tmp_project: Path) -> None:
    bus = EventBus()
    watch_dir = tmp_project / "watched"
    watch_dir.mkdir()

    received = []
    bus.subscribe(lambda e: received.append(e), EventType.FILE_CREATED)

    watcher = FileWatcher(bus=bus, root=watch_dir, recursive=True)
    watcher.start()
    try:
        time.sleep(0.3)  # let watches settle
        (watch_dir / "hello.txt").write_text("hi")
        time.sleep(0.5)  # let inotify deliver
    finally:
        watcher.stop()

    assert any(e.file_path and e.file_path.endswith("hello.txt") for e in received)


def test_file_watcher_emits_modify_event(tmp_project: Path) -> None:
    bus = EventBus()
    watch_dir = tmp_project / "watched2"
    watch_dir.mkdir()

    received = []
    bus.subscribe(lambda e: received.append(e), EventType.FILE_MODIFIED)

    watcher = FileWatcher(bus=bus, root=watch_dir, recursive=True)
    watcher.start()
    try:
        time.sleep(0.3)
        f = watch_dir / "mod.txt"
        f.write_text("v1")
        time.sleep(0.3)
        f.write_text("v2")
        time.sleep(0.5)
    finally:
        watcher.stop()

    assert any(e.event_type == EventType.FILE_MODIFIED for e in received)


def test_realtime_protection_detects_eicar(tmp_project: Path,
                                            scanner: FileScanner) -> None:
    bus = EventBus()
    watch_dir = tmp_project / "rtp"
    watch_dir.mkdir()

    threats = []
    bus.subscribe(lambda e: threats.append(e), EventType.THREAT_DETECTED)

    rtp = RealTimeProtection(
        bus=bus,
        scanner=scanner,
        watch_root=watch_dir,
        auto_quarantine=False,
    )
    rtp.start()
    try:
        time.sleep(0.3)
        (watch_dir / "eicar.txt").write_bytes(
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        )
        time.sleep(1.0)
    finally:
        rtp.stop()

    assert len(threats) >= 1
    t = threats[0]
    assert t.severity.value == "CRITICAL"
    assert t.metadata["verdict"] == "MALICIOUS"


def test_realtime_protection_health(tmp_project: Path,
                                     scanner: FileScanner) -> None:
    bus = EventBus()
    watch_dir = tmp_project / "rtp2"
    watch_dir.mkdir()

    rtp = RealTimeProtection(
        bus=bus,
        scanner=scanner,
        watch_root=watch_dir,
    )
    rtp.start()
    try:
        time.sleep(0.3)
        h = rtp.health()
        assert h["running"] is True
        assert "watcher_health" in h
    finally:
        rtp.stop()
