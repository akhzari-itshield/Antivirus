"""Unit tests for Phase 11: Ed25519 signed verifier + advanced behavior rules + settings I/O."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from itshield.config.settings import get_settings, reload_settings
from itshield.config.settings_io import export_settings, import_settings
from itshield.detection.behavior_analyzer import BehaviorAnalyzer
from itshield.events.bus import EventBus
from itshield.events.models import Event, EventType, Severity
from itshield.storage.database import Database
from itshield.storage.migrations import run_migrations
from itshield.update.signed_verifier import (
    generate_keypair, save_keypair, load_public_key, load_private_key,
    UpdateSigner, SignedVerifier,
)


def test_ed25519_keypair_generation(tmp_path: Path) -> None:
    pair = generate_keypair()
    assert b"PRIVATE KEY" in pair.private_pem
    assert b"PUBLIC KEY" in pair.public_pem
    save_keypair(pair, tmp_path / "priv.pem", tmp_path / "pub.pem")
    assert (tmp_path / "priv.pem").exists()
    assert (tmp_path / "pub.pem").exists()
    pub = load_public_key(tmp_path / "pub.pem")
    priv = load_private_key(tmp_path / "priv.pem")
    assert pub is not None
    assert priv is not None


def test_ed25519_sign_and_verify_ok(tmp_path: Path) -> None:
    pair = generate_keypair()
    save_keypair(pair, tmp_path / "priv.pem", tmp_path / "pub.pem")
    bank = tmp_path / "bank.json"
    bank.write_text('{"version": 1, "signatures": []}')

    signer = UpdateSigner(private_key_path=tmp_path / "priv.pem")
    sig_path = signer.sign_and_write(bank)
    assert sig_path.exists()
    assert sig_path == bank.with_suffix(bank.suffix + ".sig")

    verifier = SignedVerifier(public_key_path=tmp_path / "pub.pem")
    result = verifier.verify_file(bank)
    assert result.ok
    assert result.status == "OK"
    assert len(result.bank_sha256) == 64


def test_ed25519_verify_tampered_file_fails(tmp_path: Path) -> None:
    pair = generate_keypair()
    save_keypair(pair, tmp_path / "priv.pem", tmp_path / "pub.pem")
    bank = tmp_path / "bank.json"
    bank.write_text('{"version": 1, "signatures": []}')
    signer = UpdateSigner(private_key_path=tmp_path / "priv.pem")
    signer.sign_and_write(bank)

    bank.write_text('{"version": 2, "signatures": []}')

    verifier = SignedVerifier(public_key_path=tmp_path / "pub.pem")
    result = verifier.verify_file(bank)
    assert not result.ok
    assert result.status == "INVALID_SIGNATURE"


def test_ed25519_verify_missing_signature_fails(tmp_path: Path) -> None:
    pair = generate_keypair()
    save_keypair(pair, tmp_path / "priv.pem", tmp_path / "pub.pem")
    bank = tmp_path / "bank.json"
    bank.write_text('{}')
    verifier = SignedVerifier(public_key_path=tmp_path / "pub.pem")
    result = verifier.verify_file(bank)
    assert not result.ok
    assert result.status == "NO_SIGNATURE"


def test_ed25519_verify_missing_file_fails(tmp_path: Path) -> None:
    pair = generate_keypair()
    save_keypair(pair, tmp_path / "priv.pem", tmp_path / "pub.pem")
    verifier = SignedVerifier(public_key_path=tmp_path / "pub.pem")
    result = verifier.verify_file(tmp_path / "nope.json")
    assert not result.ok
    assert result.status == "KEY_ERROR"


def test_ed25519_wrong_key_fails(tmp_path: Path) -> None:
    """Signing with one key, verifying with a different key should fail."""
    pair1 = generate_keypair()
    save_keypair(pair1, tmp_path / "priv1.pem", tmp_path / "pub1.pem")
    pair2 = generate_keypair()
    save_keypair(pair2, tmp_path / "priv2.pem", tmp_path / "pub2.pem")

    bank = tmp_path / "bank.json"
    bank.write_text('{"version": 1}')
    signer = UpdateSigner(private_key_path=tmp_path / "priv1.pem")
    signer.sign_and_write(bank)

    verifier = SignedVerifier(public_key_path=tmp_path / "pub2.pem")
    result = verifier.verify_file(bank)
    assert not result.ok
    assert result.status == "INVALID_SIGNATURE"


@pytest.fixture
def bus() -> EventBus:
    return EventBus()


@pytest.fixture
def analyzer(bus: EventBus) -> BehaviorAnalyzer:
    return BehaviorAnalyzer(
        bus=bus,
        child_threshold=3,
        mass_create_threshold=5,
        mass_create_window=10.0,
        mass_modify_threshold=5,
        mass_modify_window=10.0,
    )


def _ts(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def test_mass_file_creation_triggers_ransomware_anomaly(
    bus: EventBus, analyzer: BehaviorAnalyzer,
) -> None:
    alerts: list = []
    bus.subscribe(lambda e: alerts.append(e), EventType.SECURITY_ALERT)
    analyzer.start()
    try:
        t0 = time.time()
        analyzer._on_event(Event(
            event_type=EventType.PROCESS_CREATED, source="test",
            process_id=1000, parent_process_id=1, process_name="susp",
            timestamp=_ts(t0),
        ))
        for i in range(6):
            analyzer._on_event(Event(
                event_type=EventType.FILE_CREATED, source="test",
                process_id=1000, file_path=f"/tmp/file_{i}.txt",
                timestamp=_ts(t0 + i * 0.1),
            ))
        anomalies = [a.metadata["anomaly"] for a in alerts]
        assert any("mass_file_creation" in a for a in anomalies)
    finally:
        analyzer.stop()


def test_mass_file_modification_triggers_encryption_anomaly(
    bus: EventBus, analyzer: BehaviorAnalyzer,
) -> None:
    alerts: list = []
    bus.subscribe(lambda e: alerts.append(e), EventType.SECURITY_ALERT)
    analyzer.start()
    try:
        t0 = time.time()
        analyzer._on_event(Event(
            event_type=EventType.PROCESS_CREATED, source="test",
            process_id=2000, parent_process_id=1, process_name="crypt",
            timestamp=_ts(t0),
        ))
        for i in range(6):
            analyzer._on_event(Event(
                event_type=EventType.FILE_MODIFIED, source="test",
                process_id=2000, file_path=f"/tmp/doc_{i}.docx",
                timestamp=_ts(t0 + i * 0.1),
            ))
        anomalies = [a.metadata["anomaly"] for a in alerts]
        assert any("mass_file_modification" in a for a in anomalies)
    finally:
        analyzer.stop()


def test_persistence_write_to_cron_triggers_anomaly(
    bus: EventBus, analyzer: BehaviorAnalyzer,
) -> None:
    alerts: list = []
    bus.subscribe(lambda e: alerts.append(e), EventType.SECURITY_ALERT)
    analyzer.start()
    try:
        t0 = time.time()
        analyzer._on_event(Event(
            event_type=EventType.PROCESS_CREATED, source="test",
            process_id=3000, parent_process_id=1, process_name="installer",
            timestamp=_ts(t0),
        ))
        analyzer._on_event(Event(
            event_type=EventType.FILE_CREATED, source="test",
            process_id=3000, file_path="/etc/cron.d/persist",
            timestamp=_ts(t0 + 0.1),
        ))
        anomalies = [a.metadata["anomaly"] for a in alerts]
        assert any("persistence_install" in a for a in anomalies)
    finally:
        analyzer.stop()


def test_persistence_write_to_autostart_triggers_anomaly(
    bus: EventBus, analyzer: BehaviorAnalyzer,
) -> None:
    import os
    os.environ["HOME"] = "/home/test"
    alerts: list = []
    bus.subscribe(lambda e: alerts.append(e), EventType.SECURITY_ALERT)
    analyzer.start()
    try:
        t0 = time.time()
        analyzer._on_event(Event(
            event_type=EventType.PROCESS_CREATED, source="test",
            process_id=4000, parent_process_id=1, process_name="dropper",
            timestamp=_ts(t0),
        ))
        analyzer._on_event(Event(
            event_type=EventType.FILE_CREATED, source="test",
            process_id=4000, file_path="/home/test/.config/autostart/evil.desktop",
            timestamp=_ts(t0 + 0.1),
        ))
        anomalies = [a.metadata["anomaly"] for a in alerts]
        assert any("persistence_install" in a for a in anomalies)
    finally:
        analyzer.stop()


def test_suspicious_child_interpreter_triggers_anomaly(
    bus: EventBus, analyzer: BehaviorAnalyzer,
) -> None:
    alerts: list = []
    bus.subscribe(lambda e: alerts.append(e), EventType.SECURITY_ALERT)
    analyzer.start()
    try:
        t0 = time.time()
        analyzer._on_event(Event(
            event_type=EventType.PROCESS_CREATED, source="test",
            process_id=5000, parent_process_id=1, process_name="doc.pdf.exe",
            timestamp=_ts(t0),
        ))
        analyzer._on_event(Event(
            event_type=EventType.PROCESS_CREATED, source="test",
            process_id=5001, parent_process_id=5000, process_name="python3",
            timestamp=_ts(t0 + 0.1),
        ))
        anomalies = [a.metadata["anomaly"] for a in alerts]
        assert any("suspicious_child" in a for a in anomalies)
    finally:
        analyzer.stop()


def test_normal_file_activity_does_not_trigger(
    bus: EventBus, analyzer: BehaviorAnalyzer,
) -> None:
    """A few file writes below the threshold should not trigger any anomaly."""
    alerts: list = []
    bus.subscribe(lambda e: alerts.append(e), EventType.SECURITY_ALERT)
    analyzer.start()
    try:
        t0 = time.time()
        analyzer._on_event(Event(
            event_type=EventType.PROCESS_CREATED, source="test",
            process_id=6000, parent_process_id=1, process_name="editor",
            timestamp=_ts(t0),
        ))
        for i in range(2):
            analyzer._on_event(Event(
                event_type=EventType.FILE_MODIFIED, source="test",
                process_id=6000, file_path=f"/tmp/normal_{i}.txt",
                timestamp=_ts(t0 + i * 0.1),
            ))
        anomalies = [a.metadata["anomaly"] for a in alerts]
        assert not any("mass_file" in a for a in anomalies)
        assert not any("persistence_install" in a for a in anomalies)
    finally:
        analyzer.stop()


def test_export_and_import_settings_round_trip(tmp_path: Path) -> None:
    reload_settings()
    s = get_settings()
    original_max_size = s.scanner_max_file_size

    s.scanner_max_file_size = 42 * 1024 * 1024

    out = tmp_path / "settings.json"
    export_settings(out, s)
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["version"] == 1
    assert "settings" in data

    s.scanner_max_file_size = original_max_size
    imported = import_settings(out, apply=True)
    assert "scanner_max_file_size" in imported
    s2 = get_settings()
    assert s2.scanner_max_file_size == 42 * 1024 * 1024


def test_export_settings_creates_valid_json(tmp_path: Path) -> None:
    reload_settings()
    out = tmp_path / "exp.json"
    export_settings(out)
    data = json.loads(out.read_text())
    assert "version" in data
    assert "exported_at" in data
    assert "settings" in data
    settings = data["settings"]
    assert "scanner_max_file_size" in settings
    assert "scanner_yara_timeout_seconds" in settings
    assert "log_level" in settings


def test_import_settings_invalid_file_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"no_settings_key": true}')
    with pytest.raises(ValueError, match="missing 'settings' key"):
        import_settings(bad, apply=False)
