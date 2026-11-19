"""Unit tests for itshield.detection.engine.DetectionEngine."""

from __future__ import annotations

from itshield.detection.engine import DetectionEngine, DetectionInput
from itshield.scanner.models import DetectionVerdict


def test_signature_match_returns_malicious() -> None:
    engine = DetectionEngine()
    out = engine.decide(DetectionInput(
        sha256="abc",
        signature_name="EICAR-Test-File",
    ))
    assert out.verdict == DetectionVerdict.MALICIOUS


def test_yara_match_returns_suspicious() -> None:
    engine = DetectionEngine()
    out = engine.decide(DetectionInput(
        sha256="abc",
        yara_rules=["rule1", "rule2"],
    ))
    assert out.verdict == DetectionVerdict.SUSPICIOUS


def test_no_signals_returns_clean() -> None:
    engine = DetectionEngine()
    out = engine.decide(DetectionInput(sha256="abc"))
    assert out.verdict == DetectionVerdict.CLEAN


def test_no_hash_returns_unknown() -> None:
    engine = DetectionEngine()
    out = engine.decide(DetectionInput(sha256=None))
    assert out.verdict == DetectionVerdict.UNKNOWN


def test_signature_overrides_yara() -> None:
    """If both signature and YARA match, MALICIOUS wins (priority)."""
    engine = DetectionEngine()
    out = engine.decide(DetectionInput(
        sha256="abc",
        signature_name="Bad",
        yara_rules=["some_rule"],
    ))
    assert out.verdict == DetectionVerdict.MALICIOUS
