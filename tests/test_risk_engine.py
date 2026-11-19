"""Unit tests for itshield.detection.risk_engine.RiskEngine."""

from __future__ import annotations

from itshield.detection.risk_engine import (
    RiskEngine,
    RiskInput,
    RiskLevel,
    WEIGHT_SIGNATURE_MATCH,
    WEIGHT_YARA_MATCH_CAP,
)
from itshield.scanner.models import DetectionVerdict


def test_clean_file_low_risk() -> None:
    engine = RiskEngine()
    result = engine.assess(RiskInput(
        sha256="abc",
        file_type="UNKNOWN",
    ))
    assert result.score < 20
    assert result.level == RiskLevel.LOW
    assert result.verdict == DetectionVerdict.CLEAN


def test_signature_match_drives_critical() -> None:
    engine = RiskEngine()
    result = engine.assess(RiskInput(
        sha256="abc",
        signature_name="EICAR-Test-File",
    ))
    assert result.score >= 75
    assert result.level == RiskLevel.CRITICAL
    assert result.verdict == DetectionVerdict.MALICIOUS
    names = [f.name for f in result.factors]
    assert "signature_match" in names


def test_yara_match_drives_suspicious() -> None:
    engine = RiskEngine()
    result = engine.assess(RiskInput(
        sha256="abc",
        yara_rules=["rule_one", "rule_two"],
    ))
    assert 50 <= result.score < 75
    assert result.level == RiskLevel.HIGH
    assert result.verdict == DetectionVerdict.SUSPICIOUS


def test_yara_match_capped() -> None:
    """Even 10 YARA rules can't contribute more than the cap."""
    engine = RiskEngine()
    result = engine.assess(RiskInput(
        sha256="abc",
        yara_rules=["r" + str(i) for i in range(10)],
    ))
    yara_factor = next(f for f in result.factors if f.name == "yara_matches")
    assert yara_factor.weight == WEIGHT_YARA_MATCH_CAP


def test_combined_signals_push_to_malicious() -> None:
    """No single strong signal but enough weak ones combined."""
    engine = RiskEngine()
    result = engine.assess(RiskInput(
        sha256="abc",
        yara_rules=["rule1"],                       # 25
        entropy=7.5,                                 # 15
        packed_section="section '.upx0' is packed",  # 20
        suspicious_imports=["CreateRemoteThread"],   # 15
    ))
    assert result.score >= 75
    assert result.verdict == DetectionVerdict.MALICIOUS


def test_to_dict_round_trip() -> None:
    engine = RiskEngine()
    result = engine.assess(RiskInput(
        sha256="abc",
        signature_name="Bad",
        yara_rules=["rule1"],
    ))
    d = result.to_dict()
    assert "score" in d
    assert "level" in d
    assert "verdict" in d
    assert isinstance(d["factors"], list)
    assert all("name" in f and "weight" in f for f in d["factors"])


def test_score_capped_at_100() -> None:
    """Every signal triggered should still cap at 100."""
    engine = RiskEngine()
    result = engine.assess(RiskInput(
        sha256="abc",
        signature_name="Bad",
        yara_rules=["r1", "r2", "r3"],
        entropy=7.9,
        packed_section="yes",
        suspicious_imports=["a", "b"],
        c2_indicator="bad ip",
        process_anomaly="lots of children",
        file_type="PE",
    ))
    assert result.score <= 100
