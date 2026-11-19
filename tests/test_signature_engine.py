"""Unit tests for itshield.scanner.signature_engine.SignatureEngine."""

from __future__ import annotations

from pathlib import Path

from itshield.scanner.signature_engine import SignatureEngine


def test_loads_signature_bank(tmp_project: Path) -> None:
    se = SignatureEngine()
    assert len(se) == 1
    assert se.bank_version == 1


def test_lookup_returns_match_for_eicar(tmp_project: Path) -> None:
    se = SignatureEngine()
    eicar_sha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    match = se.lookup(eicar_sha)
    assert match is not None
    assert match.name == "EICAR-Test-File"


def test_lookup_returns_none_for_unknown(tmp_project: Path) -> None:
    se = SignatureEngine()
    assert se.lookup("0" * 64) is None


def test_case_insensitive_lookup(tmp_project: Path) -> None:
    se = SignatureEngine()
    upper = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F"
    assert se.lookup(upper) is not None


def test_contains_operator(tmp_project: Path) -> None:
    se = SignatureEngine()
    eicar_sha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    assert eicar_sha in se
    assert "0" * 64 not in se
