"""Unit tests for itshield.scanner.yara_engine.YaraEngine."""

from __future__ import annotations

from pathlib import Path

import pytest

from itshield.scanner.yara_engine import YaraEngine


def test_loads_rules(tmp_project: Path) -> None:
    ye = YaraEngine()
    assert ye.ready
    assert ye.rule_count >= 1


def test_matches_eicar_string(tmp_project: Path, eicar_file: Path) -> None:
    ye = YaraEngine()
    matches = ye.scan_file(eicar_file)
    assert len(matches) >= 1
    rule_names = [m.rule for m in matches]
    assert "ITShield_EICAR_Test_String" in rule_names


def test_no_match_on_clean_file(tmp_project: Path, clean_file: Path) -> None:
    ye = YaraEngine()
    matches = ye.scan_file(clean_file)
    assert matches == []


def test_missing_file_returns_empty(tmp_project: Path) -> None:
    ye = YaraEngine()
    assert ye.scan_file(tmp_project / "missing.bin") == []
