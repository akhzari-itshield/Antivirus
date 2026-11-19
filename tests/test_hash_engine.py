"""Unit tests for itshield.scanner.hash_engine.HashEngine."""

from __future__ import annotations

import hashlib
from pathlib import Path

from itshield.scanner.hash_engine import HashEngine


def test_hash_engine_default_is_python(tmp_project: Path) -> None:
    he = HashEngine()
    assert he.algorithm == "sha256"
    assert he.backend in ("python", "rust")


def test_hash_engine_hashes_bytes() -> None:
    he = HashEngine()
    expected = hashlib.sha256(b"hello").hexdigest()
    assert he.hash_bytes(b"hello") == expected


def test_hash_engine_hashes_file(tmp_project: Path, clean_file: Path) -> None:
    he = HashEngine()
    data = clean_file.read_bytes()
    expected = hashlib.sha256(data).hexdigest()
    assert he.hash_file(clean_file) == expected


def test_hash_engine_missing_file_raises(tmp_project: Path) -> None:
    he = HashEngine()
    import pytest
    with pytest.raises(FileNotFoundError):
        he.hash_file(tmp_project / "does-not-exist.bin")


def test_hash_engine_rejects_directory(tmp_project: Path) -> None:
    he = HashEngine()
    import pytest
    with pytest.raises(IsADirectoryError):
        he.hash_file(tmp_project)


def test_hash_engine_unsupported_algorithm() -> None:
    import pytest
    with pytest.raises(ValueError):
        HashEngine(algorithm="md999")
