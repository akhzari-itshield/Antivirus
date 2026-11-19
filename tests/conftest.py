"""Common pytest fixtures for the ITShield test suite.

Every test runs against a temporary project directory with isolated
settings, signature bank and YARA rules, so the test suite is hermetic.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def tmp_project(tmp_path: Path) -> Path:
    """Create a temporary project skeleton with signatures, rules and data."""
    (tmp_path / "data").mkdir()
    (tmp_path / "reports").mkdir()
    (tmp_path / "signatures").mkdir()
    (tmp_path / "rules").mkdir()

    (tmp_path / "signatures" / "hashes.json").write_text(json.dumps({
        "version": 1,
        "generated_at": "2026-11-17T00:00:00Z",
        "signatures": [
            {
                "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                "name": "EICAR-Test-File",
                "family": "Test",
                "severity": "LOW",
                "source": "eicar.org",
            },
        ],
    }), encoding="utf-8")

    (tmp_path / "rules" / "sample.yar").write_text(
        'rule ITShield_EICAR_Test_String {\n'
        '    meta:\n'
        '        description = "EICAR test string"\n'
        '    strings:\n'
        '        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"\n'
        '    condition:\n'
        '        $eicar\n'
        '}\n'
        '\n'
        'rule ITShell_Suspicious_Shebang_Python {\n'
        '    meta:\n'
        '        description = "Python script with shebang"\n'
        '    strings:\n'
        '        $py = /#!\\/usr\\/bin\\/(env )?python[0-9]?/ nocase\n'
        '    condition:\n'
        '        $py\n'
        '}\n',
        encoding="utf-8",
    )

    (tmp_path / "scan_dir").mkdir()

    os.environ["ITSHIELD_IPC_SOCKET"] = str(tmp_path / "itshield.sock")

    from itshield.config.settings import reload_settings
    settings = reload_settings()
    settings.project_root = tmp_path
    settings.data_dir = tmp_path / "data"
    settings.reports_dir = tmp_path / "reports"
    settings.signatures_dir = tmp_path / "signatures"
    settings.rules_dir = tmp_path / "rules"
    settings.db_path = tmp_path / "data" / "itshield.db"
    settings.signature_bank_path = tmp_path / "signatures" / "hashes.json"
    settings.yara_rules_path = tmp_path / "rules" / "sample.yar"
    settings.ensure_dirs()

    return tmp_path


@pytest.fixture
def eicar_file(tmp_project: Path) -> Path:
    """Write the canonical 68-byte EICAR test file."""
    p = tmp_project / "scan_dir" / "eicar.txt"
    p.write_bytes(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    return p


@pytest.fixture
def clean_file(tmp_project: Path) -> Path:
    """Write a clean text file."""
    p = tmp_project / "scan_dir" / "clean.txt"
    p.write_bytes(b"Hello ITShield\n")
    return p


@pytest.fixture
def script_file(tmp_project: Path) -> Path:
    """Write a python script with a shebang."""
    p = tmp_project / "scan_dir" / "script.py"
    p.write_text("#!/usr/bin/python3\nprint('hello')\n", encoding="utf-8")
    return p


@pytest.fixture
def scan_dir(tmp_project: Path,
              eicar_file: Path,
              clean_file: Path,
              script_file: Path) -> Path:
    """Convenience fixture: a directory containing all three test files."""
    return tmp_project / "scan_dir"
