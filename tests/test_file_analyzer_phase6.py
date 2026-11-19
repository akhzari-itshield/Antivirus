"""Unit tests for the Phase 6 enhancements to itshield.scanner.file_analyzer.

Covers:
    * Shannon entropy computation (known values for known inputs)
    * PE structure parsing on a hand-crafted minimal PE
    * Packed-section heuristic on a synthetic high-entropy section
"""

from __future__ import annotations

import math
import struct
from pathlib import Path

import pytest

from itshield.scanner.file_analyzer import FileAnalyzer


def test_entropy_of_uniform_bytes_is_high() -> None:
    """256 different byte values uniformly distributed -> entropy ~= 8.0."""
    fa = FileAnalyzer()
    data = bytes(range(256)) * 100  # 25600 bytes, perfectly uniform
    e = fa.compute_entropy(data)
    assert e == pytest.approx(8.0, abs=0.01)


def test_entropy_of_constant_bytes_is_zero() -> None:
    fa = FileAnalyzer()
    e = fa.compute_entropy(b"\x00" * 1024)
    assert e == 0.0


def test_entropy_of_empty_is_zero() -> None:
    fa = FileAnalyzer()
    assert fa.compute_entropy(b"") == 0.0


def test_compute_file_entropy_matches_bytes(tmp_project: Path) -> None:
    fa = FileAnalyzer()
    data = b"hello world " * 100
    p = tmp_project / "ent.bin"
    p.write_bytes(data)
    assert fa.compute_file_entropy(p) == pytest.approx(fa.compute_entropy(data))


def _make_minimal_pe() -> bytes:
    """Build a minimal valid PE32 file with one section."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    e_lfanew = 64
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH",
                       0x14c, 1, 0, 0, 0, 224, 0x102)
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10b)        # magic
    struct.pack_into("<I", opt, 16, 0x1000)      # entry point
    struct.pack_into("<I", opt, 28, 0x400000)    # image base (PE32)

    section_data = b"A" * 0x200
    sec_hdr = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x1000, 0x1000,          # virtual_size, virtual_address
        0x200, 0x200,            # raw_size, raw_offset
        0, 0,                    # ptr_reloc, ptr_line
        0, 0,                    # num_reloc, num_line
        0x60000020,              # characteristics (code, exec, read)
    )

    headers = bytes(dos) + pe_sig + bytes(coff) + bytes(opt) + sec_hdr
    pad = b"\x00" * (0x200 - len(headers))
    return headers + pad + section_data


def test_parse_pe_returns_none_for_non_pe(tmp_project: Path) -> None:
    fa = FileAnalyzer()
    p = tmp_project / "notpe.bin"
    p.write_bytes(b"hello")
    assert fa.parse_pe(p) is None


def test_parse_pe_returns_pe_info_for_minimal_pe(tmp_project: Path) -> None:
    fa = FileAnalyzer()
    p = tmp_project / "min.exe"
    p.write_bytes(_make_minimal_pe())
    info = fa.parse_pe(p)
    assert info is not None
    assert info.file_type == "PE"
    assert info.machine == 0x14c
    assert info.machine_name == "IMAGE_FILE_MACHINE_I386"
    assert info.num_sections == 1
    assert info.is_pe32_plus is False
    assert info.entry_point == 0x1000
    assert info.image_base == 0x400000
    assert len(info.sections) == 1
    assert info.sections[0].name == ".text"
    assert info.sections[0].raw_size == 0x200
    assert info.overall_entropy < 2.0


def test_parse_pe_detects_packed_section(tmp_project: Path) -> None:
    """A high-entropy section should trigger the packed_section heuristic."""
    fa = FileAnalyzer()

    import os as _os
    random_data = _os.urandom(0x1000)  # 4096 bytes of random -> entropy ~8.0

    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x14c, 1, 0, 0, 0, 224, 0x102)
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10b)

    sec_hdr = struct.pack(
        "<8sIIIIIIHHI",
        b".packed",
        0x2000, 0x1000,
        0x1000, 0x200,
        0, 0, 0, 0, 0xe0000020,
    )

    headers = bytes(dos) + pe_sig + bytes(coff) + bytes(opt) + sec_hdr
    pad = b"\x00" * (0x200 - len(headers))
    pe_blob = headers + pad + random_data

    p = tmp_project / "packed.exe"
    p.write_bytes(pe_blob)
    info = fa.parse_pe(p)
    assert info is not None
    assert info.packed_section is not None
    assert ".packed" in info.packed_section
    assert ".packed" in info.suspicious_sections or info.packed_section
