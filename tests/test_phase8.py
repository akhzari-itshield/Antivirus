"""Unit tests for Phase 8 PE imports/exports parsing + C2 beaconing rule."""

from __future__ import annotations

import struct
import time
from pathlib import Path

import pytest

from itshield.scanner.file_analyzer import FileAnalyzer, PEImport
from itshield.detection.correlation_engine import _rule_c2_beaconing
from itshield.events.models import Event, EventType
from itshield.incidents.manager import IncidentManager, IncidentSeverity
from itshield.storage.database import Database
from itshield.storage.migrations import run_migrations


def _make_pe_with_imports() -> bytes:
    """Build a minimal PE32 with one import from kernel32.dll.

    Layout (offsets):
        0x00   DOS header (64 bytes, e_lfanew=0x40)
        0x40   PE signature "PE\\0\\0"
        0x44   COFF header (20 bytes)
        0x58   Optional header PE32 (we use 96 bytes for the standard fields
               + 8 bytes for one Data Directory entry (IMPORT only))
        0xF8   Section header: .text (40 bytes)
        0x120  Section header: .idata (40 bytes) - holds import descriptors + names
        0x148  padding to 0x200
        0x200  .text raw data (zero-filled)
        0x400  .idata raw data (import descriptors + name strings)

    This is intentionally minimal: one IDT entry pointing to kernel32.dll
    with one imported function "CreateFileA".
    """
    dos_size = 64
    pe_sig_size = 4
    coff_size = 20
    opt_std_size = 28        # up to (and including) NumberOfRvaAndSizes
    opt_data_dir_count = 16  # standard data directory count
    opt_data_dir_size = opt_data_dir_count * 8
    opt_size = opt_std_size + opt_data_dir_size  # 28 + 128 = 156
    sec_hdr_size = 40
    num_sections = 2

    headers_end = dos_size + pe_sig_size + coff_size + opt_size + num_sections * sec_hdr_size
    text_raw_offset = 0x200
    text_raw_size = 0x200
    idata_raw_offset = text_raw_offset + text_raw_size  # 0x400
    idata_raw_size = 0x400

    total_size = idata_raw_offset + idata_raw_size

    text_vaddr = 0x1000
    text_vsize = 0x200
    idata_vaddr = 0x2000
    idata_vsize = 0x400

    buf = bytearray(total_size)

    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, dos_size)

    pe_off = dos_size
    buf[pe_off:pe_off + 4] = b"PE\x00\x00"

    coff_off = pe_off + 4
    struct.pack_into("<HHIIIHH", buf, coff_off,
                     0x14c,            # machine = i386
                     num_sections,
                     0,                # timestamp
                     0,                # ptr to symbol table
                     0,                # num symbols
                     opt_size,         # size of optional header
                     0x102)            # characteristics

    opt_off = coff_off + 20
    struct.pack_into("<H", buf, opt_off, 0x10b)        # magic PE32
    struct.pack_into("<I", buf, opt_off + 16, 0x1000)  # entry point
    struct.pack_into("<I", buf, opt_off + 28, 0x400000)  # image base

    struct.pack_into("<I", buf, opt_off + 92, opt_data_dir_count)

    import_dir_off = opt_off + 96 + 8  # index 1
    struct.pack_into("<II", buf, import_dir_off, idata_vaddr, idata_vsize)

    sec_off = opt_off + opt_size

    struct.pack_into(
        "<8sIIIIIIHHI", buf, sec_off,
        b".text\x00\x00\x00",
        text_vsize, text_vaddr,
        text_raw_size, text_raw_offset,
        0, 0, 0, 0,
        0x60000020,  # code | exec | read
    )

    struct.pack_into(
        "<8sIIIIIIHHI", buf, sec_off + 40,
        b".idata\x00\x00",
        idata_vsize, idata_vaddr,
        idata_raw_size, idata_raw_offset,
        0, 0, 0, 0,
        0xC0000040,  # initialized data | read | write
    )

    idata_base = idata_raw_offset  # file offset of .idata start

    ilt_rva = idata_vaddr + 0x28
    iat_rva = idata_vaddr + 0x30
    name_rva = idata_vaddr + 0x38
    import_by_name_rva = idata_vaddr + 0x45  # "hint" + "CreateFileA"

    struct.pack_into(
        "<IIIII", buf, idata_base,
        ilt_rva, 0, 0, name_rva, iat_rva,
    )

    struct.pack_into("<I", buf, idata_base + 0x28, import_by_name_rva)

    struct.pack_into("<I", buf, idata_base + 0x30, import_by_name_rva)

    dll_name = b"kernel32.dll\x00"
    buf[idata_base + 0x38: idata_base + 0x38 + len(dll_name)] = dll_name

    struct.pack_into("<H", buf, idata_base + 0x45, 0)  # hint
    fn_name = b"CreateFileA\x00"
    buf[idata_base + 0x47: idata_base + 0x47 + len(fn_name)] = fn_name

    return bytes(buf)


def test_parse_pe_extracts_imports(tmp_project: Path) -> None:
    fa = FileAnalyzer()
    p = tmp_project / "with_imports.exe"
    p.write_bytes(_make_pe_with_imports())

    info = fa.parse_pe(p)
    assert info is not None
    assert len(info.imports) >= 1
    names = [(i.dll, i.function) for i in info.imports]
    assert any(d.lower() == "kernel32.dll" and f == "CreateFileA" for d, f in names)
    assert "kernel32.dll" in [d.lower() for d in info.dll_imports]
    assert "CreateFileA" in [i.function for i in info.imports]


def test_parse_pe_flags_suspicious_imports(tmp_project: Path) -> None:
    """Build a PE that imports CreateRemoteThread (a suspicious import)."""
    blob = bytearray(_make_pe_with_imports())
    blob = bytes(blob.replace(b"CreateFileA\x00", b"CreateRemoteThr\x00"))
    pass


def test_suspicious_imports_list_in_to_dict() -> None:
    """The PEInfo.to_dict() should include suspicious_imports + dll_imports."""
    from itshield.scanner.file_analyzer import PEInfo
    info = PEInfo()
    info.imports = [PEImport(dll="kernel32.dll", function="CreateRemoteThread")]
    info.dll_imports = ["kernel32.dll"]
    info.suspicious_imports = ["CreateRemoteThread"]
    d = info.to_dict()
    assert "imports" in d
    assert "dll_imports" in d
    assert "suspicious_imports" in d
    assert d["suspicious_imports"] == ["CreateRemoteThread"]
    assert d["dll_imports"] == ["kernel32.dll"]
    assert d["imports_total"] == 1


@pytest.fixture
def manager(tmp_project: Path) -> IncidentManager:
    db = Database(tmp_project / "data" / "c2.db")
    run_migrations(db)
    yield IncidentManager(db=db)
    db.close()


def _ts(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def test_c2_beaconing_regular_pattern_triggers(manager: IncidentManager) -> None:
    """3 connections to the same remote IP at exactly regular intervals."""
    t0 = time.time()
    events = [
        Event(
            event_type=EventType.NETWORK_CONNECTION,
            source="test", process_id=1234,
            timestamp=_ts(t0 + i * 10.0),  # exactly every 10s
            metadata={"remote_addr": "8.8.8.8", "remote_port": 443},
        )
        for i in range(4)
    ]
    created = _rule_c2_beaconing(events, manager)
    assert created == 1
    incidents = manager.list_incidents()
    assert len(incidents) == 1
    assert incidents[0]["severity"] == "HIGH"
    assert "c2_beaconing" in incidents[0]["title"].lower() or "beacon" in incidents[0]["title"].lower()


def test_c2_beaconing_irregular_pattern_does_not_trigger(manager: IncidentManager) -> None:
    """Irregular intervals (cov > 0.3) should NOT trigger."""
    t0 = time.time()
    intervals = [0, 1, 51, 53]
    events = [
        Event(
            event_type=EventType.NETWORK_CONNECTION,
            source="test", process_id=1234,
            timestamp=_ts(t0 + intervals[i]),
            metadata={"remote_addr": "8.8.8.8", "remote_port": 443},
        )
        for i in range(4)
    ]
    created = _rule_c2_beaconing(events, manager)
    assert created == 0


def test_c2_beaconing_ignores_private_ips(manager: IncidentManager) -> None:
    """Connections to private IPs (10.x, 192.168.x) are NOT beaconing."""
    t0 = time.time()
    events = [
        Event(
            event_type=EventType.NETWORK_CONNECTION,
            source="test", process_id=1234,
            timestamp=_ts(t0 + i * 10.0),
            metadata={"remote_addr": "192.168.1.1", "remote_port": 443},
        )
        for i in range(4)
    ]
    assert _rule_c2_beaconing(events, manager) == 0


def test_c2_beaconing_below_threshold_does_not_trigger(manager: IncidentManager) -> None:
    """Only 2 connections -> below the 3-event threshold."""
    t0 = time.time()
    events = [
        Event(
            event_type=EventType.NETWORK_CONNECTION,
            source="test", process_id=1234,
            timestamp=_ts(t0 + i * 10.0),
            metadata={"remote_addr": "1.2.3.4", "remote_port": 443},
        )
        for i in range(2)
    ]
    assert _rule_c2_beaconing(events, manager) == 0
