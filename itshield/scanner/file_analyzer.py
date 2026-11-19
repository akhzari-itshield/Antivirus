"""File Analyzer - structural analysis of files.

Section 9.5 of the architecture document + Phase 6 enhancements.

Phase 1-5 capabilities:
    * Magic-byte identification for common executable / archive / document
      formats (PE, ELF, ZIP, PDF, ...).

Phase 6 enhancements (this module):
    * Shannon entropy of the whole file
    * PE structure parsing in pure Python:
        - DOS header + PE signature
        - COFF header (machine, num sections, characteristics)
        - Optional header (PE32 vs PE32+, entry point, image base)
        - Section table (name, virtual size, raw size, entropy per section)
        - Suspicious-section detection (UPX, .packt, high-entropy .text)
        - Packed-section heuristic (raw_size much smaller than virtual size
          or section entropy >= 7.0)
    * When the Rust native extension (``itshield_native``) is importable,
      PE parsing delegates to the faster Rust implementation; the Python
      parser is the fallback.
"""

from __future__ import annotations

import math
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from itshield.logging.logger import get_logger

logger = get_logger(__name__)


_MAGIC_SIGNATURES: tuple[tuple[bytes, str, str], ...] = (
    (b"MZ", "PE", "Windows executable (PE)"),
    (b"\x7fELF", "ELF", "Linux executable (ELF)"),
    (b"PK\x03\x04", "ZIP", "ZIP archive"),
    (b"PK\x05\x06", "ZIP", "ZIP archive (empty)"),
    (b"%PDF-", "PDF", "PDF document"),
    (b"\x89PNG\r\n\x1a\n", "PNG", "PNG image"),
    (b"\xff\xd8\xff", "JPEG", "JPEG image"),
    (b"GIF87a", "GIF", "GIF image"),
    (b"GIF89a", "GIF", "GIF image"),
    (b"Rar!\x1a\x07", "RAR", "RAR archive"),
    (b"\x1f\x8b", "GZIP", "GZIP archive"),
    (b"BZh", "BZIP2", "BZIP2 archive"),
    (b"\xfd7zXZ\x00", "XZ", "XZ archive"),
    (b"#!/", "SHEBANG", "Script with shebang"),
    (b"#!", "SHEBANG", "Script with shebang"),
    (b"\xca\xfe\xba\xbe", "CLASS", "Java class file"),
    (b"\xfe\xed\xfa\xce", "MACHO", "Mach-O binary (32-bit)"),
    (b"\xfe\xed\xfa\xcf", "MACHO", "Mach-O binary (64-bit)"),
    (b"\xcf\xfa\xed\xfe", "MACHO", "Mach-O binary (64-bit LE)"),
)


@dataclass
class FileTypeInfo:
    """Result of a magic-byte identification."""

    file_type: str
    description: str
    is_executable: bool
    is_archive: bool
    is_script: bool


@dataclass
class PESection:
    """One PE section entry."""

    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    characteristics: int
    entropy: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "virtual_size": self.virtual_size,
            "virtual_address": self.virtual_address,
            "raw_size": self.raw_size,
            "raw_offset": self.raw_offset,
            "characteristics": self.characteristics,
            "entropy": round(self.entropy, 4),
        }


@dataclass
class PEImport:
    """One imported function from a DLL."""

    dll: str
    function: str
    ordinal: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"dll": self.dll, "function": self.function, "ordinal": self.ordinal}


@dataclass
class PEInfo:
    """Parsed PE structure."""

    file_type: str = "PE"
    parser: str = "python"
    size: int = 0
    e_lfanew: int = 0
    machine: int = 0
    machine_name: str = ""
    num_sections: int = 0
    characteristics: int = 0
    is_pe32_plus: bool = False
    optional_header_size: int = 0
    entry_point: int = 0
    image_base: int = 0
    sections: List[PESection] = field(default_factory=list)
    suspicious_sections: List[str] = field(default_factory=list)
    packed_section: Optional[str] = None
    overall_entropy: float = 0.0
    imports: List[PEImport] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    suspicious_imports: List[str] = field(default_factory=list)
    dll_imports: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_type": self.file_type,
            "parser": self.parser,
            "size": self.size,
            "e_lfanew": self.e_lfanew,
            "machine": self.machine,
            "machine_name": self.machine_name,
            "num_sections": self.num_sections,
            "characteristics": self.characteristics,
            "is_pe32_plus": self.is_pe32_plus,
            "optional_header_size": self.optional_header_size,
            "entry_point": self.entry_point,
            "image_base": self.image_base,
            "sections": [s.to_dict() for s in self.sections],
            "suspicious_sections": self.suspicious_sections,
            "packed_section": self.packed_section,
            "overall_entropy": round(self.overall_entropy, 4),
            "imports": [i.to_dict() for i in self.imports[:50]],   # cap to keep payload small
            "imports_total": len(self.imports),
            "exports": self.exports[:50],
            "exports_total": len(self.exports),
            "suspicious_imports": self.suspicious_imports,
            "dll_imports": self.dll_imports,
        }


_SUSPICIOUS_SECTIONS = {
    "UPX0", "UPX1", "UPX2",         # UPX-packed
    ".packt", ".packed", ".themida",  # commercial packers
    ".aspack", ".adata",
    ".petite",
    ".nsp0", ".nsp1", ".nsp2",      # Nspack
    ".MPRESS1", ".MPRESS2",
    "pebundle",
}

_SUSPICIOUS_IMPORTS = {
    "CreateRemoteThread", "CreateRemoteThreadEx",
    "VirtualAllocEx", "VirtualProtectEx", "WriteProcessMemory",
    "ReadProcessMemory", "OpenProcess", "NtUnmapViewOfSection",
    "QueueUserAPC", "NtCreateThreadEx",
    "ZwUnmapViewOfSection", "RtlCreateUserThread",
    "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
    "GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "RegSetValueExA", "RegSetValueExW",
    "RegCreateKeyExA", "RegCreateKeyExW",
    "CreateServiceA", "CreateServiceW",
    "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "OutputDebugStringA", "OutputDebugStringW",
    "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
    "HttpSendRequestA", "HttpSendRequestW",
    "URLDownloadToFileA", "URLDownloadToFileW",
    "WSAStartup", "WSASocketA", "WSASocketW",
    "socket", "connect", "send", "recv",
    "CryptAcquireContextA", "CryptAcquireContextW",
    "CryptGenKey", "CryptEncrypt", "CryptDecrypt",
    "StartServiceCtrlDispatcherA", "StartServiceCtrlDispatcherW",
    "ChangeServiceConfigA", "ChangeServiceConfigW",
}

_MACHINE_NAMES = {
    0x014c: "IMAGE_FILE_MACHINE_I386",
    0x0200: "IMAGE_FILE_MACHINE_IA64",
    0x8664: "IMAGE_FILE_MACHINE_AMD64",
    0x01c0: "IMAGE_FILE_MACHINE_ARM",
    0xaa64: "IMAGE_FILE_MACHINE_ARM64",
}


class FileAnalyzer:
    """Identify file types and (in this Phase 6 version) parse PE structure.

    Adds :meth:`compute_entropy` and an enhanced :meth:`parse_pe` that
    returns section table + entropy + packing heuristic instead of just
    the magic-byte detection stub from Phase 5.
    """

    EXECUTABLE_TYPES = {"PE", "ELF", "MACHO", "CLASS"}
    ARCHIVE_TYPES = {"ZIP", "RAR", "GZIP", "BZIP2", "XZ"}
    SCRIPT_TYPES = {"SHEBANG"}

    def __init__(self, magic_size: int = 8, read_limit: int = 64 * 1024 * 1024) -> None:
        self.magic_size = magic_size
        self.read_limit = read_limit
        self._rust_backend = self._try_load_rust_backend()

    @staticmethod
    def _try_load_rust_backend():
        try:
            import itshield_native  # type: ignore[import-not-found]
            if hasattr(itshield_native, "parse_pe"):
                return itshield_native
        except ImportError:
            return None
        return None

    @property
    def backend(self) -> str:
        return "rust" if self._rust_backend else "python"

    def identify(self, path: str | Path) -> FileTypeInfo:
        """Identify ``path`` by reading its first ``magic_size`` bytes."""
        path = Path(path)
        if not path.exists() or not path.is_file():
            return FileTypeInfo("UNKNOWN", "missing or not a regular file",
                                False, False, False)

        try:
            with path.open("rb") as fh:
                head = fh.read(self.magic_size)
        except OSError as exc:
            logger.debug("Could not read magic bytes of %s: %s", path, exc)
            return FileTypeInfo("UNKNOWN", f"read error: {exc}",
                                False, False, False)

        file_type = "UNKNOWN"
        description = "Unknown or plain-text file"
        for magic, label, desc in _MAGIC_SIGNATURES:
            if head.startswith(magic):
                file_type = label
                description = desc
                break

        return FileTypeInfo(
            file_type=file_type,
            description=description,
            is_executable=file_type in self.EXECUTABLE_TYPES,
            is_archive=file_type in self.ARCHIVE_TYPES,
            is_script=file_type in self.SCRIPT_TYPES,
        )

    def compute_entropy(self, data: bytes) -> float:
        """Shannon entropy of ``data`` (0.0..8.0 for byte values)."""
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def compute_file_entropy(self, path: str | Path) -> float:
        """Compute Shannon entropy of an entire file (chunked)."""
        path = Path(path)
        if not path.exists() or not path.is_file():
            return 0.0
        counts = Counter()
        total = 0
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                counts.update(chunk)
                total += len(chunk)
        if total == 0:
            return 0.0
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def parse_pe(self, path: str | Path) -> Optional[PEInfo]:
        """Parse a PE file structure (Phase 6 version).

        Returns a :class:`PEInfo` with section table, entropy per section,
        suspicious-section flags, and a packing heuristic. Returns ``None``
        if the file is not a PE.
        """
        path = Path(path)
        info = self.identify(path)
        if info.file_type != "PE":
            return None

        if self._rust_backend is not None:
            try:
                rust_dict = self._rust_backend.parse_pe(str(path))
                pe_info = self._parse_pe_python(path)
                if pe_info is not None:
                    pe_info.parser = "rust+python"
                    if "num_sections" in rust_dict:
                        pe_info.num_sections = int(rust_dict["num_sections"])
                    if "characteristics" in rust_dict:
                        pe_info.characteristics = int(rust_dict["characteristics"])
                    if "is_pe32_plus" in rust_dict:
                        pe_info.is_pe32_plus = bool(rust_dict["is_pe32_plus"])
                return pe_info
            except Exception:
                logger.exception("Rust parse_pe failed for %s; using Python only", path)

        return self._parse_pe_python(path)

    def _parse_pe_python(self, path: Path) -> Optional[PEInfo]:
        """Pure-Python PE parser producing :class:`PEInfo`."""
        try:
            data = path.read_bytes()
        except OSError as exc:
            logger.warning("Could not read %s for PE parsing: %s", path, exc)
            return None

        if len(data) < 64:
            return None
        if data[:2] != b"MZ":
            return None

        pe = PEInfo(parser="python", size=len(data))

        pe.e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if pe.e_lfanew + 24 >= len(data):
            return None
        if data[pe.e_lfanew:pe.e_lfanew + 4] != b"PE\x00\x00":
            return None

        coff_off = pe.e_lfanew + 4
        (pe.machine, pe.num_sections, _timestamp, _sym_ptr, _num_syms,
         pe.optional_header_size, pe.characteristics) = struct.unpack_from(
            "<HHIIIHH", data, coff_off)
        pe.machine_name = _MACHINE_NAMES.get(pe.machine, f"unknown(0x{pe.machine:04x})")

        opt_off = coff_off + 20
        if pe.optional_header_size >= 2:
            opt_magic = struct.unpack_from("<H", data, opt_off)[0]
            pe.is_pe32_plus = (opt_magic == 0x20b)
            if opt_off + 20 < len(data):
                pe.entry_point = struct.unpack_from("<I", data, opt_off + 16)[0]
            if pe.is_pe32_plus and opt_off + 32 < len(data):
                pe.image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
            elif not pe.is_pe32_plus and opt_off + 32 < len(data):
                pe.image_base = struct.unpack_from("<I", data, opt_off + 28)[0]

        sec_off = opt_off + pe.optional_header_size
        SECTION_FMT = "<8sIIIIIIHHI"
        for i in range(pe.num_sections):
            off = sec_off + i * 40
            if off + 40 > len(data):
                break
            (name_bytes, vsize, vaddr, rsize, roff, _ptr_reloc, _ptr_line,
             _nreloc, _nline, chars) = struct.unpack_from(SECTION_FMT, data, off)
            name = name_bytes.rstrip(b"\x00").decode("latin-1", errors="replace")
            sec_entropy = 0.0
            if rsize > 0 and roff + rsize <= len(data):
                sec_entropy = self.compute_entropy(data[roff:roff + rsize])
            section = PESection(
                name=name,
                virtual_size=vsize,
                virtual_address=vaddr,
                raw_size=rsize,
                raw_offset=roff,
                characteristics=chars,
                entropy=sec_entropy,
            )
            pe.sections.append(section)

            if name.upper() in _SUSPICIOUS_SECTIONS:
                pe.suspicious_sections.append(name)
            if rsize > 0 and vsize > rsize * 4 and vsize > 1024:
                if not pe.packed_section:
                    pe.packed_section = (
                        f"section {name!r}: virtual_size={vsize} "
                        f">> raw_size={rsize} (likely packed)"
                    )
            if sec_entropy >= 7.0 and rsize >= 1024 and name not in (".rdata",):
                if not pe.packed_section:
                    pe.packed_section = (
                        f"section {name!r}: entropy={sec_entropy:.3f} "
                        f"(likely packed/encrypted)"
                    )

        pe.overall_entropy = self.compute_entropy(data)

        data_dir_off = opt_off + (112 if pe.is_pe32_plus else 96)
        if data_dir_off + 16 <= len(data):
            export_dir_rva, export_dir_size = struct.unpack_from("<II", data, data_dir_off)
            import_dir_rva, import_dir_size = struct.unpack_from("<II", data, data_dir_off + 8)
            file_offset_of = self._make_rva_resolver(pe.sections)
            if import_dir_rva and import_dir_size:
                self._parse_pe_imports(data, pe, import_dir_rva, file_offset_of)
            if export_dir_rva and export_dir_size:
                self._parse_pe_exports(data, pe, export_dir_rva, file_offset_of)

        pe.dll_imports = sorted({imp.dll for imp in pe.imports})
        pe.suspicious_imports = sorted({
            imp.function for imp in pe.imports
            if imp.function in _SUSPICIOUS_IMPORTS
        })

        return pe

    @staticmethod
    def _make_rva_resolver(sections: List[PESection]):
        """Return a callable(rva) -> file_offset, using the section table."""
        def resolve(rva: int) -> Optional[int]:
            for s in sections:
                if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
                    delta = rva - s.virtual_address
                    if s.raw_offset + delta < s.raw_offset + s.raw_size:
                        return s.raw_offset + delta
            return None
        return resolve

    def _parse_pe_imports(
        self,
        data: bytes,
        pe: PEInfo,
        import_dir_rva: int,
        rva_to_offset,
    ) -> None:
        """Parse the Import Directory Table.

        Each IDT entry is 20 bytes:
            OriginalFirstThunk (4, RVA to ILT)
            TimeDateStamp (4)
            ForwarderChain (4)
            Name (4, RVA to DLL name string)
            FirstThunk (4, RVA to IAT)

        We walk the array until we hit an all-zero entry (terminator).
        For each DLL, we walk its ILT to extract imported function names.
        """
        idt_off = rva_to_offset(import_dir_rva)
        if idt_off is None or idt_off + 20 > len(data):
            return

        idx = 0
        while True:
            entry_off = idt_off + idx * 20
            if entry_off + 20 > len(data):
                break
            (oft, _ts, _fwd, name_rva, _ft) = struct.unpack_from("<IIIII", data, entry_off)
            if oft == 0 and name_rva == 0:
                break  # terminator

            dll_name = self._read_cstr_at_rva(data, name_rva, rva_to_offset)
            if not dll_name:
                idx += 1
                continue

            thunk_rva = oft if oft else _ft
            thunk_off = rva_to_offset(thunk_rva)
            if thunk_off is None:
                idx += 1
                continue

            thunk_size = 8 if pe.is_pe32_plus else 4
            fmt = "<Q" if pe.is_pe32_plus else "<I"
            mask = 0xFFFFFFFFFFFFFFFF if pe.is_pe32_plus else 0xFFFFFFFF
            ordinal_flag = 0x8000000000000000 if pe.is_pe32_plus else 0x80000000

            t_idx = 0
            while True:
                t_off = thunk_off + t_idx * thunk_size
                if t_off + thunk_size > len(data):
                    break
                entry = struct.unpack_from(fmt, data, t_off)[0]
                if entry == 0:
                    break
                if entry & ordinal_flag:
                    ordinal = int(entry & 0xFFFF)
                    pe.imports.append(PEImport(dll=dll_name, function=f"#ordinal:{ordinal}", ordinal=ordinal))
                else:
                    name_off = rva_to_offset(int(entry & mask))
                    if name_off is not None and name_off + 2 < len(data):
                        end = data.find(b"\x00", name_off + 2)
                        if end != -1:
                            try:
                                fn_name = data[name_off + 2:end].decode("latin-1", errors="replace")
                            except Exception:
                                fn_name = ""
                            if fn_name:
                                pe.imports.append(PEImport(dll=dll_name, function=fn_name))
                t_idx += 1
                if t_idx > 4096:
                    break
            idx += 1
            if idx > 256:  # cap DLL count
                break

    def _parse_pe_exports(
        self,
        data: bytes,
        pe: PEInfo,
        export_dir_rva: int,
        rva_to_offset,
    ) -> None:
        """Parse the Export Directory.

        Layout (40 bytes):
            Characteristics (4), TimeDateStamp (4),
            MajorVersion (2), MinorVersion (2),
            Name (4, RVA to DLL name),
            Base (4),
            NumberOfFunctions (4),
            NumberOfNames (4),
            AddressOfFunctions (4, RVA),
            AddressOfNames (4, RVA to array of name RVAs),
            AddressOfNameOrdinals (4, RVA to array of ordinals)
        """
        edir_off = rva_to_offset(export_dir_rva)
        if edir_off is None or edir_off + 40 > len(data):
            return

        (_chars, _ts, _maj, _min, _name_rva, _base,
         _num_funcs, num_names,
         _addr_funcs, addr_names, _addr_ordinals) = struct.unpack_from(
            "<IIHHIIIIIII", data, edir_off
        )

        if num_names == 0:
            return
        names_off = rva_to_offset(addr_names)
        if names_off is None:
            return

        for i in range(min(num_names, 1024)):
            entry_off = names_off + i * 4
            if entry_off + 4 > len(data):
                break
            name_rva = struct.unpack_from("<I", data, entry_off)[0]
            name = self._read_cstr_at_rva(data, name_rva, rva_to_offset)
            if name:
                pe.exports.append(name)

    @staticmethod
    def _read_cstr_at_rva(data: bytes, rva: int, rva_to_offset) -> str:
        """Read a NUL-terminated ASCII string at the given RVA (best effort)."""
        off = rva_to_offset(rva)
        if off is None or off >= len(data):
            return ""
        end = data.find(b"\x00", off)
        if end == -1 or end - off > 256:
            return ""
        try:
            return data[off:end].decode("latin-1", errors="replace")
        except Exception:
            return ""
