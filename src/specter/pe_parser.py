"""
PE (Portable Executable) file static analyzer.
Parses DOS/PE headers, section table, import/export tables, resources,
and extracts strings, detects packers, and computes indicators.
"""

from __future__ import annotations

import hashlib
import io
import math
import re
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# PE Format constants
DOS_SIGNATURE = b"MZ"
PE_SIGNATURE = b"PE\x00\x00"

IMAGE_FILE_MACHINE = {
    0x014C: "i386",
    0x0200: "IA64",
    0x8664: "AMD64",
    0x01C0: "ARM",
    0xAA64: "ARM64",
}

IMAGE_SUBSYSTEM = {
    0: "UNKNOWN",
    1: "NATIVE",
    2: "WINDOWS_GUI",
    3: "WINDOWS_CUI",
    5: "OS2_CUI",
    7: "POSIX_CUI",
    9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION",
    11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER",
    14: "XBOX",
    16: "WINDOWS_BOOT_APPLICATION",
}

IMAGE_CHARACTERISTICS = {
    0x0001: "RELOCS_STRIPPED",
    0x0002: "EXECUTABLE_IMAGE",
    0x0004: "LINE_NUMS_STRIPPED",
    0x0008: "LOCAL_SYMS_STRIPPED",
    0x0020: "LARGE_ADDRESS_AWARE",
    0x0100: "32BIT_MACHINE",
    0x0200: "DEBUG_STRIPPED",
    0x1000: "SYSTEM",
    0x2000: "DLL",
    0x4000: "UP_SYSTEM_ONLY",
}

SECTION_CHARACTERISTICS = {
    0x00000020: "CODE",
    0x00000040: "INITIALIZED_DATA",
    0x00000080: "UNINITIALIZED_DATA",
    0x04000000: "NO_CACHE",
    0x08000000: "NO_PAGE",
    0x10000000: "SHARED",
    0x20000000: "EXECUTE",
    0x40000000: "READ",
    0x80000000: "WRITE",
}

# Known packer signatures (name -> list of byte patterns as hex)
PACKER_SIGNATURES: Dict[str, List[bytes]] = {
    "UPX": [b"UPX0", b"UPX1", b"UPX2", b"UPX!"],
    "MPRESS": [b"MPRESS1", b"MPRESS2"],
    "ASPack": [b"\x60\xe8\x00\x00\x00\x00\x5d\x81\xed"],
    "PECompact": [b"PEC2"],
    "Themida": [b"Themida"],
    "VMProtect": [b"VMProtect"],
    "Obsidium": [b".obsidium"],
    "Armadillo": [b"ArmAccess", b"Silicon Realms"],
    "NSPack": [b"NSPack"],
    "PEtite": [b"PEtite"],
}

_INTERESTING_STRING_PATTERN = re.compile(
    rb"(?:"
    rb"(?:https?|ftp|smtp)://[^\x00-\x1f\x7f-\xff]{4,}"  # URLs
    rb"|(?:[a-zA-Z0-9\-\.]+\.(?:exe|dll|bat|ps1|vbs|cmd|scr|pif|hta|jar)){1}"  # Executables
    rb"|(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)[^\x00]{4,64})"  # Registry
    rb"|(?:[A-Z]:\\[^\x00\x0a\x0d]{4,128})"  # Windows paths
    rb"|(?:/etc/[^\x00\x0a\x0d]{2,64})"  # Unix paths
    rb"|(?:SELECT\s+\*\s+FROM|DROP\s+TABLE|INSERT\s+INTO)"  # SQL
    rb"|(?:cmd\.exe|powershell|wscript|cscript|regsvr32|mshta|certutil)"
    rb")"
)


class PEParseError(Exception):
    pass


@dataclass
class DOSHeader:
    magic: bytes
    e_cblp: int
    e_cp: int
    e_cparhdr: int
    e_minalloc: int
    e_maxalloc: int
    e_ss: int
    e_sp: int
    e_ip: int
    e_cs: int
    e_lfanew: int  # Offset to PE header


@dataclass
class COFFHeader:
    machine: int
    number_of_sections: int
    time_date_stamp: int
    pointer_to_symbol_table: int
    number_of_symbols: int
    size_of_optional_header: int
    characteristics: int

    @property
    def machine_name(self) -> str:
        return IMAGE_FILE_MACHINE.get(self.machine, f"UNKNOWN(0x{self.machine:04x})")

    @property
    def timestamp_dt(self) -> str:
        try:
            import datetime
            return datetime.datetime.utcfromtimestamp(self.time_date_stamp).isoformat() + "Z"
        except (ValueError, OSError):
            return f"<invalid: {self.time_date_stamp}>"

    @property
    def characteristic_flags(self) -> List[str]:
        return [
            name for mask, name in IMAGE_CHARACTERISTICS.items()
            if self.characteristics & mask
        ]


@dataclass
class OptionalHeader:
    magic: int  # 0x010B = PE32, 0x020B = PE32+
    major_linker_version: int
    minor_linker_version: int
    size_of_code: int
    size_of_initialized_data: int
    size_of_uninitialized_data: int
    address_of_entry_point: int
    base_of_code: int
    image_base: int
    section_alignment: int
    file_alignment: int
    major_os_version: int
    minor_os_version: int
    major_image_version: int
    minor_image_version: int
    major_subsystem_version: int
    minor_subsystem_version: int
    size_of_image: int
    size_of_headers: int
    checksum: int
    subsystem: int
    dll_characteristics: int
    size_of_stack_reserve: int
    size_of_stack_commit: int
    size_of_heap_reserve: int
    size_of_heap_commit: int
    number_of_rva_and_sizes: int
    data_directories: List[Tuple[int, int]]  # (RVA, Size) pairs

    @property
    def is_64bit(self) -> bool:
        return self.magic == 0x020B

    @property
    def subsystem_name(self) -> str:
        return IMAGE_SUBSYSTEM.get(self.subsystem, f"UNKNOWN({self.subsystem})")


@dataclass
class SectionHeader:
    name: str
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    characteristics: int
    entropy: float = 0.0
    md5: str = ""

    @property
    def characteristic_flags(self) -> List[str]:
        return [
            name for mask, name in SECTION_CHARACTERISTICS.items()
            if self.characteristics & mask
        ]

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)

    @property
    def is_writable(self) -> bool:
        return bool(self.characteristics & 0x80000000)

    @property
    def is_suspicious(self) -> bool:
        return self.is_executable and self.is_writable


@dataclass
class ImportEntry:
    dll_name: str
    functions: List[str] = field(default_factory=list)
    is_suspicious: bool = False


@dataclass
class ExportEntry:
    name: str
    ordinal: int
    rva: int


@dataclass
class PEFile:
    """Fully parsed PE file with all headers and extracted indicators."""
    data: bytes
    dos_header: DOSHeader
    coff_header: COFFHeader
    optional_header: OptionalHeader
    sections: List[SectionHeader]
    imports: List[ImportEntry] = field(default_factory=list)
    exports: List[ExportEntry] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    detected_packers: List[str] = field(default_factory=list)
    overlay_data: Optional[bytes] = None
    overlay_entropy: float = 0.0

    # Hashes
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    imphash: str = ""

    @property
    def file_size(self) -> int:
        return len(self.data)

    @property
    def is_dll(self) -> bool:
        return bool(self.coff_header.characteristics & 0x2000)

    @property
    def is_64bit(self) -> bool:
        return self.optional_header.is_64bit

    @property
    def has_overlay(self) -> bool:
        return self.overlay_data is not None and len(self.overlay_data) > 0

    @property
    def suspicious_sections(self) -> List[SectionHeader]:
        return [s for s in self.sections if s.is_suspicious or s.entropy > 7.0]

    @property
    def suspicious_imports(self) -> List[ImportEntry]:
        return [i for i in self.imports if i.is_suspicious]

    @property
    def risk_indicators(self) -> List[str]:
        indicators = []
        if self.detected_packers:
            indicators.append(f"Packer: {', '.join(self.detected_packers)}")
        for sec in self.suspicious_sections:
            if sec.entropy > 7.0:
                indicators.append(f"High entropy section: {sec.name} ({sec.entropy:.2f})")
            if sec.is_suspicious:
                indicators.append(f"RWX section: {sec.name}")
        for imp in self.suspicious_imports:
            indicators.append(f"Suspicious import: {imp.dll_name}")
        if self.has_overlay and self.overlay_entropy > 6.5:
            indicators.append(f"High entropy overlay ({self.overlay_entropy:.2f})")
        if self.coff_header.time_date_stamp == 0:
            indicators.append("Zero compile timestamp (possible manual modification)")
        return indicators

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_size": self.file_size,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "imphash": self.imphash,
            "is_dll": self.is_dll,
            "is_64bit": self.is_64bit,
            "machine": self.coff_header.machine_name,
            "compile_timestamp": self.coff_header.timestamp_dt,
            "subsystem": self.optional_header.subsystem_name,
            "entry_point": hex(self.optional_header.address_of_entry_point),
            "image_base": hex(self.optional_header.image_base),
            "sections": [
                {
                    "name": s.name,
                    "virtual_size": s.virtual_size,
                    "raw_size": s.size_of_raw_data,
                    "entropy": s.entropy,
                    "characteristics": s.characteristic_flags,
                    "is_suspicious": s.is_suspicious,
                }
                for s in self.sections
            ],
            "imports": [
                {"dll": i.dll_name, "function_count": len(i.functions), "suspicious": i.is_suspicious}
                for i in self.imports
            ],
            "exports": [{"name": e.name, "ordinal": e.ordinal} for e in self.exports],
            "detected_packers": self.detected_packers,
            "has_overlay": self.has_overlay,
            "overlay_entropy": self.overlay_entropy,
            "risk_indicators": self.risk_indicators,
            "interesting_strings_count": len(self.strings),
        }


# DLLs whose imports indicate suspicious capability
_SUSPICIOUS_DLLS = {
    "kernel32.dll": {
        "suspicious_funcs": {
            "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory",
            "CreateRemoteThread", "NtUnmapViewOfSection", "SetWindowsHookEx",
            "OpenProcess", "ReadProcessMemory", "AdjustTokenPrivileges",
        }
    },
    "wininet.dll": {"suspicious_funcs": set()},
    "ws2_32.dll": {"suspicious_funcs": {"WSAStartup", "connect", "send", "recv", "WSASend"}},
    "advapi32.dll": {
        "suspicious_funcs": {
            "RegCreateKeyEx", "RegSetValueEx", "CreateServiceA",
            "OpenSCManagerA", "StartServiceA",
        }
    },
    "ntdll.dll": {
        "suspicious_funcs": {
            "NtCreateSection", "NtMapViewOfSection", "NtWriteVirtualMemory",
            "NtCreateThreadEx", "NtQueueApcThread",
        }
    },
    "shell32.dll": {"suspicious_funcs": {"ShellExecuteA", "ShellExecuteW"}},
    "urlmon.dll": {"suspicious_funcs": {"URLDownloadToFileA", "URLDownloadToFileW"}},
    "crypt32.dll": {"suspicious_funcs": set()},
}


class PEParser:
    """
    Full PE file parser using struct-based binary parsing.
    No external dependencies required.
    """

    def __init__(self, min_string_length: int = 5) -> None:
        self.min_string_length = min_string_length

    def parse(self, data: bytes) -> PEFile:
        """Parse PE file bytes and return a fully analyzed PEFile."""
        if len(data) < 64:
            raise PEParseError(f"File too small to be a PE: {len(data)} bytes")
        if data[:2] != DOS_SIGNATURE:
            raise PEParseError("Missing MZ signature")

        buf = io.BytesIO(data)

        dos = self._parse_dos_header(buf)
        pe_offset = dos.e_lfanew

        if pe_offset < 64 or pe_offset > len(data) - 24:
            raise PEParseError(f"Invalid PE header offset: {pe_offset:#x}")

        buf.seek(pe_offset)
        sig = buf.read(4)
        if sig != PE_SIGNATURE:
            raise PEParseError(f"Invalid PE signature at offset {pe_offset:#x}")

        coff = self._parse_coff_header(buf)
        opt = self._parse_optional_header(buf, coff.size_of_optional_header)
        sections = self._parse_sections(buf, coff.number_of_sections, data)
        imports = self._parse_imports(data, opt, sections)
        exports = self._parse_exports(data, opt, sections)
        strings = self._extract_strings(data)
        packers = self._detect_packers(data, sections)
        overlay, overlay_entropy = self._extract_overlay(data, sections)

        pe = PEFile(
            data=data,
            dos_header=dos,
            coff_header=coff,
            optional_header=opt,
            sections=sections,
            imports=imports,
            exports=exports,
            strings=strings,
            detected_packers=packers,
            overlay_data=overlay,
            overlay_entropy=overlay_entropy,
        )

        # Compute hashes
        pe.md5 = hashlib.md5(data).hexdigest()
        pe.sha1 = hashlib.sha1(data).hexdigest()
        pe.sha256 = hashlib.sha256(data).hexdigest()
        pe.imphash = self._compute_imphash(imports)

        return pe

    def _parse_dos_header(self, buf: io.BytesIO) -> DOSHeader:
        buf.seek(0)
        raw = buf.read(64)
        if len(raw) < 64:
            raise PEParseError("Truncated DOS header")
        fields = struct.unpack_from("<2sHHHHHHHHHHHHHHHHHHHHHHHHHHHHHI", raw)
        return DOSHeader(
            magic=fields[0],
            e_cblp=fields[1],
            e_cp=fields[2],
            e_cparhdr=fields[4],
            e_minalloc=fields[5],
            e_maxalloc=fields[6],
            e_ss=fields[8],
            e_sp=fields[9],
            e_ip=fields[11],
            e_cs=fields[12],
            e_lfanew=fields[30],
        )

    def _parse_coff_header(self, buf: io.BytesIO) -> COFFHeader:
        raw = buf.read(20)
        if len(raw) < 20:
            raise PEParseError("Truncated COFF header")
        machine, num_sections, timestamp, sym_ptr, num_sym, opt_size, chars = \
            struct.unpack_from("<HHIIIHH", raw)
        return COFFHeader(
            machine=machine,
            number_of_sections=num_sections,
            time_date_stamp=timestamp,
            pointer_to_symbol_table=sym_ptr,
            number_of_symbols=num_sym,
            size_of_optional_header=opt_size,
            characteristics=chars,
        )

    def _parse_optional_header(self, buf: io.BytesIO, opt_size: int) -> OptionalHeader:
        if opt_size < 28:
            raise PEParseError(f"Optional header too small: {opt_size}")

        raw = buf.read(opt_size)
        if len(raw) < opt_size:
            raise PEParseError("Truncated optional header")

        magic = struct.unpack_from("<H", raw)[0]
        is_pe32_plus = magic == 0x020B

        if is_pe32_plus:
            if opt_size < 112:
                raise PEParseError("PE32+ optional header too small")
            (magic, maj_link, min_link, size_code, size_init, size_uninit,
             entry_point, base_code, image_base) = struct.unpack_from("<HBBIIIII Q", raw, 0)
            (sec_align, file_align) = struct.unpack_from("<II", raw, 32)
            (maj_os, min_os, maj_img, min_img, maj_sub, min_sub) = \
                struct.unpack_from("<HHHHHH", raw, 40)
            (size_img, size_hdr, checksum, subsystem, dll_chars) = \
                struct.unpack_from("<IIIHH", raw, 56)
            (stack_res, stack_com, heap_res, heap_com) = \
                struct.unpack_from("<QQQQ", raw, 72)
            num_dirs = struct.unpack_from("<I", raw, 108)[0]
        else:
            if opt_size < 96:
                raise PEParseError("PE32 optional header too small")
            (magic, maj_link, min_link, size_code, size_init, size_uninit,
             entry_point, base_code, base_data, image_base) = struct.unpack_from("<HBBIIIIIII", raw, 0)
            (sec_align, file_align) = struct.unpack_from("<II", raw, 32)
            (maj_os, min_os, maj_img, min_img, maj_sub, min_sub) = \
                struct.unpack_from("<HHHHHH", raw, 40)
            (size_img, size_hdr, checksum, subsystem, dll_chars) = \
                struct.unpack_from("<IIIHH", raw, 56)
            (stack_res, stack_com, heap_res, heap_com) = \
                struct.unpack_from("<IIII", raw, 72)
            num_dirs = struct.unpack_from("<I", raw, 92)[0]

        # Parse data directories
        dir_offset = 108 if is_pe32_plus else 96
        num_dirs = min(num_dirs, 16)
        data_dirs = []
        for i in range(num_dirs):
            offset = dir_offset + i * 8
            if offset + 8 <= len(raw):
                rva, size = struct.unpack_from("<II", raw, offset)
                data_dirs.append((rva, size))
            else:
                data_dirs.append((0, 0))

        while len(data_dirs) < 16:
            data_dirs.append((0, 0))

        return OptionalHeader(
            magic=magic,
            major_linker_version=maj_link,
            minor_linker_version=min_link,
            size_of_code=size_code,
            size_of_initialized_data=size_init,
            size_of_uninitialized_data=size_uninit,
            address_of_entry_point=entry_point,
            base_of_code=base_code,
            image_base=image_base,
            section_alignment=sec_align,
            file_alignment=file_align,
            major_os_version=maj_os,
            minor_os_version=min_os,
            major_image_version=maj_img,
            minor_image_version=min_img,
            major_subsystem_version=maj_sub,
            minor_subsystem_version=min_sub,
            size_of_image=size_img,
            size_of_headers=size_hdr,
            checksum=checksum,
            subsystem=subsystem,
            dll_characteristics=dll_chars,
            size_of_stack_reserve=stack_res,
            size_of_stack_commit=stack_com,
            size_of_heap_reserve=heap_res,
            size_of_heap_commit=heap_com,
            number_of_rva_and_sizes=num_dirs,
            data_directories=data_dirs,
        )

    def _parse_sections(
        self, buf: io.BytesIO, count: int, data: bytes
    ) -> List[SectionHeader]:
        sections = []
        for _ in range(min(count, 96)):
            raw = buf.read(40)
            if len(raw) < 40:
                break
            name_bytes = raw[:8].rstrip(b"\x00")
            name = name_bytes.decode("ascii", errors="replace")
            (virt_size, virt_addr, raw_size, raw_ptr, _reloc, _lnno, _nreloc, _nlnno, chars) = \
                struct.unpack_from("<IIIIIIHHI", raw, 8)

            section = SectionHeader(
                name=name,
                virtual_size=virt_size,
                virtual_address=virt_addr,
                size_of_raw_data=raw_size,
                pointer_to_raw_data=raw_ptr,
                characteristics=chars,
            )

            if raw_ptr > 0 and raw_size > 0:
                end = min(raw_ptr + raw_size, len(data))
                sec_data = data[raw_ptr:end]
                if sec_data:
                    section.entropy = self._calc_entropy(sec_data)
                    section.md5 = hashlib.md5(sec_data).hexdigest()

            sections.append(section)
        return sections

    def _parse_imports(
        self, data: bytes, opt: OptionalHeader, sections: List[SectionHeader]
    ) -> List[ImportEntry]:
        if len(opt.data_directories) < 2:
            return []

        import_rva, import_size = opt.data_directories[1]
        if import_rva == 0 or import_size == 0:
            return []

        raw_off = self._rva_to_offset(import_rva, sections)
        if raw_off is None:
            return []

        imports = []
        offset = raw_off

        while offset + 20 <= len(data):
            (orig_first_thunk, timestamp, forwarder, name_rva, first_thunk) = \
                struct.unpack_from("<IIIII", data, offset)

            if name_rva == 0:
                break

            name_off = self._rva_to_offset(name_rva, sections)
            if name_off is None:
                offset += 20
                continue

            dll_name = self._read_cstring(data, name_off).lower()
            if not dll_name:
                offset += 20
                continue

            functions = self._parse_import_thunks(
                data, orig_first_thunk or first_thunk, opt.is_64bit, sections
            )

            is_suspicious = False
            if dll_name in _SUSPICIOUS_DLLS:
                suspicious_funcs = _SUSPICIOUS_DLLS[dll_name]["suspicious_funcs"]
                if not suspicious_funcs or any(f in suspicious_funcs for f in functions):
                    is_suspicious = bool(suspicious_funcs) and bool(
                        set(functions) & suspicious_funcs
                    )
                # Network DLLs are always suspicious
                if dll_name in ("wininet.dll", "crypt32.dll"):
                    is_suspicious = True

            imports.append(ImportEntry(
                dll_name=dll_name,
                functions=functions,
                is_suspicious=is_suspicious,
            ))
            offset += 20

        return imports

    def _parse_import_thunks(
        self,
        data: bytes,
        thunk_rva: int,
        is_64bit: bool,
        sections: List[SectionHeader],
    ) -> List[str]:
        if thunk_rva == 0:
            return []

        thunk_off = self._rva_to_offset(thunk_rva, sections)
        if thunk_off is None:
            return []

        functions = []
        entry_size = 8 if is_64bit else 4
        max_imports = 1000

        for i in range(max_imports):
            off = thunk_off + i * entry_size
            if off + entry_size > len(data):
                break

            if is_64bit:
                value = struct.unpack_from("<Q", data, off)[0]
            else:
                value = struct.unpack_from("<I", data, off)[0]

            if value == 0:
                break

            ordinal_flag = (1 << 63) if is_64bit else (1 << 31)
            if value & ordinal_flag:
                functions.append(f"Ordinal_{value & 0xFFFF}")
                continue

            hint_rva = value & (0x7FFFFFFFFFFFFFFF if is_64bit else 0x7FFFFFFF)
            hint_off = self._rva_to_offset(hint_rva, sections)
            if hint_off is not None and hint_off + 2 < len(data):
                func_name = self._read_cstring(data, hint_off + 2)
                if func_name:
                    functions.append(func_name)

        return functions

    def _parse_exports(
        self, data: bytes, opt: OptionalHeader, sections: List[SectionHeader]
    ) -> List[ExportEntry]:
        if len(opt.data_directories) < 1:
            return []

        export_rva, export_size = opt.data_directories[0]
        if export_rva == 0:
            return []

        raw_off = self._rva_to_offset(export_rva, sections)
        if raw_off is None or raw_off + 40 > len(data):
            return []

        (_, _, _, _, _, num_funcs, num_names, func_rva, names_rva, ordinals_rva) = \
            struct.unpack_from("<IIIIIIIIII", data, raw_off)

        names_off = self._rva_to_offset(names_rva, sections)
        ordinals_off = self._rva_to_offset(ordinals_rva, sections)
        funcs_off = self._rva_to_offset(func_rva, sections)

        exports = []
        if names_off is None or ordinals_off is None or funcs_off is None:
            return exports

        for i in range(min(num_names, 1000)):
            if names_off + (i + 1) * 4 > len(data):
                break
            if ordinals_off + (i + 1) * 2 > len(data):
                break

            name_rva_entry = struct.unpack_from("<I", data, names_off + i * 4)[0]
            ordinal = struct.unpack_from("<H", data, ordinals_off + i * 2)[0]

            name_off = self._rva_to_offset(name_rva_entry, sections)
            name = ""
            if name_off is not None:
                name = self._read_cstring(data, name_off)

            func_off_entry = funcs_off + ordinal * 4
            func_rva_val = 0
            if func_off_entry + 4 <= len(data):
                func_rva_val = struct.unpack_from("<I", data, func_off_entry)[0]

            exports.append(ExportEntry(name=name, ordinal=ordinal, rva=func_rva_val))

        return exports

    def _extract_strings(self, data: bytes) -> List[str]:
        """Extract interesting strings using regex patterns."""
        found = []
        for match in _INTERESTING_STRING_PATTERN.finditer(data):
            try:
                s = match.group().decode("ascii", errors="ignore").strip()
                if len(s) >= self.min_string_length:
                    found.append(s)
            except Exception:
                pass
        return list(dict.fromkeys(found))[:500]  # deduplicate, cap at 500

    def _detect_packers(self, data: bytes, sections: List[SectionHeader]) -> List[str]:
        """Detect known packer signatures in binary data and section names."""
        found = []
        for packer, signatures in PACKER_SIGNATURES.items():
            for sig in signatures:
                if sig in data[:0x10000]:  # check first 64KB
                    found.append(packer)
                    break

        # Check for section name packer indicators
        section_names = {s.name.lower() for s in sections}
        if "upx0" in section_names or "upx1" in section_names:
            if "UPX" not in found:
                found.append("UPX")
        if ".aspack" in section_names:
            found.append("ASPack")

        # Heuristic: all high-entropy sections with few imports = packed
        if not found and sections:
            avg_entropy = sum(s.entropy for s in sections) / len(sections)
            if avg_entropy > 6.8:
                found.append("Unknown/Heuristic")

        return found

    def _extract_overlay(
        self, data: bytes, sections: List[SectionHeader]
    ) -> Tuple[Optional[bytes], float]:
        """Extract any data appended after the last PE section."""
        if not sections:
            return None, 0.0

        last_section_end = max(
            (s.pointer_to_raw_data + s.size_of_raw_data)
            for s in sections
            if s.pointer_to_raw_data > 0
        )
        if last_section_end >= len(data):
            return None, 0.0

        overlay = data[last_section_end:]
        if len(overlay) < 4:
            return None, 0.0

        entropy = self._calc_entropy(overlay)
        return overlay, entropy

    @staticmethod
    def _rva_to_offset(
        rva: int, sections: List[SectionHeader]
    ) -> Optional[int]:
        """Convert a Relative Virtual Address to a file offset."""
        for sec in sections:
            if sec.virtual_address <= rva < sec.virtual_address + max(sec.virtual_size, sec.size_of_raw_data):
                return sec.pointer_to_raw_data + (rva - sec.virtual_address)
        return None

    @staticmethod
    def _read_cstring(data: bytes, offset: int, max_len: int = 256) -> str:
        """Read a null-terminated ASCII string from offset."""
        end = data.find(b"\x00", offset, offset + max_len)
        if end == -1:
            end = min(offset + max_len, len(data))
        try:
            return data[offset:end].decode("ascii", errors="ignore")
        except Exception:
            return ""

    @staticmethod
    def _calc_entropy(data: bytes) -> float:
        """Shannon entropy of a byte sequence."""
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        entropy = 0.0
        for count in freq:
            if count:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def _compute_imphash(imports: List[ImportEntry]) -> str:
        """Compute import hash (imphash) for malware family clustering."""
        if not imports:
            return ""
        parts = []
        for imp in imports:
            dll = imp.dll_name.lower()
            if dll.endswith(".dll"):
                dll = dll[:-4]
            for func in imp.functions:
                parts.append(f"{dll}.{func.lower()}")
        if not parts:
            return ""
        return hashlib.md5(",".join(sorted(parts)).encode()).hexdigest()
