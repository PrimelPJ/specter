"""
Windows process memory dump analyzer.

Parses MINIDUMP (.dmp) files and raw memory snapshots to detect:
  - Injected PE images loaded outside known module paths
  - Inline API hooks (JMP/CALL patches at function entry points)
  - Suspicious strings in non-image executable regions
  - Private executable memory not backed by any file on disk
"""

from __future__ import annotations

import io
import re
import struct
from dataclasses import dataclass, field
from enum import IntFlag
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# MINIDUMP format constants  (MSDN: MINIDUMP_HEADER / MINIDUMP_DIRECTORY)
# ---------------------------------------------------------------------------

MINIDUMP_SIGNATURE = 0x504D444D  # "MDMP"
MINIDUMP_VERSION = 0xA793

# Stream type IDs
STREAM_UNUSED = 0
STREAM_THREAD_LIST = 3
STREAM_MODULE_LIST = 4
STREAM_MEMORY64_LIST = 9
STREAM_MEMORY_LIST = 5
STREAM_SYSTEM_INFO = 7
STREAM_EXCEPTION = 6

# Page protection flags (VirtualAlloc / VirtualQuery)
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100

EXECUTABLE_PROTECTIONS: Set[int] = {
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
}

# Memory type flags
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000

# x86/x64 JMP / CALL opcodes that indicate inline hooks
JMP_OPCODE = 0xE9    # relative JMP rel32
CALL_OPCODE = 0xE8   # relative CALL rel32
JMP_SHORT = 0xEB     # short JMP rel8
MOV_RAX_JMP = (0x48, 0xB8)  # MOV RAX, imm64 followed by JMP RAX (x64 trampoline)

# Minimum printable string length for extraction
MIN_STRING_LEN = 6


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class MemoryRegion:
    """A single virtual memory region from MINIDUMP_MEMORY_INFO or raw scan."""

    base_address: int
    region_size: int
    protect: int           # current page protection
    type: int              # MEM_IMAGE | MEM_MAPPED | MEM_PRIVATE
    state: int             # MEM_COMMIT = 0x1000, MEM_FREE = 0x10000, MEM_RESERVE = 0x2000
    module_path: str = ""  # filled when region backs a loaded module
    data: bytes = b""      # raw bytes (may be empty for reserved regions)

    @property
    def is_executable(self) -> bool:
        return (self.protect & 0xFF) in EXECUTABLE_PROTECTIONS

    @property
    def is_private(self) -> bool:
        return self.type == MEM_PRIVATE

    @property
    def is_image(self) -> bool:
        return self.type == MEM_IMAGE

    @property
    def end_address(self) -> int:
        return self.base_address + self.region_size

    @property
    def has_data(self) -> bool:
        return len(self.data) > 0

    def address_str(self) -> str:
        return f"0x{self.base_address:016X}"


@dataclass
class LoadedModule:
    """A module record from the MINIDUMP_MODULE_LIST stream."""

    base_address: int
    size: int
    name: str
    timestamp: int = 0
    checksum: int = 0

    @property
    def end_address(self) -> int:
        return self.base_address + self.size

    def contains(self, address: int) -> bool:
        return self.base_address <= address < self.end_address


@dataclass
class HookFinding:
    """Detected inline hook at a function entry point."""

    region_base: int
    hook_offset: int          # offset within the region's data
    absolute_address: int
    hook_type: str            # "JMP_REL32", "CALL_REL32", "JMP_SHORT", "MOV_RAX_JMP"
    original_bytes: bytes     # first 8 bytes at the hook location
    jump_target: int          # resolved target address (0 if not computable)
    target_module: str = ""   # module name if target is inside a known module

    def address_str(self) -> str:
        return f"0x{self.absolute_address:016X}"

    def target_str(self) -> str:
        return f"0x{self.jump_target:016X}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "absolute_address": self.address_str(),
            "hook_type": self.hook_type,
            "original_bytes": self.original_bytes.hex(),
            "jump_target": self.target_str(),
            "target_module": self.target_module,
        }


@dataclass
class InjectionFinding:
    """PE image or shellcode found in a private/non-image executable region."""

    region_base: int
    region_size: int
    injection_type: str   # "PE_IMAGE", "SHELLCODE", "REFLECTIVE_DLL"
    pe_dos_offset: int = 0
    suspected_name: str = ""
    entropy: float = 0.0
    extracted_strings: List[str] = field(default_factory=list)
    hooks: List[HookFinding] = field(default_factory=list)

    def address_str(self) -> str:
        return f"0x{self.region_base:016X}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_address": self.address_str(),
            "region_size": self.region_size,
            "injection_type": self.injection_type,
            "suspected_name": self.suspected_name,
            "entropy": round(self.entropy, 4),
            "extracted_strings": self.extracted_strings[:20],
            "hooks": [h.to_dict() for h in self.hooks],
        }


@dataclass
class MemoryAnalysisReport:
    """Full analysis result for a single memory dump."""

    source: str
    is_minidump: bool
    modules: List[LoadedModule] = field(default_factory=list)
    regions: List[MemoryRegion] = field(default_factory=list)
    injections: List[InjectionFinding] = field(default_factory=list)
    hooks: List[HookFinding] = field(default_factory=list)
    suspicious_strings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def threat_score(self) -> int:
        """
        Heuristic threat score 0-100 based on finding counts and types.
        """
        score = 0
        score += min(40, len(self.injections) * 15)
        score += min(30, len(self.hooks) * 5)
        score += min(20, len(self.suspicious_strings) * 2)
        for inj in self.injections:
            if inj.injection_type == "REFLECTIVE_DLL":
                score += 10
        return min(100, score)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "is_minidump": self.is_minidump,
            "threat_score": self.threat_score,
            "module_count": len(self.modules),
            "region_count": len(self.regions),
            "injections": [i.to_dict() for i in self.injections],
            "hooks": [h.to_dict() for h in self.hooks],
            "suspicious_strings": self.suspicious_strings[:50],
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

class _StructReader:
    """Lightweight struct reader with bounds checking."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    @property
    def pos(self) -> int:
        return self._pos

    def seek(self, offset: int) -> None:
        self._pos = offset

    def remaining(self) -> int:
        return len(self._data) - self._pos

    def read(self, n: int) -> bytes:
        chunk = self._data[self._pos: self._pos + n]
        self._pos += n
        return chunk

    def unpack(self, fmt: str) -> Tuple:
        size = struct.calcsize(fmt)
        chunk = self._data[self._pos: self._pos + size]
        if len(chunk) < size:
            raise struct.error(f"Need {size} bytes, only {len(chunk)} available at 0x{self._pos:X}")
        self._pos += size
        return struct.unpack(fmt, chunk)

    def read_utf16le_string(self, length_bytes: int) -> str:
        raw = self.read(length_bytes)
        try:
            return raw.decode("utf-16-le").rstrip("\x00")
        except UnicodeDecodeError:
            return raw.hex()

    def read_at(self, offset: int, fmt: str) -> Tuple:
        size = struct.calcsize(fmt)
        chunk = self._data[offset: offset + size]
        if len(chunk) < size:
            raise struct.error(f"Need {size} bytes at 0x{offset:X}")
        return struct.unpack(fmt, chunk)

    def bytes_at(self, offset: int, n: int) -> bytes:
        return self._data[offset: offset + n]


def _calc_entropy(data: bytes) -> float:
    """Shannon entropy of a byte buffer (0.0–8.0)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / length
            entropy -= p * (p.bit_length() - 1 + (p & (p - 1) > 0))
    # Use a log2 approximation via math-free integer bit_length
    import math
    entropy = 0.0
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


def _extract_ascii_strings(data: bytes, min_len: int = MIN_STRING_LEN) -> List[str]:
    """Extract printable ASCII strings of at least min_len characters."""
    pattern = re.compile(rb"[ -~]{" + str(min_len).encode() + rb",}")
    return [m.group().decode("ascii") for m in pattern.finditer(data)]


def _extract_wide_strings(data: bytes, min_len: int = MIN_STRING_LEN) -> List[str]:
    """Extract UTF-16LE strings of at least min_len characters."""
    results = []
    i = 0
    buf = []
    while i < len(data) - 1:
        lo = data[i]
        hi = data[i + 1]
        if hi == 0 and 0x20 <= lo <= 0x7E:
            buf.append(chr(lo))
            i += 2
        else:
            if len(buf) >= min_len:
                results.append("".join(buf))
            buf = []
            i += 1
    if len(buf) >= min_len:
        results.append("".join(buf))
    return results


# Suspicious string patterns: network IOC indicators, process injection APIs, etc.
_SUSPICIOUS_PATTERNS = [
    re.compile(rb"https?://[^\x00\s\"]{8,}", re.IGNORECASE),
    re.compile(rb"(?:cmd\.exe|powershell|wscript|cscript|mshta|regsvr32)", re.IGNORECASE),
    re.compile(rb"(?:VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection)", re.IGNORECASE),
    re.compile(rb"(?:LoadLibrary|GetProcAddress|SetWindowsHookEx|OpenProcess)", re.IGNORECASE),
    re.compile(rb"(?:\\Device\\Nsi|\\GLOBAL\?\?\\)", re.IGNORECASE),
    re.compile(rb"(?:mimikatz|sekurlsa|lsadump|kerberos::)", re.IGNORECASE),
    re.compile(rb"(?:HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon)", re.IGNORECASE),
    re.compile(rb"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}"),
]


def _scan_suspicious_strings(
    data: bytes, base_address: int
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for pattern in _SUSPICIOUS_PATTERNS:
        for m in pattern.finditer(data):
            findings.append(
                {
                    "address": f"0x{base_address + m.start():016X}",
                    "pattern": pattern.pattern.decode(errors="replace"),
                    "match": m.group().decode(errors="replace")[:200],
                }
            )
    return findings


# ---------------------------------------------------------------------------
# PE detection helpers
# ---------------------------------------------------------------------------

def _find_pe_headers(data: bytes) -> List[int]:
    """Return all offsets in data that look like a PE DOS stub (MZ + valid e_lfanew)."""
    offsets: List[int] = []
    i = 0
    while i < len(data) - 64:
        i = data.find(b"MZ", i)
        if i < 0:
            break
        if i + 60 <= len(data) - 4:
            (e_lfanew,) = struct.unpack_from("<I", data, i + 60)
            pe_off = i + e_lfanew
            if 0 < e_lfanew < 0x400 and pe_off + 4 <= len(data):
                sig = data[pe_off: pe_off + 4]
                if sig == b"PE\x00\x00":
                    offsets.append(i)
        i += 2
    return offsets


def _is_reflective_dll(data: bytes, dos_offset: int) -> bool:
    """
    Heuristic: a reflective DLL loader often exports a function called
    "ReflectiveDLLInjection" or contains the reflective loader stub.
    """
    window = data[dos_offset: dos_offset + 0x4000]
    return b"ReflectiveDLL" in window or b"ReflectiveLoader" in window


def _parse_pe_name(data: bytes, dos_offset: int) -> str:
    """Try to extract the original filename from PE version or export directory."""
    window = data[dos_offset: dos_offset + min(0x8000, len(data) - dos_offset)]
    # Look for OriginalFilename in VS_VERSIONINFO
    m = re.search(rb"O\x00r\x00i\x00g\x00i\x00n\x00a\x00l\x00F\x00i\x00l\x00e\x00n\x00a\x00m\x00e\x00"
                  rb"\x00\x00.{0,4}((?:[^\x00].){1,64})\x00\x00", window)
    if m:
        try:
            return m.group(1).decode("utf-16-le").strip()
        except UnicodeDecodeError:
            pass
    return ""


# ---------------------------------------------------------------------------
# Hook detection
# ---------------------------------------------------------------------------

def _detect_hooks(
    data: bytes,
    base_address: int,
    modules: List[LoadedModule],
    scan_size: int = 0x10000,
) -> List[HookFinding]:
    """
    Scan the first `scan_size` bytes of a region for JMP/CALL hook patterns
    that redirect execution to a different memory region.
    """
    hooks: List[HookFinding] = []
    check_data = data[:scan_size]
    i = 0
    while i < len(check_data) - 8:
        b = check_data[i]
        abs_addr = base_address + i

        if b == JMP_OPCODE and i + 5 <= len(check_data):
            # E9 rel32 — relative JMP
            (rel,) = struct.unpack_from("<i", check_data, i + 1)
            target = abs_addr + 5 + rel
            hook_type = "JMP_REL32"
        elif b == CALL_OPCODE and i + 5 <= len(check_data):
            (rel,) = struct.unpack_from("<i", check_data, i + 1)
            target = abs_addr + 5 + rel
            hook_type = "CALL_REL32"
        elif b == JMP_SHORT and i + 2 <= len(check_data):
            rel = struct.unpack_from("<b", check_data, i + 1)[0]
            target = abs_addr + 2 + rel
            hook_type = "JMP_SHORT"
        elif (b == MOV_RAX_JMP[0] and i + 1 < len(check_data)
              and check_data[i + 1] == MOV_RAX_JMP[1] and i + 12 <= len(check_data)):
            # 48 B8 imm64 — MOV RAX, imm64
            (target,) = struct.unpack_from("<Q", check_data, i + 2)
            hook_type = "MOV_RAX_JMP"
        else:
            i += 1
            continue

        # Only report if the target falls outside the region being scanned
        if not (base_address <= target < base_address + len(data)):
            target_mod = _module_at(target, modules)
            hooks.append(
                HookFinding(
                    region_base=base_address,
                    hook_offset=i,
                    absolute_address=abs_addr,
                    hook_type=hook_type,
                    original_bytes=check_data[i: i + 8],
                    jump_target=target,
                    target_module=target_mod,
                )
            )
        i += 1
    return hooks


def _module_at(address: int, modules: List[LoadedModule]) -> str:
    for mod in modules:
        if mod.contains(address):
            return mod.name
    return ""


# ---------------------------------------------------------------------------
# MINIDUMP parser
# ---------------------------------------------------------------------------

class _MinidumpParser:
    """Parses the MINIDUMP_HEADER + stream directory into typed records."""

    HEADER_FMT = "<IHHIIIq"  # Signature, Version, NumberOfStreams, StreamDirectoryRva, Checksum, TimeDateStamp, Flags
    HEADER_SIZE = struct.calcsize(HEADER_FMT)
    DIR_ENTRY_FMT = "<IIQ"   # StreamType, DataSize, Rva
    DIR_ENTRY_SIZE = struct.calcsize(DIR_ENTRY_FMT)

    def __init__(self, data: bytes) -> None:
        self._r = _StructReader(data)
        self._data = data
        self.modules: List[LoadedModule] = []
        self.regions: List[MemoryRegion] = []
        self.errors: List[str] = []

    def parse(self) -> None:
        try:
            (sig, ver, num_streams, dir_rva, checksum, ts, flags) = self._r.read_at(0, self.HEADER_FMT)
        except struct.error as e:
            self.errors.append(f"Header parse error: {e}")
            return

        if sig != MINIDUMP_SIGNATURE:
            self.errors.append(f"Invalid MDMP signature: 0x{sig:08X}")
            return

        for i in range(num_streams):
            offset = dir_rva + i * self.DIR_ENTRY_SIZE
            try:
                (stream_type, data_size, rva) = self._r.read_at(offset, self.DIR_ENTRY_FMT)
            except struct.error as e:
                self.errors.append(f"Directory entry {i} parse error: {e}")
                continue
            try:
                if stream_type == STREAM_MODULE_LIST:
                    self._parse_module_list(int(rva), data_size)
                elif stream_type == STREAM_MEMORY_LIST:
                    self._parse_memory_list(int(rva), data_size)
                elif stream_type == STREAM_MEMORY64_LIST:
                    self._parse_memory64_list(int(rva), data_size)
            except Exception as e:
                self.errors.append(f"Stream type {stream_type} parse error: {e}")

    def _parse_module_list(self, rva: int, size: int) -> None:
        (num_modules,) = struct.unpack_from("<I", self._data, rva)
        offset = rva + 4
        # MINIDUMP_MODULE: BaseOfImage(8), SizeOfImage(4), CheckSum(4), TimeDateStamp(4),
        # ModuleNameRva(4), VersionInfo(52), CvRecord(8), MiscRecord(8), Reserved0(8), Reserved1(8)
        MOD_FMT = "<QIIIII"  # partial: BaseOfImage, SizeOfImage, CheckSum, TimeDateStamp, ModuleNameRva
        MOD_ENTRY_SIZE = 108  # full MINIDUMP_MODULE is 108 bytes
        for i in range(num_modules):
            mod_off = offset + i * MOD_ENTRY_SIZE
            try:
                (base, img_size, checksum, ts, name_rva) = struct.unpack_from(MOD_FMT, self._data, mod_off)
                name = self._read_minidump_string(name_rva)
                self.modules.append(
                    LoadedModule(base_address=base, size=img_size, name=name, timestamp=ts, checksum=checksum)
                )
            except struct.error:
                pass

    def _read_minidump_string(self, rva: int) -> str:
        if rva == 0 or rva >= len(self._data) - 4:
            return ""
        (length,) = struct.unpack_from("<I", self._data, rva)
        raw = self._data[rva + 4: rva + 4 + length]
        try:
            return raw.decode("utf-16-le")
        except UnicodeDecodeError:
            return ""

    def _parse_memory_list(self, rva: int, size: int) -> None:
        (num_ranges,) = struct.unpack_from("<I", self._data, rva)
        offset = rva + 4
        # MINIDUMP_MEMORY_DESCRIPTOR: StartOfMemoryRange(8), Memory(MINIDUMP_LOCATION_DESCRIPTOR: Size(4), Rva(4))
        DESC_FMT = "<QII"
        DESC_SIZE = struct.calcsize(DESC_FMT)
        for i in range(num_ranges):
            off = offset + i * DESC_SIZE
            try:
                (start, mem_size, mem_rva) = struct.unpack_from(DESC_FMT, self._data, off)
                raw = self._data[mem_rva: mem_rva + mem_size]
                self.regions.append(
                    MemoryRegion(
                        base_address=start,
                        region_size=mem_size,
                        protect=PAGE_EXECUTE_READ,  # not available in MemoryList
                        type=MEM_PRIVATE,
                        state=0x1000,
                        data=raw,
                    )
                )
            except struct.error:
                pass

    def _parse_memory64_list(self, rva: int, size: int) -> None:
        # MINIDUMP_MEMORY64_LIST: NumberOfMemoryRanges(8), BaseRva(8), then descriptors
        (num_ranges, base_rva) = struct.unpack_from("<QQ", self._data, rva)
        offset = rva + 16
        DESC_FMT = "<QQ"  # StartOfMemoryRange, DataSize
        DESC_SIZE = struct.calcsize(DESC_FMT)
        current_rva = int(base_rva)
        for i in range(int(num_ranges)):
            off = offset + i * DESC_SIZE
            try:
                (start, data_size) = struct.unpack_from(DESC_FMT, self._data, off)
                raw = self._data[current_rva: current_rva + data_size]
                self.regions.append(
                    MemoryRegion(
                        base_address=start,
                        region_size=int(data_size),
                        protect=PAGE_EXECUTE_READ,
                        type=MEM_PRIVATE,
                        state=0x1000,
                        data=raw,
                    )
                )
                current_rva += int(data_size)
            except struct.error:
                pass


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class MemoryAnalyzer:
    """
    Analyzes Windows process memory dumps for malicious indicators.

    Supports:
    - Full MINIDUMP (.dmp) files with MDMP header
    - Raw memory snapshots (flat binary blobs)
    - Manually supplied MemoryRegion lists for unit testing

    Usage::
        analyzer = MemoryAnalyzer()
        report = analyzer.analyze_file("/path/to/dump.dmp")
        print(report.threat_score)
    """

    def __init__(
        self,
        scan_hooks: bool = True,
        scan_injections: bool = True,
        scan_strings: bool = True,
        max_region_size_for_strings: int = 64 * 1024 * 1024,  # 64 MB
    ) -> None:
        self.scan_hooks = scan_hooks
        self.scan_injections = scan_injections
        self.scan_strings = scan_strings
        self.max_region_size_for_strings = max_region_size_for_strings

    def analyze_file(self, path: str) -> MemoryAnalysisReport:
        with open(path, "rb") as fh:
            data = fh.read()
        return self.analyze_bytes(data, source=path)

    def analyze_bytes(self, data: bytes, source: str = "<buffer>") -> MemoryAnalysisReport:
        is_minidump, modules, regions, errors = self._parse_dump(data)
        return self._analyze_regions(
            source=source, is_minidump=is_minidump, modules=modules, regions=regions, errors=errors
        )

    def analyze_regions(
        self,
        regions: List[MemoryRegion],
        modules: Optional[List[LoadedModule]] = None,
        source: str = "<manual>",
    ) -> MemoryAnalysisReport:
        return self._analyze_regions(
            source=source,
            is_minidump=False,
            modules=modules or [],
            regions=regions,
            errors=[],
        )

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #

    def _parse_dump(
        self, data: bytes
    ) -> Tuple[bool, List[LoadedModule], List[MemoryRegion], List[str]]:
        """Detect dump type and delegate to the right parser."""
        if len(data) >= 4:
            (sig,) = struct.unpack_from("<I", data, 0)
            if sig == MINIDUMP_SIGNATURE:
                parser = _MinidumpParser(data)
                parser.parse()
                return True, parser.modules, parser.regions, parser.errors

        # Raw dump: treat the whole blob as one region at address 0
        region = MemoryRegion(
            base_address=0,
            region_size=len(data),
            protect=PAGE_EXECUTE_READ,
            type=MEM_PRIVATE,
            state=0x1000,
            data=data,
        )
        return False, [], [region], []

    def _analyze_regions(
        self,
        source: str,
        is_minidump: bool,
        modules: List[LoadedModule],
        regions: List[MemoryRegion],
        errors: List[str],
    ) -> MemoryAnalysisReport:
        report = MemoryAnalysisReport(
            source=source, is_minidump=is_minidump, modules=modules, regions=regions, errors=errors
        )

        for region in regions:
            if not region.has_data:
                continue
            if self.scan_injections:
                injections = self._detect_injections(region, modules)
                report.injections.extend(injections)
            if self.scan_hooks and region.is_executable:
                hooks = _detect_hooks(region.data, region.base_address, modules)
                report.hooks.extend(hooks)
            if self.scan_strings and region.is_executable and region.region_size <= self.max_region_size_for_strings:
                suspicious = _scan_suspicious_strings(region.data, region.base_address)
                report.suspicious_strings.extend(suspicious)

        return report

    def _detect_injections(
        self, region: MemoryRegion, modules: List[LoadedModule]
    ) -> List[InjectionFinding]:
        findings: List[InjectionFinding] = []

        if not region.is_executable:
            return findings

        # Image regions backed by a known module are legitimate
        if region.is_image and any(
            m.base_address == region.base_address for m in modules
        ):
            return findings

        # Look for PE headers in the region
        pe_offsets = _find_pe_headers(region.data)
        if pe_offsets:
            for dos_off in pe_offsets:
                reflective = _is_reflective_dll(region.data, dos_off)
                inj_type = "REFLECTIVE_DLL" if reflective else "PE_IMAGE"
                name = _parse_pe_name(region.data, dos_off)
                strings = _extract_ascii_strings(region.data[dos_off: dos_off + 0x10000])
                strings += _extract_wide_strings(region.data[dos_off: dos_off + 0x10000])
                hooks = []
                if self.scan_hooks:
                    hooks = _detect_hooks(region.data, region.base_address, modules)
                findings.append(
                    InjectionFinding(
                        region_base=region.base_address,
                        region_size=region.region_size,
                        injection_type=inj_type,
                        pe_dos_offset=dos_off,
                        suspected_name=name,
                        entropy=_calc_entropy(region.data[:0x10000]),
                        extracted_strings=strings[:30],
                        hooks=hooks,
                    )
                )
        elif region.is_private and region.is_executable:
            # No PE header — could be shellcode or a packed payload
            entropy = _calc_entropy(region.data[:0x4000])
            # Only flag if entropy is high (packed/encrypted) or contains suspicious patterns
            suspicious = _scan_suspicious_strings(region.data[:0x4000], region.base_address)
            if entropy > 6.5 or suspicious:
                strings = _extract_ascii_strings(region.data[:0x4000])
                findings.append(
                    InjectionFinding(
                        region_base=region.base_address,
                        region_size=region.region_size,
                        injection_type="SHELLCODE",
                        entropy=entropy,
                        extracted_strings=strings[:20],
                    )
                )

        return findings
