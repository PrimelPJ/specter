"""
Office document malware analyzer.

Supports:
- OLE2 compound file format (legacy .doc, .xls, .ppt files)
  * Directory entry tree walking
  * VBA macro stream extraction and decompression (RLE compression)
  * Auto-exec macro detection (Document_Open, Auto_Open, Workbook_Open, etc.)
  * Suspicious keyword scanning in macro source
- OOXML format (.docx, .xlsx, .pptx — ZIP-based)
  * vbaProject.bin extraction and parsing
  * Relationship scanning for external targets
  * Content-type enumeration
- IOC extraction from document content
  * Embedded URLs
  * IP addresses
  * Base64-encoded payloads
  * Shell command patterns
"""

from __future__ import annotations

import hashlib
import io
import re
import struct
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# OLE2 magic bytes
OLE2_SIGNATURE = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"

# OOXML (ZIP) magic bytes
ZIP_SIGNATURE = b"PK\x03\x04"

# VBA compression constants
VBA_COMPRESSION_MAGIC = 0x01
VBA_SIGNATURE = b"Attribut"

# Suspicious VBA keywords indicative of malicious behavior
SUSPICIOUS_VBA_KEYWORDS = [
    "Shell", "CreateObject", "WScript.Shell", "PowerShell", "cmd.exe",
    "XMLHTTP", "WinHttp", "InternetExplorer", "Environ", "GetObject",
    "CallByName", "Execute", "eval", "Chr(", "ChrW(", "Asc(",
    "StrReverse", "Base64", "FromBase64String", "URLDownloadToFile",
    "URLDownloadToFileA", "WriteText", "ADODB.Stream", "Run(",
    "ShellExecute", "RegWrite", "RegRead", "AutoOpen", "Document_Open",
    "Workbook_Open", "Auto_Open", "Workbook_BeforeClose",
    "Document_Close", "Application.OnTime",
    "certutil", "mshta", "regsvr32", "rundll32", "wmic", "bitsadmin",
]

# Auto-execute macro entry points
AUTO_EXEC_NAMES = {
    "AutoOpen", "AutoClose", "AutoExec", "AutoExit",
    "Document_Open", "Document_Close", "DocumentOpen",
    "Workbook_Open", "Workbook_BeforeClose", "Workbook_Activate",
    "Auto_Open", "Auto_Close", "SheetActivate",
    "App_Workbook_Open",
}

_URL_RE = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_B64_RE = re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})')
_SHELL_RE = re.compile(
    r'(?:powershell|cmd\.exe|/c\s|/k\s|mshta|wscript|cscript|regsvr32|rundll32)',
    re.IGNORECASE,
)


class DocFormat(str, Enum):
    OLE2 = "OLE2"
    OOXML = "OOXML"
    UNKNOWN = "UNKNOWN"


@dataclass
class VBAModule:
    name: str
    source_code: str
    compressed_size: int
    decompressed_size: int
    has_auto_exec: bool = False
    suspicious_keywords: List[str] = field(default_factory=list)
    stream_path: str = ""

    @property
    def risk_score(self) -> int:
        score = 0
        if self.has_auto_exec:
            score += 40
        score += min(len(self.suspicious_keywords) * 5, 40)
        return min(score, 100)


@dataclass
class EmbeddedObject:
    name: str
    size: int
    sha256: str
    clsid: Optional[str] = None
    progid: Optional[str] = None


@dataclass
class OfficeMacroIOC:
    urls: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    base64_payloads: List[str] = field(default_factory=list)
    shell_commands: List[str] = field(default_factory=list)


@dataclass
class OfficeAnalysisResult:
    file_format: DocFormat
    sha256: str
    file_size: int

    has_macros: bool = False
    macro_modules: List[VBAModule] = field(default_factory=list)
    auto_exec_macros: List[str] = field(default_factory=list)
    suspicious_keywords: List[str] = field(default_factory=list)

    ole_streams: List[str] = field(default_factory=list)
    embedded_objects: List[EmbeddedObject] = field(default_factory=list)
    external_relationships: List[str] = field(default_factory=list)
    content_types: List[str] = field(default_factory=list)

    iocs: OfficeMacroIOC = field(default_factory=OfficeMacroIOC)

    errors: List[str] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        score = 0
        if self.has_macros:
            score += 20
        if self.auto_exec_macros:
            score += 30
        kw_score = min(len(set(self.suspicious_keywords)) * 3, 25)
        score += kw_score
        ioc_score = (
            min(len(self.iocs.urls) * 5, 15)
            + min(len(self.iocs.ips) * 3, 10)
            + min(len(self.iocs.base64_payloads) * 5, 10)
            + min(len(self.iocs.shell_commands) * 5, 10)
        )
        score += ioc_score
        return min(score, 100)

    @property
    def verdict(self) -> str:
        s = self.risk_score
        if s >= 70:
            return "malicious"
        if s >= 40:
            return "suspicious"
        if s >= 10:
            return "potentially_unwanted"
        return "clean"

    def to_dict(self) -> Dict:
        return {
            "file_format": self.file_format.value,
            "sha256": self.sha256,
            "file_size": self.file_size,
            "has_macros": self.has_macros,
            "macro_count": len(self.macro_modules),
            "auto_exec_macros": self.auto_exec_macros,
            "suspicious_keywords": sorted(set(self.suspicious_keywords)),
            "ole_streams": self.ole_streams,
            "embedded_objects": [
                {"name": e.name, "size": e.size, "sha256": e.sha256}
                for e in self.embedded_objects
            ],
            "external_relationships": self.external_relationships,
            "content_types": self.content_types,
            "iocs": {
                "urls": self.iocs.urls,
                "ips": self.iocs.ips,
                "base64_payloads": [p[:64] + "..." if len(p) > 64 else p for p in self.iocs.base64_payloads],
                "shell_commands": self.iocs.shell_commands,
            },
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# OLE2 parsing
# ---------------------------------------------------------------------------

class OLE2Header:
    """Parses the 512-byte OLE2 compound file header."""

    STRUCT = struct.Struct("<8s16sHHHHHHIIIIIIIIIIIIHH")
    SIZE = 512

    def __init__(self, data: bytes) -> None:
        fields = self.STRUCT.unpack_from(data)
        (
            self.signature, self.clsid, self.minor_version, self.dll_version,
            self.byte_order, self.sector_size_pow2, self.mini_sector_size_pow2,
            _reserved, self.dir_sectors, self.fat_sectors, self.first_dir_sector,
            self.transaction_sig, self.mini_stream_cutoff, self.first_minifat_sector,
            self.minifat_sectors, self.first_difat_sector, self.difat_sectors,
            *_rest,
        ) = fields
        self.sector_size = 1 << self.sector_size_pow2
        self.mini_sector_size = 1 << self.mini_sector_size_pow2

    @property
    def is_valid(self) -> bool:
        return self.signature == OLE2_SIGNATURE


@dataclass
class OLE2DirEntry:
    name: str
    entry_type: int  # 0=empty,1=storage,2=stream,5=root
    start_sector: int
    size: int
    clsid: bytes
    child_id: int
    left_sibling_id: int
    right_sibling_id: int


class OLE2Parser:
    """
    Minimal OLE2 compound file parser.

    Reads FAT chains to locate stream data and walks the directory tree
    to enumerate storage/stream entries by name.
    """

    DIRENT_STRUCT = struct.Struct("<64sHBBIIIQQIII16sII")
    FREESECT = 0xFFFFFFFF
    ENDOFCHAIN = 0xFFFFFFFE
    FATSECT = 0xFFFFFFFD
    DIFSECT = 0xFFFFFFFC

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._header = OLE2Header(data)
        self._fat: List[int] = []
        self._dir_entries: List[OLE2DirEntry] = []
        self._mini_stream_data: bytes = b""
        self._mini_fat: List[int] = []
        self._errors: List[str] = []

        if self._header.is_valid:
            self._load_fat()
            self._load_directory()
            self._load_mini_fat()

    def _sector_offset(self, sector: int) -> int:
        return (sector + 1) * self._header.sector_size

    def _read_sector(self, sector: int) -> bytes:
        off = self._sector_offset(sector)
        end = off + self._header.sector_size
        if end > len(self._data):
            return b"\x00" * self._header.sector_size
        return self._data[off:end]

    def _follow_chain(self, start: int) -> bytes:
        result = bytearray()
        sector = start
        visited = set()
        while sector not in (self.ENDOFCHAIN, self.FREESECT) and sector < len(self._fat):
            if sector in visited:
                self._errors.append(f"FAT chain loop at sector {sector}")
                break
            visited.add(sector)
            result.extend(self._read_sector(sector))
            sector = self._fat[sector]
        return bytes(result)

    def _load_fat(self) -> None:
        ss = self._header.sector_size
        entries_per_sector = ss // 4
        fat_sectors: List[int] = []

        # Read DIFAT sectors for large FATs
        difat_data = self._data[76: 76 + 109 * 4]
        for i in range(109):
            sid = struct.unpack_from("<I", difat_data, i * 4)[0]
            if sid in (self.FREESECT, self.ENDOFCHAIN):
                break
            fat_sectors.append(sid)

        next_difat = self._header.first_difat_sector
        while next_difat not in (self.ENDOFCHAIN, self.FREESECT):
            sector_data = self._read_sector(next_difat)
            for i in range(entries_per_sector - 1):
                sid = struct.unpack_from("<I", sector_data, i * 4)[0]
                if sid in (self.FREESECT, self.ENDOFCHAIN):
                    break
                fat_sectors.append(sid)
            next_difat = struct.unpack_from("<I", sector_data, (entries_per_sector - 1) * 4)[0]

        fat: List[int] = []
        for fs in fat_sectors:
            sector_data = self._read_sector(fs)
            for i in range(entries_per_sector):
                fat.append(struct.unpack_from("<I", sector_data, i * 4)[0])
        self._fat = fat

    def _load_directory(self) -> None:
        dir_data = self._follow_chain(self._header.first_dir_sector)
        entry_size = 128
        entries = []
        for i in range(0, len(dir_data), entry_size):
            chunk = dir_data[i: i + entry_size]
            if len(chunk) < entry_size:
                break
            fields = self.DIRENT_STRUCT.unpack_from(chunk)
            raw_name, name_len, etype, color, left, right, child, *_ = fields
            clsid = fields[13]
            start = fields[14]
            size = fields[15]

            name_len = min(name_len, 64)
            try:
                name = raw_name[: name_len].decode("utf-16-le").rstrip("\x00")
            except UnicodeDecodeError:
                name = f"<entry_{i // entry_size}>"
            entries.append(
                OLE2DirEntry(
                    name=name,
                    entry_type=etype,
                    start_sector=start,
                    size=size,
                    clsid=clsid,
                    child_id=child,
                    left_sibling_id=left,
                    right_sibling_id=right,
                )
            )
        self._dir_entries = entries

    def _load_mini_fat(self) -> None:
        if not self._dir_entries:
            return
        root = self._dir_entries[0]
        self._mini_stream_data = self._follow_chain(root.start_sector)[: root.size]

        mfat_data = self._follow_chain(self._header.first_minifat_sector)
        entries_per_sector = self._header.sector_size // 4
        for i in range(0, len(mfat_data), 4):
            if i + 4 > len(mfat_data):
                break
            self._mini_fat.append(struct.unpack_from("<I", mfat_data, i)[0])

    def _read_mini_stream(self, start: int, size: int) -> bytes:
        result = bytearray()
        sector = start
        ms = self._header.mini_sector_size
        visited: set = set()
        while sector not in (self.ENDOFCHAIN, self.FREESECT) and sector < len(self._mini_fat):
            if sector in visited:
                break
            visited.add(sector)
            off = sector * ms
            result.extend(self._mini_stream_data[off: off + ms])
            sector = self._mini_fat[sector]
        return bytes(result[:size])

    def get_stream(self, name: str) -> Optional[bytes]:
        """Return the raw bytes of a named stream."""
        for entry in self._dir_entries:
            if entry.name.lower() == name.lower() and entry.entry_type == 2:
                if entry.size < self._header.mini_stream_cutoff:
                    return self._read_mini_stream(entry.start_sector, entry.size)
                return self._follow_chain(entry.start_sector)[: entry.size]
        return None

    def stream_names(self) -> List[str]:
        return [e.name for e in self._dir_entries if e.entry_type == 2]

    def storage_names(self) -> List[str]:
        return [e.name for e in self._dir_entries if e.entry_type == 1]

    @property
    def errors(self) -> List[str]:
        return list(self._errors)


# ---------------------------------------------------------------------------
# VBA decompression (MS-OVBA RLE)
# ---------------------------------------------------------------------------

def _vba_decompress(data: bytes) -> bytes:
    """
    Decompress VBA RLE-compressed data per MS-OVBA specification.

    Each 4096-byte decompressed chunk is preceded by a 2-byte CompressedChunkHeader.
    The flag byte determines whether each token is a literal byte or a copy token.
    """
    out = bytearray()
    i = 0

    if not data or data[0] != VBA_COMPRESSION_MAGIC:
        return data  # not compressed, return as-is

    i = 1  # skip magic byte
    while i < len(data):
        if i + 2 > len(data):
            break
        chunk_header = struct.unpack_from("<H", data, i)[0]
        i += 2
        is_compressed = chunk_header & 0x8000
        chunk_size = (chunk_header & 0x0FFF) + 3

        if not is_compressed:
            out.extend(data[i: i + 4096])
            i += 4096
            continue

        chunk_start = len(out)
        chunk_end = i + chunk_size

        while i < chunk_end and i < len(data):
            flag_byte = data[i]
            i += 1
            for bit in range(8):
                if i >= chunk_end or i >= len(data):
                    break
                if (flag_byte >> bit) & 1:
                    # copy token
                    if i + 2 > len(data):
                        break
                    token = struct.unpack_from("<H", data, i)[0]
                    i += 2
                    decompressed_so_far = len(out) - chunk_start
                    length_mask, offset_mask, bit_count = _copy_token_help(decompressed_so_far)
                    length = (token & length_mask) + 3
                    raw_offset = (token & offset_mask) >> bit_count
                    copy_offset = raw_offset + 1
                    src = len(out) - copy_offset
                    for k in range(length):
                        if src + k < len(out):
                            out.append(out[src + k])
                        else:
                            break
                else:
                    out.append(data[i])
                    i += 1
    return bytes(out)


def _copy_token_help(decompressed_so_far: int) -> Tuple[int, int, int]:
    """Return (length_mask, offset_mask, bit_count) for VBA copy token decoding."""
    if decompressed_so_far <= 16:
        return 0x000F, 0xFFF0, 4
    if decompressed_so_far <= 32:
        return 0x001F, 0xFFE0, 5
    if decompressed_so_far <= 64:
        return 0x003F, 0xFFC0, 6
    if decompressed_so_far <= 128:
        return 0x007F, 0xFF80, 7
    if decompressed_so_far <= 256:
        return 0x00FF, 0xFF00, 8
    if decompressed_so_far <= 512:
        return 0x01FF, 0xFE00, 9
    if decompressed_so_far <= 1024:
        return 0x03FF, 0xFC00, 10
    if decompressed_so_far <= 2048:
        return 0x07FF, 0xF800, 11
    return 0x0FFF, 0xF000, 12


# ---------------------------------------------------------------------------
# VBA stream parser
# ---------------------------------------------------------------------------

def _extract_vba_modules(ole: OLE2Parser) -> List[VBAModule]:
    """
    Locate and extract VBA modules from an OLE2 compound document.

    Searches for streams named 'VBA/thisXxx', 'VBA/Module*', and '_VBA_PROJECT'
    in the directory. For each module stream, skips the MODULE header and
    decompresses the source code.
    """
    modules: List[VBAModule] = []
    vba_stream_names = [
        n for n in ole.stream_names()
        if re.match(r'^(this|sheet|module|vba)', n, re.IGNORECASE)
        or n.lower() in ("thisdocument", "thisworkbook", "sheet1", "module1")
    ]

    for name in ole.stream_names():
        raw = ole.get_stream(name)
        if not raw:
            continue
        # Look for compressed VBA code offset marker
        offset = raw.find(b"\x00Attribut")
        if offset == -1:
            offset = raw.find(VBA_SIGNATURE)
        if offset == -1:
            continue

        # Skip possible p-code prefix by finding compression magic
        magic_offset = raw.find(b"\x01", offset)
        if magic_offset == -1 or magic_offset > offset + 256:
            compressed_data = raw[offset:]
        else:
            compressed_data = raw[magic_offset:]

        try:
            source = _vba_decompress(compressed_data).decode("latin-1", errors="replace")
        except Exception:
            source = raw[offset:].decode("latin-1", errors="replace")

        keywords_found = [kw for kw in SUSPICIOUS_VBA_KEYWORDS if kw.lower() in source.lower()]
        has_auto = any(ae.lower() in source.lower() for ae in AUTO_EXEC_NAMES)

        modules.append(
            VBAModule(
                name=name,
                source_code=source,
                compressed_size=len(raw),
                decompressed_size=len(source),
                has_auto_exec=has_auto,
                suspicious_keywords=keywords_found,
                stream_path=name,
            )
        )
    return modules


# ---------------------------------------------------------------------------
# IOC extraction
# ---------------------------------------------------------------------------

def _extract_iocs(text: str) -> OfficeMacroIOC:
    ioc = OfficeMacroIOC()
    ioc.urls = list({m.group() for m in _URL_RE.finditer(text)})
    ioc.ips = list({m.group() for m in _IP_RE.finditer(text)})
    ioc.base64_payloads = list({m.group() for m in _B64_RE.finditer(text) if len(m.group()) >= 40})
    ioc.shell_commands = list({m.group() for m in _SHELL_RE.finditer(text)})
    return ioc


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class OfficeAnalyzer:
    """
    Static analyzer for Office documents.

    Detects macros, auto-exec entry points, suspicious keywords, and IOCs
    in both OLE2 (legacy binary) and OOXML (ZIP-based) Office formats.
    """

    def analyze(self, data: bytes, filename: str = "") -> OfficeAnalysisResult:
        sha256 = hashlib.sha256(data).hexdigest()
        fmt = self._detect_format(data)

        result = OfficeAnalysisResult(
            file_format=fmt,
            sha256=sha256,
            file_size=len(data),
        )

        if fmt == DocFormat.OLE2:
            self._analyze_ole2(data, result)
        elif fmt == DocFormat.OOXML:
            self._analyze_ooxml(data, result)
        else:
            result.errors.append("Unrecognized file format — not OLE2 or OOXML")

        return result

    def _detect_format(self, data: bytes) -> DocFormat:
        if data[:8] == OLE2_SIGNATURE:
            return DocFormat.OLE2
        if data[:4] == ZIP_SIGNATURE:
            return DocFormat.OOXML
        return DocFormat.UNKNOWN

    def _analyze_ole2(self, data: bytes, result: OfficeAnalysisResult) -> None:
        try:
            ole = OLE2Parser(data)
        except Exception as exc:
            result.errors.append(f"OLE2 parse error: {exc}")
            return

        result.ole_streams = ole.stream_names()
        result.errors.extend(ole.errors)

        modules = _extract_vba_modules(ole)
        if modules:
            result.has_macros = True
            result.macro_modules = modules
            all_keywords: List[str] = []
            full_source = ""
            for m in modules:
                all_keywords.extend(m.suspicious_keywords)
                full_source += m.source_code + "\n"
                if m.has_auto_exec:
                    result.auto_exec_macros.append(m.name)
            result.suspicious_keywords = list(set(all_keywords))
            result.iocs = _extract_iocs(full_source)

        # Check for embedded objects (OLE storage entries that look like OLE objects)
        for entry_name in ole.storage_names():
            raw = ole.get_stream(entry_name)
            if raw and len(raw) > 4:
                result.embedded_objects.append(
                    EmbeddedObject(
                        name=entry_name,
                        size=len(raw),
                        sha256=hashlib.sha256(raw).hexdigest(),
                    )
                )

    def _analyze_ooxml(self, data: bytes, result: OfficeAnalysisResult) -> None:
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except Exception as exc:
            result.errors.append(f"OOXML ZIP parse error: {exc}")
            return

        names = zf.namelist()
        result.content_types = names

        # Scan relationships files for external targets
        for name in names:
            if name.endswith(".rels"):
                try:
                    rels_content = zf.read(name).decode("utf-8", errors="replace")
                    ext_targets = re.findall(r'Target="(https?://[^"]+)"', rels_content)
                    result.external_relationships.extend(ext_targets)
                except Exception:
                    pass

        # Extract and analyze vbaProject.bin if present
        vba_bin_names = [n for n in names if n.lower().endswith("vbaproject.bin")]
        for vba_bin_name in vba_bin_names:
            try:
                vba_data = zf.read(vba_bin_name)
                inner_result = OfficeAnalysisResult(
                    file_format=DocFormat.OLE2,
                    sha256=hashlib.sha256(vba_data).hexdigest(),
                    file_size=len(vba_data),
                )
                self._analyze_ole2(vba_data, inner_result)
                result.has_macros = inner_result.has_macros
                result.macro_modules.extend(inner_result.macro_modules)
                result.auto_exec_macros.extend(inner_result.auto_exec_macros)
                result.suspicious_keywords.extend(inner_result.suspicious_keywords)
                result.ole_streams.extend(inner_result.ole_streams)
                # Merge IOCs
                result.iocs.urls.extend(inner_result.iocs.urls)
                result.iocs.ips.extend(inner_result.iocs.ips)
                result.iocs.base64_payloads.extend(inner_result.iocs.base64_payloads)
                result.iocs.shell_commands.extend(inner_result.iocs.shell_commands)
            except Exception as exc:
                result.errors.append(f"vbaProject.bin analysis error: {exc}")

        # Scan all XML files for IOCs
        all_xml = ""
        for name in names:
            if name.endswith((".xml", ".rels", ".vml")):
                try:
                    all_xml += zf.read(name).decode("utf-8", errors="replace") + "\n"
                except Exception:
                    pass
        xml_iocs = _extract_iocs(all_xml)
        result.iocs.urls = list(set(result.iocs.urls + xml_iocs.urls))
        result.iocs.ips = list(set(result.iocs.ips + xml_iocs.ips))
        result.iocs.shell_commands = list(set(result.iocs.shell_commands + xml_iocs.shell_commands))
