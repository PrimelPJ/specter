"""
ELF (Executable and Linkable Format) static analyzer.
Parses ELF headers, section/program tables, symbol tables, dynamic linking info,
computes section entropy, detects packers, stripped binaries, and suspicious indicators.
Supports both 32-bit and 64-bit ELF files (little-endian and big-endian).
"""

from __future__ import annotations

import hashlib
import io
import math
import re
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple

# ELF magic bytes
ELF_MAGIC = b"\x7fELF"

# EI_CLASS values
ELFCLASS32 = 1
ELFCLASS64 = 2

# EI_DATA values
ELFDATA2LSB = 1  # Little-endian
ELFDATA2MSB = 2  # Big-endian

# ELF file types
ET_NONE = 0
ET_REL  = 1
ET_EXEC = 2
ET_DYN  = 3
ET_CORE = 4

ELF_TYPE_NAMES: Dict[int, str] = {
    ET_NONE: "NONE",
    ET_REL:  "REL",
    ET_EXEC: "EXEC",
    ET_DYN:  "DYN",
    ET_CORE: "CORE",
}

# e_machine values
EM_NONE    = 0
EM_386     = 3
EM_MIPS    = 8
EM_PPC     = 20
EM_PPC64   = 21
EM_ARM     = 40
EM_X86_64  = 62
EM_AARCH64 = 183
EM_RISCV   = 243

ELF_MACHINE_NAMES: Dict[int, str] = {
    EM_NONE:    "NONE",
    EM_386:     "i386",
    EM_MIPS:    "MIPS",
    EM_PPC:     "PowerPC",
    EM_PPC64:   "PowerPC64",
    EM_ARM:     "ARM",
    EM_X86_64:  "x86-64",
    EM_AARCH64: "AArch64",
    EM_RISCV:   "RISC-V",
}

# Section header types
SHT_NULL     = 0
SHT_PROGBITS = 1
SHT_SYMTAB   = 2
SHT_STRTAB   = 3
SHT_RELA     = 4
SHT_HASH     = 5
SHT_DYNAMIC  = 6
SHT_NOTE     = 7
SHT_NOBITS   = 8
SHT_REL      = 9
SHT_DYNSYM   = 11
SHT_INIT_ARRAY   = 14
SHT_FINI_ARRAY   = 15
SHT_GNU_HASH     = 0x6FFFFFF6
SHT_GNU_VERSYM   = 0x6FFFFFFF
SHT_GNU_VERNEED  = 0x6FFFFFFE
SHT_GNU_VERDEF   = 0x6FFFFFFD

SHT_NAMES: Dict[int, str] = {
    SHT_NULL: "NULL", SHT_PROGBITS: "PROGBITS", SHT_SYMTAB: "SYMTAB",
    SHT_STRTAB: "STRTAB", SHT_RELA: "RELA", SHT_HASH: "HASH",
    SHT_DYNAMIC: "DYNAMIC", SHT_NOTE: "NOTE", SHT_NOBITS: "NOBITS",
    SHT_REL: "REL", SHT_DYNSYM: "DYNSYM", SHT_INIT_ARRAY: "INIT_ARRAY",
    SHT_FINI_ARRAY: "FINI_ARRAY", SHT_GNU_HASH: "GNU_HASH",
    SHT_GNU_VERSYM: "GNU_VERSYM", SHT_GNU_VERNEED: "GNU_VERNEED",
    SHT_GNU_VERDEF: "GNU_VERDEF",
}

# Section flags
SHF_WRITE     = 0x1
SHF_ALLOC     = 0x2
SHF_EXECINSTR = 0x4
SHF_MERGE     = 0x10
SHF_STRINGS   = 0x20

# Program header types
PT_NULL    = 0
PT_LOAD    = 1
PT_DYNAMIC = 2
PT_INTERP  = 3
PT_NOTE    = 4
PT_PHDR    = 6
PT_TLS     = 7
PT_GNU_EH_FRAME = 0x6474E550
PT_GNU_STACK    = 0x6474E551
PT_GNU_RELRO    = 0x6474E552

PT_NAMES: Dict[int, str] = {
    PT_NULL: "NULL", PT_LOAD: "LOAD", PT_DYNAMIC: "DYNAMIC",
    PT_INTERP: "INTERP", PT_NOTE: "NOTE", PT_PHDR: "PHDR", PT_TLS: "TLS",
    PT_GNU_EH_FRAME: "GNU_EH_FRAME", PT_GNU_STACK: "GNU_STACK",
    PT_GNU_RELRO: "GNU_RELRO",
}

# Dynamic tag types
DT_NULL    = 0
DT_NEEDED  = 1
DT_RPATH   = 15
DT_RUNPATH = 29
DT_FLAGS   = 30
DT_FLAGS_1 = 0x6FFFFFFB
DT_SONAME  = 14
DT_DEBUG   = 21

# Symbol binding
STB_LOCAL  = 0
STB_GLOBAL = 1
STB_WEAK   = 2

# Symbol type
STT_NOTYPE  = 0
STT_OBJECT  = 1
STT_FUNC    = 2
STT_SECTION = 3
STT_FILE    = 4
STT_COMMON  = 5
STT_TLS     = 6

# Symbol visibility
STV_DEFAULT   = 0
STV_INTERNAL  = 1
STV_HIDDEN    = 2
STV_PROTECTED = 3

# Known suspicious symbols associated with rootkits / backdoors
SUSPICIOUS_SYMBOLS: List[Tuple[str, str]] = [
    ("ptrace",           "Anti-debugging via ptrace check"),
    ("prctl",            "Process attribute manipulation (anti-debug/sandbox evasion)"),
    ("mprotect",         "Memory permission change (shellcode staging)"),
    ("mmap",             "Anonymous memory mapping (code injection)"),
    ("dlopen",           "Dynamic library loading (plugin/backdoor loading)"),
    ("system",           "Shell command execution"),
    ("popen",            "Shell command execution via pipe"),
    ("execve",           "Process execution"),
    ("execvp",           "Process execution"),
    ("fork",             "Process forking (daemon/backdoor persistence)"),
    ("setuid",           "Privilege escalation"),
    ("setgid",           "Privilege escalation"),
    ("socket",           "Network socket creation"),
    ("connect",          "Network connection"),
    ("bind",             "Network listener binding"),
    ("recv",             "Network data receive"),
    ("send",             "Network data send"),
    ("getenv",           "Environment variable access"),
    ("unlink",           "File deletion"),
    ("chmod",            "File permission change"),
    ("chown",            "File ownership change"),
    ("inotify_init",     "File system event monitoring (surveillance)"),
    ("LD_PRELOAD",       "LD_PRELOAD injection string"),
    ("LD_LIBRARY_PATH",  "Library path override"),
    ("__libc_start_main","Potential libc hijack point"),
    ("fopen",            "File read/write"),
    ("freopen",          "File redirection"),
    ("getaddrinfo",      "DNS resolution"),
    ("gethostbyname",    "DNS resolution"),
    ("setsockopt",       "Socket option manipulation"),
    ("epoll_create",     "Event polling (C2 loop indicator)"),
    ("pthread_create",   "Thread creation (backdoor worker threads)"),
    ("nanosleep",        "Sleep/timing evasion"),
    ("signal",           "Signal handler manipulation"),
    ("sigaction",        "Signal handler manipulation"),
    ("alarm",            "Timed execution / watchdog"),
    ("getpid",           "Process enumeration"),
    ("getppid",          "Parent process detection (sandbox evasion)"),
    ("readlink",         "Symlink resolution (path traversal)"),
    ("opendir",          "Directory enumeration"),
    ("readdir",          "Directory enumeration"),
    ("sysinfo",          "System information gathering"),
    ("uname",            "OS fingerprinting"),
]

# Known packer/obfuscator section names
PACKER_SECTIONS: List[Tuple[str, str]] = [
    ("UPX0",    "UPX packer"),
    ("UPX1",    "UPX packer"),
    ("UPX2",    "UPX packer"),
    (".UPX",    "UPX packer"),
    (".packed", "Custom packer"),
    (".crypted","Encrypted section (custom packer/protector)"),
    (".enigma", "Enigma protector"),
    (".nsp0",   "NsPack packer"),
    (".nsp1",   "NsPack packer"),
    ("themida", "Themida/WinLicense protector"),
]

# High-entropy threshold indicating packed/encrypted data
HIGH_ENTROPY_THRESHOLD = 7.0


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ELFIdent:
    """Parsed EI_* identity bytes from the 16-byte e_ident field."""
    magic: bytes
    ei_class: int          # 1=32-bit, 2=64-bit
    ei_data: int           # 1=LE, 2=BE
    ei_version: int
    ei_osabi: int
    ei_abiversion: int

    @property
    def bits(self) -> int:
        return 32 if self.ei_class == ELFCLASS32 else 64

    @property
    def endian(self) -> str:
        return "little" if self.ei_data == ELFDATA2LSB else "big"

    @property
    def endian_char(self) -> str:
        return "<" if self.ei_data == ELFDATA2LSB else ">"


@dataclass
class ELFHeader:
    """Parsed ELF file header."""
    ident: ELFIdent
    e_type: int
    e_machine: int
    e_version: int
    e_entry: int
    e_phoff: int
    e_shoff: int
    e_flags: int
    e_ehsize: int
    e_phentsize: int
    e_phnum: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int

    @property
    def type_name(self) -> str:
        return ELF_TYPE_NAMES.get(self.e_type, f"0x{self.e_type:04X}")

    @property
    def machine_name(self) -> str:
        return ELF_MACHINE_NAMES.get(self.e_machine, f"0x{self.e_machine:04X}")

    @property
    def is_pie(self) -> bool:
        return self.e_type == ET_DYN

    @property
    def is_executable(self) -> bool:
        return self.e_type in (ET_EXEC, ET_DYN)


@dataclass
class ELFSection:
    """A single parsed section header entry."""
    index: int
    name: str
    sh_type: int
    sh_flags: int
    sh_addr: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_info: int
    sh_addralign: int
    sh_entsize: int
    data: bytes = field(default_factory=bytes, repr=False)
    entropy: float = 0.0

    @property
    def type_name(self) -> str:
        return SHT_NAMES.get(self.sh_type, f"0x{self.sh_type:08X}")

    @property
    def is_executable(self) -> bool:
        return bool(self.sh_flags & SHF_EXECINSTR)

    @property
    def is_writable(self) -> bool:
        return bool(self.sh_flags & SHF_WRITE)

    @property
    def is_allocated(self) -> bool:
        return bool(self.sh_flags & SHF_ALLOC)

    @property
    def flags_str(self) -> str:
        parts = []
        if self.sh_flags & SHF_ALLOC:     parts.append("A")
        if self.sh_flags & SHF_EXECINSTR: parts.append("X")
        if self.sh_flags & SHF_WRITE:     parts.append("W")
        if self.sh_flags & SHF_STRINGS:   parts.append("S")
        if self.sh_flags & SHF_MERGE:     parts.append("M")
        return "".join(parts)


@dataclass
class ELFSegment:
    """A single parsed program header (segment) entry."""
    index: int
    p_type: int
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_align: int

    @property
    def type_name(self) -> str:
        return PT_NAMES.get(self.p_type, f"0x{self.p_type:08X}")

    @property
    def is_executable(self) -> bool:
        return bool(self.p_flags & 0x1)

    @property
    def is_writable(self) -> bool:
        return bool(self.p_flags & 0x2)

    @property
    def is_readable(self) -> bool:
        return bool(self.p_flags & 0x4)

    @property
    def flags_str(self) -> str:
        r = "R" if self.is_readable else " "
        w = "W" if self.is_writable else " "
        x = "E" if self.is_executable else " "
        return f"{r}{w}{x}"


@dataclass
class ELFSymbol:
    """A single symbol table entry."""
    name: str
    value: int
    size: int
    bind: int
    sym_type: int
    visibility: int
    shndx: int

    @property
    def bind_name(self) -> str:
        return {STB_LOCAL: "LOCAL", STB_GLOBAL: "GLOBAL", STB_WEAK: "WEAK"}.get(
            self.bind, f"{self.bind}"
        )

    @property
    def type_name(self) -> str:
        return {
            STT_NOTYPE: "NOTYPE", STT_OBJECT: "OBJECT", STT_FUNC: "FUNC",
            STT_SECTION: "SECTION", STT_FILE: "FILE", STT_COMMON: "COMMON",
            STT_TLS: "TLS",
        }.get(self.sym_type, f"{self.sym_type}")


@dataclass
class DynamicEntry:
    """A single .dynamic section entry."""
    d_tag: int
    d_val: int
    name: str = ""  # resolved string (for DT_NEEDED, DT_RPATH etc.)


@dataclass
class ELFNote:
    """A single NOTE section entry."""
    name: str
    note_type: int
    desc: bytes


@dataclass
class ELFSuspiciousIndicator:
    """A suspicious pattern found during ELF analysis."""
    category: str
    description: str
    detail: str
    severity: int  # 1 (low) – 5 (critical)


@dataclass
class ELFAnalysisResult:
    """Full static analysis result for an ELF binary."""
    file_size: int
    sha256: str
    md5: str
    header: ELFHeader
    sections: List[ELFSection] = field(default_factory=list)
    segments: List[ELFSegment] = field(default_factory=list)
    dynamic_symbols: List[ELFSymbol] = field(default_factory=list)
    static_symbols: List[ELFSymbol] = field(default_factory=list)
    needed_libraries: List[str] = field(default_factory=list)
    rpath: Optional[str] = None
    runpath: Optional[str] = None
    soname: Optional[str] = None
    interpreter: Optional[str] = None
    notes: List[ELFNote] = field(default_factory=list)
    build_id: Optional[str] = None
    strings: List[str] = field(default_factory=list)
    suspicious_indicators: List[ELFSuspiciousIndicator] = field(default_factory=list)

    # Security feature flags
    has_nx_stack: bool = False
    has_relro: bool = False
    has_full_relro: bool = False
    has_canary: bool = False
    has_pie: bool = False
    has_fortify: bool = False
    is_stripped: bool = False
    is_packed: bool = False

    # Aggregate metrics
    overall_risk_score: int = 0       # 0-100
    max_section_entropy: float = 0.0
    avg_section_entropy: float = 0.0
    suspicious_symbol_hits: List[Tuple[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_size": self.file_size,
            "sha256": self.sha256,
            "md5": self.md5,
            "header": {
                "class": self.header.ident.bits,
                "endian": self.header.ident.endian,
                "type": self.header.type_name,
                "machine": self.header.machine_name,
                "entry_point": hex(self.header.e_entry),
                "is_pie": self.header.is_pie,
            },
            "sections": [
                {
                    "name": s.name, "type": s.type_name,
                    "flags": s.flags_str, "size": s.sh_size,
                    "entropy": round(s.entropy, 4),
                    "executable": s.is_executable,
                }
                for s in self.sections
            ],
            "needed_libraries": self.needed_libraries,
            "rpath": self.rpath,
            "runpath": self.runpath,
            "soname": self.soname,
            "interpreter": self.interpreter,
            "build_id": self.build_id,
            "security": {
                "nx_stack": self.has_nx_stack,
                "relro": self.has_relro,
                "full_relro": self.has_full_relro,
                "stack_canary": self.has_canary,
                "pie": self.has_pie,
                "fortify": self.has_fortify,
                "stripped": self.is_stripped,
                "packed": self.is_packed,
            },
            "risk_score": self.overall_risk_score,
            "max_section_entropy": round(self.max_section_entropy, 4),
            "avg_section_entropy": round(self.avg_section_entropy, 4),
            "suspicious_symbols": [
                {"name": name, "description": desc}
                for name, desc in self.suspicious_symbol_hits
            ],
            "indicators": [
                {
                    "category": ind.category,
                    "description": ind.description,
                    "detail": ind.detail,
                    "severity": ind.severity,
                }
                for ind in self.suspicious_indicators
            ],
        }


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class ELFParseError(Exception):
    pass


class ELFParser:
    """
    Parses and statically analyzes ELF binaries.

    Usage::

        with open("sample", "rb") as f:
            data = f.read()
        result = ELFParser(data).analyze()
    """

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._buf = io.BytesIO(data)
        self._header: Optional[ELFHeader] = None
        self._endian: str = "<"    # struct format prefix
        self._bits: int = 64

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self) -> ELFAnalysisResult:
        if len(self._data) < 4 or self._data[:4] != ELF_MAGIC:
            raise ELFParseError("Not a valid ELF file (bad magic)")

        header = self._parse_elf_header()
        self._header = header
        self._endian = header.ident.endian_char
        self._bits = header.ident.bits

        sections = self._parse_sections(header)
        segments = self._parse_segments(header)
        interpreter = self._extract_interpreter(segments)

        dynamic_entries, needed_libs, rpath, runpath, soname = self._parse_dynamic(sections)
        dyn_symbols = self._parse_symbol_table(sections, SHT_DYNSYM)
        static_symbols = self._parse_symbol_table(sections, SHT_SYMTAB)
        notes, build_id = self._parse_notes(sections, segments)
        strings = self._extract_strings()

        result = ELFAnalysisResult(
            file_size=len(self._data),
            sha256=hashlib.sha256(self._data).hexdigest(),
            md5=hashlib.md5(self._data).hexdigest(),
            header=header,
            sections=sections,
            segments=segments,
            dynamic_symbols=dyn_symbols,
            static_symbols=static_symbols,
            needed_libraries=needed_libs,
            rpath=rpath,
            runpath=runpath,
            soname=soname,
            interpreter=interpreter,
            notes=notes,
            build_id=build_id,
            strings=strings,
        )

        self._detect_security_features(result)
        self._detect_suspicious_indicators(result)
        self._compute_entropy_stats(result)
        result.overall_risk_score = self._compute_risk_score(result)

        return result

    # ------------------------------------------------------------------
    # ELF Header parsing
    # ------------------------------------------------------------------

    def _parse_elf_header(self) -> ELFHeader:
        self._buf.seek(0)
        e_ident_raw = self._buf.read(16)
        if len(e_ident_raw) < 16:
            raise ELFParseError("Truncated e_ident")

        ident = ELFIdent(
            magic=e_ident_raw[:4],
            ei_class=e_ident_raw[4],
            ei_data=e_ident_raw[5],
            ei_version=e_ident_raw[6],
            ei_osabi=e_ident_raw[7],
            ei_abiversion=e_ident_raw[8],
        )

        if ident.ei_class not in (ELFCLASS32, ELFCLASS64):
            raise ELFParseError(f"Unknown EI_CLASS: {ident.ei_class}")
        if ident.ei_data not in (ELFDATA2LSB, ELFDATA2MSB):
            raise ELFParseError(f"Unknown EI_DATA: {ident.ei_data}")

        e = ident.endian_char

        if ident.ei_class == ELFCLASS64:
            fmt = f"{e}HHIQQQIHHHHHH"
            size = struct.calcsize(fmt)
            raw = self._buf.read(size)
            if len(raw) < size:
                raise ELFParseError("Truncated ELF64 header")
            (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
             e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
             e_shstrndx) = struct.unpack(fmt, raw)
        else:
            fmt = f"{e}HHIIIIIHHHHHH"
            size = struct.calcsize(fmt)
            raw = self._buf.read(size)
            if len(raw) < size:
                raise ELFParseError("Truncated ELF32 header")
            (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
             e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
             e_shstrndx) = struct.unpack(fmt, raw)

        return ELFHeader(
            ident=ident, e_type=e_type, e_machine=e_machine, e_version=e_version,
            e_entry=e_entry, e_phoff=e_phoff, e_shoff=e_shoff, e_flags=e_flags,
            e_ehsize=e_ehsize, e_phentsize=e_phentsize, e_phnum=e_phnum,
            e_shentsize=e_shentsize, e_shnum=e_shnum, e_shstrndx=e_shstrndx,
        )

    # ------------------------------------------------------------------
    # Section table
    # ------------------------------------------------------------------

    def _parse_sections(self, hdr: ELFHeader) -> List[ELFSection]:
        if hdr.e_shoff == 0 or hdr.e_shnum == 0:
            return []

        e = hdr.ident.endian_char
        sections_raw: List[ELFSection] = []
        sh_fmt32 = f"{e}IIIIIIIIII"
        sh_fmt64 = f"{e}IIQQQQIIQQ"

        for i in range(hdr.e_shnum):
            offset = hdr.e_shoff + i * hdr.e_shentsize
            self._buf.seek(offset)
            if hdr.ident.ei_class == ELFCLASS64:
                raw = self._buf.read(struct.calcsize(sh_fmt64))
                if len(raw) < struct.calcsize(sh_fmt64):
                    break
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                 sh_link, sh_info, sh_addralign, sh_entsize) = struct.unpack(sh_fmt64, raw)
            else:
                raw = self._buf.read(struct.calcsize(sh_fmt32))
                if len(raw) < struct.calcsize(sh_fmt32):
                    break
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                 sh_link, sh_info, sh_addralign, sh_entsize) = struct.unpack(sh_fmt32, raw)

            # Read section data (skip SHT_NOBITS)
            data = b""
            if sh_type != SHT_NOBITS and sh_size > 0 and sh_offset < len(self._data):
                data = self._data[sh_offset: sh_offset + sh_size]

            sections_raw.append(ELFSection(
                index=i, name="", sh_type=sh_type, sh_flags=sh_flags,
                sh_addr=sh_addr, sh_offset=sh_offset, sh_size=sh_size,
                sh_link=sh_link, sh_info=sh_info, sh_addralign=sh_addralign,
                sh_entsize=sh_entsize, data=data,
                entropy=_entropy(data) if data else 0.0,
            ))

        # Resolve section names from .shstrtab
        if hdr.e_shstrndx < len(sections_raw):
            strtab = sections_raw[hdr.e_shstrndx].data
            for sec in sections_raw:
                sec.name = _read_cstring(strtab, sec.name if isinstance(sec.name, int) else 0)
        # name field was stored as sh_name offset (int) until resolved
        # patch: re-do with correct offset stored above
        self._buf.seek(hdr.e_shoff)
        for i, sec in enumerate(sections_raw):
            offset = hdr.e_shoff + i * hdr.e_shentsize
            self._buf.seek(offset)
            if hdr.ident.ei_class == ELFCLASS64:
                sh_name_offset = struct.unpack(f"{e}I", self._buf.read(4))[0]
            else:
                sh_name_offset = struct.unpack(f"{e}I", self._buf.read(4))[0]
            if hdr.e_shstrndx < len(sections_raw):
                strtab = sections_raw[hdr.e_shstrndx].data
                sec.name = _read_cstring(strtab, sh_name_offset)

        return sections_raw

    # ------------------------------------------------------------------
    # Program header (segment) table
    # ------------------------------------------------------------------

    def _parse_segments(self, hdr: ELFHeader) -> List[ELFSegment]:
        if hdr.e_phoff == 0 or hdr.e_phnum == 0:
            return []

        e = hdr.ident.endian_char
        segments = []

        # ELF32: p_flags is after p_align; ELF64: p_flags is after p_type
        ph_fmt32 = f"{e}IIIIIIII"
        ph_fmt64 = f"{e}IIQQQQQQ"

        for i in range(hdr.e_phnum):
            offset = hdr.e_phoff + i * hdr.e_phentsize
            self._buf.seek(offset)
            if hdr.ident.ei_class == ELFCLASS64:
                raw = self._buf.read(struct.calcsize(ph_fmt64))
                if len(raw) < struct.calcsize(ph_fmt64):
                    break
                (p_type, p_flags, p_offset, p_vaddr, p_paddr,
                 p_filesz, p_memsz, p_align) = struct.unpack(ph_fmt64, raw)
            else:
                raw = self._buf.read(struct.calcsize(ph_fmt32))
                if len(raw) < struct.calcsize(ph_fmt32):
                    break
                (p_type, p_offset, p_vaddr, p_paddr, p_filesz,
                 p_memsz, p_flags, p_align) = struct.unpack(ph_fmt32, raw)

            segments.append(ELFSegment(
                index=i, p_type=p_type, p_flags=p_flags, p_offset=p_offset,
                p_vaddr=p_vaddr, p_paddr=p_paddr, p_filesz=p_filesz,
                p_memsz=p_memsz, p_align=p_align,
            ))

        return segments

    # ------------------------------------------------------------------
    # .interp segment
    # ------------------------------------------------------------------

    def _extract_interpreter(self, segments: List[ELFSegment]) -> Optional[str]:
        for seg in segments:
            if seg.p_type == PT_INTERP and seg.p_filesz > 0:
                raw = self._data[seg.p_offset: seg.p_offset + seg.p_filesz]
                return raw.rstrip(b"\x00").decode("utf-8", errors="replace")
        return None

    # ------------------------------------------------------------------
    # .dynamic section parsing
    # ------------------------------------------------------------------

    def _parse_dynamic(
        self, sections: List[ELFSection]
    ) -> Tuple[List[DynamicEntry], List[str], Optional[str], Optional[str], Optional[str]]:
        dyn_section = next((s for s in sections if s.sh_type == SHT_DYNAMIC), None)
        dynstr_section = next(
            (s for s in sections if s.name == ".dynstr"), None
        )
        if dyn_section is None or not dyn_section.data:
            return [], [], None, None, None

        e = self._endian
        entry_fmt = f"{e}{'qq' if self._bits == 64 else 'ii'}"
        entry_size = struct.calcsize(entry_fmt)

        entries: List[DynamicEntry] = []
        needed: List[str] = []
        rpath = runpath = soname = None

        data = dyn_section.data
        offset = 0
        while offset + entry_size <= len(data):
            d_tag, d_val = struct.unpack(entry_fmt, data[offset: offset + entry_size])
            offset += entry_size
            if d_tag == DT_NULL:
                break

            name = ""
            if dynstr_section and dynstr_section.data:
                if d_tag in (DT_NEEDED, DT_RPATH, DT_RUNPATH, DT_SONAME):
                    name = _read_cstring(dynstr_section.data, d_val)

            entry = DynamicEntry(d_tag=d_tag, d_val=d_val, name=name)
            entries.append(entry)

            if d_tag == DT_NEEDED:
                needed.append(name)
            elif d_tag == DT_RPATH:
                rpath = name
            elif d_tag == DT_RUNPATH:
                runpath = name
            elif d_tag == DT_SONAME:
                soname = name

        return entries, needed, rpath, runpath, soname

    # ------------------------------------------------------------------
    # Symbol table parsing
    # ------------------------------------------------------------------

    def _parse_symbol_table(
        self, sections: List[ELFSection], sht_type: int
    ) -> List[ELFSymbol]:
        sym_section = next((s for s in sections if s.sh_type == sht_type), None)
        if sym_section is None or not sym_section.data:
            return []

        # Find associated string table
        strtab_section: Optional[ELFSection] = None
        if 0 < sym_section.sh_link < len(sections):
            strtab_section = sections[sym_section.sh_link]

        e = self._endian
        if self._bits == 64:
            sym_fmt = f"{e}IBBHQQ"  # name, info, other, shndx, value, size
        else:
            sym_fmt = f"{e}IIIBBH"  # name, value, size, info, other, shndx

        sym_size = struct.calcsize(sym_fmt)
        symbols = []
        data = sym_section.data

        for offset in range(0, len(data) - sym_size + 1, sym_size):
            raw = data[offset: offset + sym_size]
            if len(raw) < sym_size:
                break

            if self._bits == 64:
                st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack(sym_fmt, raw)
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack(sym_fmt, raw)

            bind = (st_info >> 4) & 0xF
            sym_type = st_info & 0xF
            visibility = st_other & 0x3

            name = ""
            if strtab_section and strtab_section.data:
                name = _read_cstring(strtab_section.data, st_name)

            symbols.append(ELFSymbol(
                name=name, value=st_value, size=st_size,
                bind=bind, sym_type=sym_type, visibility=visibility,
                shndx=st_shndx,
            ))

        return symbols

    # ------------------------------------------------------------------
    # Notes parsing
    # ------------------------------------------------------------------

    def _parse_notes(
        self, sections: List[ELFSection], segments: List[ELFSegment]
    ) -> Tuple[List[ELFNote], Optional[str]]:
        notes: List[ELFNote] = []
        build_id: Optional[str] = None

        note_sections = [s for s in sections if s.sh_type == SHT_NOTE and s.data]
        if not note_sections:
            # Fall back to PT_NOTE segments
            for seg in segments:
                if seg.p_type == PT_NOTE and seg.p_filesz > 0:
                    raw = self._data[seg.p_offset: seg.p_offset + seg.p_filesz]
                    parsed = self._parse_note_data(raw)
                    notes.extend(parsed)
        else:
            for sec in note_sections:
                parsed = self._parse_note_data(sec.data)
                notes.extend(parsed)

        for note in notes:
            if note.name == "GNU" and note.note_type == 3:  # NT_GNU_BUILD_ID
                build_id = note.desc.hex()

        return notes, build_id

    def _parse_note_data(self, data: bytes) -> List[ELFNote]:
        notes = []
        e = self._endian
        offset = 0
        while offset + 12 <= len(data):
            namesz, descsz, note_type = struct.unpack(f"{e}III", data[offset: offset + 12])
            offset += 12
            name_raw = data[offset: offset + namesz]
            name = name_raw.rstrip(b"\x00").decode("utf-8", errors="replace")
            offset += _align4(namesz)
            desc = data[offset: offset + descsz]
            offset += _align4(descsz)
            notes.append(ELFNote(name=name, note_type=note_type, desc=desc))
        return notes

    # ------------------------------------------------------------------
    # String extraction
    # ------------------------------------------------------------------

    def _extract_strings(self, min_len: int = 6) -> List[str]:
        pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
        return [m.group().decode("ascii", errors="replace") for m in pattern.finditer(self._data)]

    # ------------------------------------------------------------------
    # Security feature detection
    # ------------------------------------------------------------------

    def _detect_security_features(self, result: ELFAnalysisResult) -> None:
        hdr = result.header

        # PIE: ET_DYN type
        result.has_pie = hdr.is_pie

        # NX stack: GNU_STACK segment without execute flag
        for seg in result.segments:
            if seg.p_type == PT_GNU_STACK:
                result.has_nx_stack = not seg.is_executable
                break
        else:
            result.has_nx_stack = False  # no GNU_STACK = potentially executable stack

        # RELRO
        has_relro_seg = any(seg.p_type == PT_GNU_RELRO for seg in result.segments)
        if has_relro_seg:
            result.has_relro = True
            # Full RELRO requires BIND_NOW flag in .dynamic or DT_FLAGS_1 with DF_1_NOW
            sym_names = {s.name for s in result.dynamic_symbols}
            # Heuristic: __relro_end present or BIND_NOW in DT_FLAGS
            result.has_full_relro = "__relro_end" in sym_names or "__end__" in sym_names

        # Stack canary: presence of __stack_chk_fail in dynamic symbols
        dyn_names = {s.name for s in result.dynamic_symbols}
        result.has_canary = "__stack_chk_fail" in dyn_names

        # FORTIFY_SOURCE: presence of __*_chk functions
        result.has_fortify = any(
            s.name.endswith("_chk") and s.name.startswith("__")
            for s in result.dynamic_symbols
        )

        # Stripped: no .symtab section
        has_symtab = any(s.sh_type == SHT_SYMTAB for s in result.sections)
        result.is_stripped = not has_symtab

        # Packer detection: check section names and high overall entropy
        for sec in result.sections:
            for packer_name, packer_desc in PACKER_SECTIONS:
                if packer_name.lower() in sec.name.lower():
                    result.is_packed = True
                    result.suspicious_indicators.append(ELFSuspiciousIndicator(
                        category="packer",
                        description=f"Known packer section detected: {packer_desc}",
                        detail=f"Section '{sec.name}' matches packer pattern '{packer_name}'",
                        severity=3,
                    ))

        # If overall entropy > 7.2 and no .text section, likely packed
        text_sections = [s for s in result.sections if s.name in (".text", ".code")]
        if not text_sections:
            exec_sections = [s for s in result.sections if s.is_executable and s.sh_size > 0]
            if exec_sections:
                avg_exec_entropy = sum(s.entropy for s in exec_sections) / len(exec_sections)
                if avg_exec_entropy > HIGH_ENTROPY_THRESHOLD:
                    result.is_packed = True
                    result.suspicious_indicators.append(ELFSuspiciousIndicator(
                        category="packer",
                        description="High entropy executable sections with no .text",
                        detail=f"Average entropy of executable sections: {avg_exec_entropy:.2f}",
                        severity=3,
                    ))

    # ------------------------------------------------------------------
    # Suspicious indicator detection
    # ------------------------------------------------------------------

    def _detect_suspicious_indicators(self, result: ELFAnalysisResult) -> None:
        all_sym_names = {s.name for s in result.dynamic_symbols} | {s.name for s in result.static_symbols}
        strings_set = set(result.strings)

        # Check for suspicious symbols
        for sym_name, description in SUSPICIOUS_SYMBOLS:
            if sym_name in all_sym_names or sym_name in strings_set:
                result.suspicious_symbol_hits.append((sym_name, description))

        # Network capabilities
        network_syms = {"socket", "connect", "bind", "recv", "send", "getaddrinfo", "gethostbyname"}
        found_net = network_syms & all_sym_names
        if found_net:
            result.suspicious_indicators.append(ELFSuspiciousIndicator(
                category="network",
                description="Network communication capability detected",
                detail=f"Symbols: {', '.join(sorted(found_net))}",
                severity=2,
            ))

        # Command execution
        exec_syms = {"execve", "execvp", "system", "popen"}
        found_exec = exec_syms & all_sym_names
        if found_exec:
            result.suspicious_indicators.append(ELFSuspiciousIndicator(
                category="execution",
                description="Shell/command execution capability detected",
                detail=f"Symbols: {', '.join(sorted(found_exec))}",
                severity=3,
            ))

        # Privilege escalation
        priv_syms = {"setuid", "setgid", "setreuid", "setregid", "capset"}
        found_priv = priv_syms & all_sym_names
        if found_priv:
            result.suspicious_indicators.append(ELFSuspiciousIndicator(
                category="privilege_escalation",
                description="Privilege manipulation capability detected",
                detail=f"Symbols: {', '.join(sorted(found_priv))}",
                severity=4,
            ))

        # Anti-debug
        if "ptrace" in all_sym_names:
            result.suspicious_indicators.append(ELFSuspiciousIndicator(
                category="anti_analysis",
                description="ptrace anti-debugging check",
                detail="ptrace symbol imported - may check if being debugged",
                severity=3,
            ))

        if "getppid" in all_sym_names:
            result.suspicious_indicators.append(ELFSuspiciousIndicator(
                category="anti_analysis",
                description="Parent process detection (sandbox evasion)",
                detail="getppid symbol - may detect analysis environments",
                severity=2,
            ))

        # LD_PRELOAD injection strings in binary
        ld_preload_strings = [s for s in result.strings if "LD_PRELOAD" in s or "LD_LIBRARY_PATH" in s]
        if ld_preload_strings:
            result.suspicious_indicators.append(ELFSuspiciousIndicator(
                category="defense_evasion",
                description="LD_PRELOAD/LD_LIBRARY_PATH manipulation",
                detail=f"Strings found: {ld_preload_strings[:3]}",
                severity=4,
            ))

        # /proc filesystem access (sandbox/container evasion)
        proc_strings = [s for s in result.strings if s.startswith("/proc/")]
        if len(proc_strings) > 2:
            result.suspicious_indicators.append(ELFSuspiciousIndicator(
                category="discovery",
                description="Extensive /proc filesystem access",
                detail=f"Strings: {proc_strings[:5]}",
                severity=2,
            ))

        # Writable+executable segment (W^X violation)
        for seg in result.segments:
            if seg.p_type == PT_LOAD and seg.is_writable and seg.is_executable:
                result.suspicious_indicators.append(ELFSuspiciousIndicator(
                    category="defense_evasion",
                    description="Writable and executable LOAD segment (W+X violation)",
                    detail=f"Segment {seg.index}: offset=0x{seg.p_offset:X}, "
                           f"flags={seg.flags_str}",
                    severity=4,
                ))

        # Missing security features as low-severity indicators
        if not result.has_nx_stack:
            result.suspicious_indicators.append(ELFSuspiciousIndicator(
                category="hardening",
                description="Executable stack (no NX/DEP protection)",
                detail="No GNU_STACK segment or executable stack flag set",
                severity=2,
            ))
        if not result.has_pie:
            result.suspicious_indicators.append(ELFSuspiciousIndicator(
                category="hardening",
                description="Not compiled as PIE (no ASLR)",
                detail="ET_EXEC type - fixed load address",
                severity=1,
            ))
        if not result.has_canary:
            result.suspicious_indicators.append(ELFSuspiciousIndicator(
                category="hardening",
                description="No stack canary protection",
                detail="__stack_chk_fail not found in dynamic symbols",
                severity=1,
            ))

        # Rootkit: hiding behavior (libc hooking, symbol interposing)
        hook_patterns = {"fopen", "open", "readdir", "read", "stat", "lstat", "opendir"}
        found_hooks = hook_patterns & all_sym_names
        if result.soname and found_hooks:
            result.suspicious_indicators.append(ELFSuspiciousIndicator(
                category="rootkit",
                description="Shared library with file/dir access symbol hooks (potential rootkit)",
                detail=f"soname={result.soname}, symbols: {', '.join(sorted(found_hooks))}",
                severity=4,
            ))

        # Deleted RPATH / suspicious library paths
        if result.rpath and any(p in result.rpath for p in ("/tmp", "/var/tmp", "/dev/shm")):
            result.suspicious_indicators.append(ELFSuspiciousIndicator(
                category="persistence",
                description="RPATH points to suspicious directory",
                detail=f"RPATH: {result.rpath}",
                severity=3,
            ))

    # ------------------------------------------------------------------
    # Entropy stats
    # ------------------------------------------------------------------

    def _compute_entropy_stats(self, result: ELFAnalysisResult) -> None:
        entropies = [s.entropy for s in result.sections if s.sh_size > 0]
        if entropies:
            result.max_section_entropy = max(entropies)
            result.avg_section_entropy = sum(entropies) / len(entropies)

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def _compute_risk_score(self, result: ELFAnalysisResult) -> int:
        score = 0

        # Indicator-based
        for ind in result.suspicious_indicators:
            score += {1: 3, 2: 6, 3: 12, 4: 18, 5: 25}.get(ind.severity, 5)

        # Suspicious symbols
        score += min(len(result.suspicious_symbol_hits) * 3, 30)

        # Entropy
        if result.max_section_entropy > 7.8:
            score += 15
        elif result.max_section_entropy > 7.0:
            score += 8

        # Packing
        if result.is_packed:
            score += 20

        # Missing hardening (low weight since legitimate code also lacks it)
        if not result.has_nx_stack:
            score += 3
        if not result.has_canary:
            score += 2

        return min(score, 100)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def _read_cstring(data: bytes, offset: int) -> str:
    if offset >= len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end == -1:
        raw = data[offset:]
    else:
        raw = data[offset:end]
    return raw.decode("utf-8", errors="replace")


def _align4(n: int) -> int:
    return (n + 3) & ~3


def analyze_elf(data: bytes) -> ELFAnalysisResult:
    """Convenience wrapper: parse and analyze an ELF binary from raw bytes."""
    return ELFParser(data).analyze()
