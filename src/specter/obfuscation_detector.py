"""
Obfuscation detection for PE binaries and shellcode payloads.
"""

from __future__ import annotations

import base64
import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class ObfuscationType(str, Enum):
    BASE64_SHELLCODE = "base64_shellcode"
    XOR_ENCODED_STRINGS = "xor_encoded_strings"
    ROT13_STRINGS = "rot13_strings"
    STACK_STRINGS = "stack_strings"
    DYNAMIC_API_RESOLUTION = "dynamic_api_resolution"
    ANTI_DISASSEMBLY = "anti_disassembly"
    IMPORT_TABLE_HIDING = "import_table_hiding"
    STRING_ENCRYPTION = "string_encryption"
    SELF_MODIFYING_CODE = "self_modifying_code"
    CONTROL_FLOW_FLATTENING = "control_flow_flattening"
    DEAD_CODE = "dead_code"
    JUNK_CODE_INSERTION = "junk_code_insertion"


@dataclass
class ObfuscationFinding:
    """A single detected obfuscation artifact."""
    obfuscation_type: ObfuscationType
    offset: int
    length: int
    confidence: float  # 0.0–1.0
    decoded_value: Optional[str] = None
    context_bytes: bytes = b""
    description: str = ""
    xor_key: Optional[int] = None


@dataclass
class XorKeyCandidate:
    key: int
    score: float
    decoded_sample: bytes
    printable_ratio: float


@dataclass
class ObfuscationReport:
    """Aggregated obfuscation analysis results."""
    findings: List[ObfuscationFinding] = field(default_factory=list)
    overall_confidence: float = 0.0
    obfuscation_score: float = 0.0
    detected_types: List[ObfuscationType] = field(default_factory=list)
    xor_keys_found: List[int] = field(default_factory=list)
    base64_payloads: List[bytes] = field(default_factory=list)
    dynamic_api_calls: List[str] = field(default_factory=list)
    stack_string_count: int = 0

    @property
    def is_obfuscated(self) -> bool:
        return self.obfuscation_score >= 30.0

    @property
    def is_heavily_obfuscated(self) -> bool:
        return self.obfuscation_score >= 65.0

    def summary(self) -> str:
        if not self.findings:
            return "No obfuscation detected"
        types = ", ".join(t.value for t in self.detected_types)
        return (
            f"Score: {self.obfuscation_score:.1f}/100 | "
            f"Findings: {len(self.findings)} | "
            f"Types: {types}"
        )


# ------------------------------------------------------------------ patterns

# x86/x64 shellcode prologue sequences
_SHELLCODE_PROLOGUES: List[bytes] = [
    b"\xfc\xe8",               # CLD; CALL  (classic Metasploit x86)
    b"\xfc\x48\x83",           # CLD; REX.W SUB  (Metasploit x64)
    b"\x55\x8b\xec",           # PUSH EBP; MOV EBP, ESP
    b"\x60\x89\xe5",           # PUSHAD; MOV EBP, ESP
    b"\xeb\x27\x5b",           # JMP SHORT; POP EBX  (egg hunter)
    b"\x31\xc0\x50",           # XOR EAX; PUSH EAX
    b"\x64\xa1\x30",           # MOV EAX, FS:[0x30]  (PEB x86)
    b"\x65\x48\x8b\x04\x25\x60",  # MOV RAX, GS:[0x60]  (PEB x64)
    b"\x6a\x40\x68",           # PUSH 0x40; PUSH  (VirtualAlloc stub)
    b"\xd9\xeb\x9b\xd9",       # FPU-based GetPC
]

# Dynamic API resolution function names
_DYNAMIC_API_BYTES: List[bytes] = [
    b"GetProcAddress",
    b"LoadLibraryA",
    b"LoadLibraryW",
    b"LdrGetProcedureAddress",
    b"NtQuerySystemInformation",
]

# Anti-disassembly gadget patterns (bytes, description)
_ANTI_DISASM_GADGETS: List[Tuple[bytes, str]] = [
    (b"\xeb\xff", "JMP SHORT -1 (opaque predicate)"),
    (b"\xe8\x00\x00\x00\x00\x58", "CALL+0/POP EAX (position-independent stub)"),
    (b"\xff\xe4", "JMP ESP (stack pivot)"),
    (b"\x0f\x0b", "UD2 (intentional invalid instruction)"),
    (b"\x0f\xff", "UD0 (undefined encoding)"),
    (b"\xf2\xf2", "Stacked REP prefix (disassembler confusion)"),
    (b"\x66\x66\x66", "Stacked operand-size prefix"),
]

# Stack-string assembly: consecutive MOV BYTE PTR [EBP+x], imm patterns
_STACK_STR_32 = re.compile(rb"(?:\xc6\x45[\x00-\xff][\x20-\x7e]){4,}", re.DOTALL)
_STACK_STR_64 = re.compile(rb"(?:\xc6\x44\x24[\x00-\xff][\x20-\x7e]){4,}", re.DOTALL)

# Base64 payload (minimum 40 encoded chars = ~30 raw bytes)
_B64_PATTERN = re.compile(
    rb"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
)

# API names that indicate hash-based resolution after a hash lookup
_HASH_API_KEYWORDS = {kw.lower() for kw in [
    "VirtualAlloc", "VirtualProtect", "CreateThread", "WriteProcessMemory",
    "LoadLibraryA", "GetProcAddress",
]}


# ------------------------------------------------------------------ helpers


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length)
        for c in freq.values()
        if c > 0
    )


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if 0x20 <= b < 0x7F) / len(data)


def _looks_like_shellcode(data: bytes) -> bool:
    """Heuristic: high entropy OR known prologue, low printable ratio."""
    if len(data) < 32:
        return False
    ent = _shannon_entropy(data)
    pr = _printable_ratio(data)
    for prologue in _SHELLCODE_PROLOGUES:
        if data.startswith(prologue) or prologue in data[:64]:
            return True
    return ent >= 6.0 and pr < 0.30


def _rot13(s: str) -> str:
    result = []
    for ch in s:
        if "a" <= ch <= "z":
            result.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            result.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
        else:
            result.append(ch)
    return "".join(result)


_SENSITIVE_KEYWORDS = {
    "createfile", "regopenkey", "writefile", "openprocess",
    "virtualalloc", "loadlibrary", "getprocaddress", "createthread",
    "httpsendrequest", "internetconnect", "wscript", "powershell",
    "cmd.exe", "explorer", "svchost", "regsvr32", "mshta",
}


# ---------------------------------------------------------------- detector


class ObfuscationDetector:
    """
    Detects obfuscation techniques in PE binary data.

    Analyzes: base64-encoded shellcode, XOR-encoded strings with key
    recovery, stack-assembled strings, dynamic API resolution, anti-
    disassembly gadgets, and encrypted string regions.
    """

    def analyze(self, data: bytes) -> ObfuscationReport:
        """Run all detection passes and return an ObfuscationReport."""
        report = ObfuscationReport()
        findings: List[ObfuscationFinding] = []

        findings.extend(self._detect_base64_shellcode(data))
        findings.extend(self._detect_xor_strings(data))
        findings.extend(self._detect_stack_strings(data))
        findings.extend(self._detect_dynamic_api(data))
        findings.extend(self._detect_anti_disassembly(data))
        findings.extend(self._detect_string_encryption(data))
        findings.extend(self._detect_rot13_strings(data))

        report.findings = findings
        report.detected_types = list({f.obfuscation_type for f in findings})
        report.xor_keys_found = list({
            f.xor_key for f in findings if f.xor_key is not None
        })
        report.base64_payloads = [
            f.context_bytes
            for f in findings
            if f.obfuscation_type == ObfuscationType.BASE64_SHELLCODE
            and f.context_bytes
        ]
        report.dynamic_api_calls = [
            f.description
            for f in findings
            if f.obfuscation_type == ObfuscationType.DYNAMIC_API_RESOLUTION
        ]
        report.stack_string_count = sum(
            1 for f in findings if f.obfuscation_type == ObfuscationType.STACK_STRINGS
        )
        report.obfuscation_score = self._compute_score(report)
        report.overall_confidence = min(1.0, len(findings) / 10.0)

        return report

    # --------------------------------------------------------- base64

    def _detect_base64_shellcode(self, data: bytes) -> List[ObfuscationFinding]:
        findings: List[ObfuscationFinding] = []
        for m in _B64_PATTERN.finditer(data):
            raw = m.group(0)
            try:
                decoded = base64.b64decode(raw + b"==")
            except Exception:
                continue
            if not _looks_like_shellcode(decoded):
                continue
            findings.append(ObfuscationFinding(
                obfuscation_type=ObfuscationType.BASE64_SHELLCODE,
                offset=m.start(),
                length=len(raw),
                confidence=0.85,
                decoded_value=f"<{len(decoded)}-byte payload>",
                context_bytes=decoded[:64],
                description=(
                    f"Base64-encoded shellcode at 0x{m.start():x} "
                    f"({len(decoded)} bytes decoded)"
                ),
            ))
        return findings

    # ---------------------------------------------------------- XOR

    def _detect_xor_strings(self, data: bytes) -> List[ObfuscationFinding]:
        """Slide a 256-byte window; try all non-null single-byte XOR keys."""
        findings: List[ObfuscationFinding] = []
        window = 256
        step = 128
        seen_keys: set = set()

        for offset in range(0, max(1, len(data) - window), step):
            chunk = data[offset:offset + window]
            candidate = self._best_xor_key(chunk)
            if candidate is None or candidate.key == 0:
                continue
            key = candidate.key
            if key in seen_keys:
                continue
            if candidate.printable_ratio < 0.55 or candidate.score < 0.45:
                continue
            seen_keys.add(key)
            decoded_strings = self._extract_strings_from_decoded(
                bytes(b ^ key for b in data)
            )
            findings.append(ObfuscationFinding(
                obfuscation_type=ObfuscationType.XOR_ENCODED_STRINGS,
                offset=offset,
                length=window,
                confidence=min(0.95, candidate.score),
                decoded_value="; ".join(decoded_strings[:5]),
                context_bytes=bytes(b ^ key for b in chunk[:32]),
                description=(
                    f"XOR key 0x{key:02x} — "
                    f"{len(decoded_strings)} strings decoded"
                ),
                xor_key=key,
            ))
        return findings

    def _best_xor_key(self, data: bytes) -> Optional[XorKeyCandidate]:
        if not data:
            return None
        best: Optional[XorKeyCandidate] = None
        for key in range(1, 256):
            decoded = bytes(b ^ key for b in data)
            pr = _printable_ratio(decoded)
            # Bonus for high-frequency English characters
            common = sum(decoded.count(c) for c in b" etaoinshrdlu")
            score = pr * 0.70 + (common / len(data)) * 0.30
            if score > 0.35 and (best is None or score > best.score):
                best = XorKeyCandidate(
                    key=key,
                    score=score,
                    decoded_sample=decoded[:32],
                    printable_ratio=pr,
                )
        return best

    @staticmethod
    def _extract_strings_from_decoded(
        decoded: bytes, min_len: int = 5
    ) -> List[str]:
        strings: List[str] = []
        current: List[int] = []
        for b in decoded:
            if 0x20 <= b < 0x7F:
                current.append(b)
            else:
                if len(current) >= min_len:
                    strings.append(bytes(current).decode("ascii", errors="replace"))
                current = []
        if len(current) >= min_len:
            strings.append(bytes(current).decode("ascii", errors="replace"))
        return strings[:20]

    # ------------------------------------------------------ stack strings

    def _detect_stack_strings(self, data: bytes) -> List[ObfuscationFinding]:
        findings: List[ObfuscationFinding] = []
        for pattern, step in ((_STACK_STR_32, 4), (_STACK_STR_64, 5)):
            for m in pattern.finditer(data):
                raw = m.group(0)
                chars = bytes(raw[i + step - 1] for i in range(0, len(raw), step))
                decoded = chars.decode("ascii", errors="replace")
                findings.append(ObfuscationFinding(
                    obfuscation_type=ObfuscationType.STACK_STRINGS,
                    offset=m.start(),
                    length=len(raw),
                    confidence=0.75,
                    decoded_value=decoded,
                    description=f"Stack-assembled string: '{decoded[:50]}'",
                ))
        return findings

    # ------------------------------------------------- dynamic API resolution

    def _detect_dynamic_api(self, data: bytes) -> List[ObfuscationFinding]:
        findings: List[ObfuscationFinding] = []

        for api_name in _DYNAMIC_API_BYTES:
            idx = 0
            while True:
                pos = data.find(api_name, idx)
                if pos == -1:
                    break
                findings.append(ObfuscationFinding(
                    obfuscation_type=ObfuscationType.DYNAMIC_API_RESOLUTION,
                    offset=pos,
                    length=len(api_name),
                    confidence=0.70,
                    description=f"Dynamic API: {api_name.decode()}",
                ))
                idx = pos + 1

        # Heuristic: high density of indirect CALL-through-register implies
        # hash-based API resolution (no import table entries).
        call_reg = re.compile(rb"\xff[\xd0-\xd7]")
        call_offsets = [m.start() for m in call_reg.finditer(data)]
        if len(call_offsets) > 20:
            findings.append(ObfuscationFinding(
                obfuscation_type=ObfuscationType.IMPORT_TABLE_HIDING,
                offset=call_offsets[0],
                length=2,
                confidence=0.60,
                description=(
                    f"{len(call_offsets)} indirect CALL-reg instructions — "
                    "possible hash-based API resolution"
                ),
            ))
        return findings

    # ------------------------------------------------- anti-disassembly

    def _detect_anti_disassembly(self, data: bytes) -> List[ObfuscationFinding]:
        findings: List[ObfuscationFinding] = []
        for pattern_bytes, description in _ANTI_DISASM_GADGETS:
            idx = 0
            count = 0
            while True:
                pos = data.find(pattern_bytes, idx)
                if pos == -1:
                    break
                count += 1
                if count <= 3:
                    findings.append(ObfuscationFinding(
                        obfuscation_type=ObfuscationType.ANTI_DISASSEMBLY,
                        offset=pos,
                        length=len(pattern_bytes),
                        confidence=0.65,
                        context_bytes=data[max(0, pos - 4):pos + 8],
                        description=description,
                    ))
                idx = pos + 1
        return findings

    # ------------------------------------------------- string encryption

    def _detect_string_encryption(self, data: bytes) -> List[ObfuscationFinding]:
        """
        Flag high-entropy windows that sit adjacent to a decryption loop
        (XOR-byte or ADD-byte over a memory region).
        """
        findings: List[ObfuscationFinding] = []
        window = 256
        # XOR BYTE PTR [reg+disp32], imm8 — decryption loop signature
        decrypt_loop = re.compile(
            rb"\x80[\xb0-\xb7][\x00-\xff]{4}[\x00-\xff]"  # XOR [reg+d32], imm8
            rb"|"
            rb"\x34[\x01-\xfe]"                            # XOR AL, imm8
        )

        for offset in range(0, max(1, len(data) - window), window):
            chunk = data[offset:offset + window]
            ent = _shannon_entropy(chunk)
            if ent < 7.0:
                continue
            pr = _printable_ratio(chunk)
            if pr > 0.65:
                continue  # printable high-entropy is likely plain text / code

            nearby = data[max(0, offset - 64):offset + window + 64]
            if decrypt_loop.search(nearby):
                findings.append(ObfuscationFinding(
                    obfuscation_type=ObfuscationType.STRING_ENCRYPTION,
                    offset=offset,
                    length=window,
                    confidence=0.70,
                    description=(
                        f"Encrypted string region at 0x{offset:x} "
                        f"(H={ent:.2f}, pr={pr:.2f}) adjacent to decrypt loop"
                    ),
                ))
        return findings

    # ---------------------------------------------------- ROT13

    def _detect_rot13_strings(self, data: bytes) -> List[ObfuscationFinding]:
        findings: List[ObfuscationFinding] = []
        alpha_run = re.compile(rb"[A-Za-z]{8,}")
        for m in alpha_run.finditer(data):
            s = m.group(0).decode("ascii")
            decoded = _rot13(s)
            if any(kw in decoded.lower() for kw in _SENSITIVE_KEYWORDS):
                findings.append(ObfuscationFinding(
                    obfuscation_type=ObfuscationType.ROT13_STRINGS,
                    offset=m.start(),
                    length=len(s),
                    confidence=0.55,
                    decoded_value=decoded,
                    description=(
                        f"ROT13 string: '{s[:30]}' → '{decoded[:30]}'"
                    ),
                ))
        return findings

    # ----------------------------------------------------------- scoring

    @staticmethod
    def _compute_score(report: ObfuscationReport) -> float:
        """Weighted sum capped at 100. Each type contributes once."""
        weights: Dict[ObfuscationType, float] = {
            ObfuscationType.BASE64_SHELLCODE:        25.0,
            ObfuscationType.XOR_ENCODED_STRINGS:     20.0,
            ObfuscationType.STACK_STRINGS:            15.0,
            ObfuscationType.DYNAMIC_API_RESOLUTION:  20.0,
            ObfuscationType.ANTI_DISASSEMBLY:         15.0,
            ObfuscationType.IMPORT_TABLE_HIDING:      20.0,
            ObfuscationType.STRING_ENCRYPTION:        18.0,
            ObfuscationType.ROT13_STRINGS:            10.0,
            ObfuscationType.SELF_MODIFYING_CODE:      30.0,
            ObfuscationType.CONTROL_FLOW_FLATTENING:  25.0,
            ObfuscationType.DEAD_CODE:                 8.0,
            ObfuscationType.JUNK_CODE_INSERTION:      12.0,
        }
        type_scores: Dict[ObfuscationType, float] = {}
        for finding in report.findings:
            w = weights.get(finding.obfuscation_type, 10.0)
            scored = w * finding.confidence
            prev = type_scores.get(finding.obfuscation_type, 0.0)
            if scored > prev:
                type_scores[finding.obfuscation_type] = scored
        total = sum(type_scores.values())
        diversity_bonus = len(type_scores) * 2.0
        return min(100.0, total + diversity_bonus)
