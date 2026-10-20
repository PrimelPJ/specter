"""
Advanced string extraction for malware analysis.
Handles ASCII, wide-char, stack strings, XOR-obfuscated strings,
base64-encoded payloads, and Unicode decomposition.
"""

from __future__ import annotations

import base64
import itertools
import re
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterator, List, Optional, Set, Tuple


class StringEncoding(str, Enum):
    ASCII = "ascii"
    UTF16LE = "utf-16le"
    UTF16BE = "utf-16be"
    UTF8 = "utf-8"
    XOR = "xor"
    BASE64 = "base64"
    ROT13 = "rot13"
    STACK = "stack"     # Stack-constructed string (push byte sequences)


class StringCategory(str, Enum):
    PATH = "path"
    REGISTRY = "registry"
    NETWORK = "network"
    API_CALL = "api_call"
    COMMAND = "command"
    MUTEX = "mutex"
    CRYPTO = "crypto"
    GENERIC = "generic"
    OBFUSCATED = "obfuscated"


_RE_BASE64 = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_RE_HEX_STRING = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
_RE_WINDOWS_PATH = re.compile(r"[A-Za-z]:\\(?:[^\x00-\x1f\\/:*?\"<>|]+\\)*[^\x00-\x1f\\/:*?\"<>|]*", re.IGNORECASE)
_RE_REGISTRY = re.compile(r"(?:HKEY_|HKCU|HKLM|HKU|HKCC|HKCR)[\\\w]+", re.IGNORECASE)
_RE_COMMAND = re.compile(r"(?:cmd(?:\.exe)?|powershell(?:\.exe)?|wscript|cscript|regsvr32|rundll32|mshta|wmic)\b.*", re.IGNORECASE)
_RE_API_CALLS = re.compile(
    r"\b(?:VirtualAlloc|VirtualProtect|CreateRemoteThread|WriteProcessMemory|"
    r"NtUnmapViewOfSection|RtlDecompressBuffer|LoadLibrary(?:A|W|ExA|ExW)?|"
    r"GetProcAddress|ShellExecute(?:A|W)?|CreateProcess(?:A|W)?|"
    r"InternetOpen(?:A|W)?|HttpSendRequest|URLDownloadToFile|"
    r"CryptEncrypt|BCryptEncrypt|RegSetValue|SetWindowsHookEx)\b"
)
_RE_MUTEX_NAME = re.compile(r"(?:Global|Local)\\[^\x00-\x1f]{4,64}|(?:_MUTEX_|_mutex_)[A-Z0-9_]+", re.IGNORECASE)
_RE_CRYPTO_CONST = re.compile(r"(?:AES|RSA|RC4|Salsa20|ChaCha|SHA-?(?:1|256|512)|MD5)\b", re.IGNORECASE)


@dataclass
class ExtractedString:
    value: str
    encoding: StringEncoding
    offset: int
    length: int
    category: StringCategory = StringCategory.GENERIC
    xor_key: Optional[int] = None         # For XOR-decoded strings
    entropy: float = 0.0
    is_suspicious: bool = False
    notes: List[str] = field(default_factory=list)

    def __hash__(self) -> int:
        return hash((self.encoding, self.value))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ExtractedString):
            return NotImplemented
        return self.encoding == other.encoding and self.value == other.value

    @property
    def printable_value(self) -> str:
        return "".join(c if c.isprintable() else "." for c in self.value)


@dataclass
class StringExtractionResult:
    strings: List[ExtractedString] = field(default_factory=list)
    base64_decoded: List[Tuple[str, bytes]] = field(default_factory=list)  # (original, decoded)
    xor_decoded: List[ExtractedString] = field(default_factory=list)
    total_bytes_scanned: int = 0

    def by_category(self, category: StringCategory) -> List[ExtractedString]:
        return [s for s in self.strings if s.category == category]

    def suspicious(self) -> List[ExtractedString]:
        return [s for s in self.strings if s.is_suspicious]

    def by_encoding(self, encoding: StringEncoding) -> List[ExtractedString]:
        return [s for s in self.strings if s.encoding == encoding]

    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for s in self.strings:
            counts[s.category.value] = counts.get(s.category.value, 0) + 1
        counts["total"] = len(self.strings)
        counts["suspicious"] = len(self.suspicious())
        counts["base64_payloads"] = len(self.base64_decoded)
        counts["xor_decoded"] = len(self.xor_decoded)
        return counts


def _calculate_string_entropy(s: str) -> float:
    """Shannon entropy for a string."""
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    import math
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def _categorize_string(value: str) -> Tuple[StringCategory, bool, List[str]]:
    """Classify a string and flag suspicious patterns."""
    notes = []
    is_suspicious = False

    if _RE_WINDOWS_PATH.search(value):
        return StringCategory.PATH, False, notes

    if _RE_REGISTRY.search(value):
        return StringCategory.REGISTRY, False, notes

    if _RE_MUTEX_NAME.search(value):
        return StringCategory.MUTEX, True, ["mutex name pattern"]

    if _RE_API_CALLS.search(value):
        is_suspicious = True
        notes.append("sensitive API call name")
        return StringCategory.API_CALL, is_suspicious, notes

    if _RE_COMMAND.search(value):
        is_suspicious = True
        notes.append("command execution pattern")
        return StringCategory.COMMAND, is_suspicious, notes

    if _RE_CRYPTO_CONST.search(value):
        return StringCategory.CRYPTO, False, notes

    if re.search(r"https?://|ftp://|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", value):
        is_suspicious = True
        notes.append("network indicator")
        return StringCategory.NETWORK, is_suspicious, notes

    return StringCategory.GENERIC, False, notes


def _decode_xor(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def _is_printable_ratio(data: bytes, threshold: float = 0.80) -> bool:
    printable = sum(1 for b in data if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
    return printable / max(1, len(data)) >= threshold


def _extract_ascii_strings(data: bytes, min_len: int = 4) -> Iterator[Tuple[str, int]]:
    i = 0
    start = -1
    chars: List[str] = []
    while i < len(data):
        b = data[i]
        if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D):
            if start == -1:
                start = i
            chars.append(chr(b))
        else:
            if len(chars) >= min_len:
                yield "".join(chars), start
            chars = []
            start = -1
        i += 1
    if len(chars) >= min_len:
        yield "".join(chars), start


def _extract_wide_strings(data: bytes, min_len: int = 4) -> Iterator[Tuple[str, int]]:
    i = 0
    start = -1
    chars: List[str] = []
    while i < len(data) - 1:
        lo = data[i]
        hi = data[i + 1]
        if hi == 0 and (0x20 <= lo < 0x7F or lo in (0x09, 0x0A, 0x0D)):
            if start == -1:
                start = i
            chars.append(chr(lo))
        else:
            if len(chars) >= min_len:
                yield "".join(chars), start
            chars = []
            start = -1
        i += 2
    if len(chars) >= min_len:
        yield "".join(chars), start


def _try_decode_base64(candidate: str) -> Optional[bytes]:
    """Attempt to decode a base64 candidate. Returns decoded bytes or None."""
    # Normalize padding
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        decoded = base64.b64decode(padded)
        if len(decoded) >= 8 and _is_printable_ratio(decoded, 0.70):
            return decoded
        # Check for nested binary payloads (PE, ELF, scripts)
        if decoded[:2] == b"MZ" or decoded[:4] == b"\x7fELF":
            return decoded
        if len(decoded) >= 16:
            return decoded
    except Exception:
        pass
    return None


class StringExtractor:
    """
    Multi-encoding string extractor for malware samples.

    Features:
    - ASCII and UTF-16LE extraction with minimum length filtering
    - Base64 decoding of embedded payloads
    - XOR brute-force for single-byte XOR obfuscation
    - String categorization (path, registry, API, command, network, crypto)
    - Entropy-based suspicion scoring
    - Stack string reconstruction heuristics
    """

    XOR_KEYS_TO_TRY = list(range(1, 256))

    def __init__(
        self,
        min_length: int = 4,
        max_length: int = 512,
        decode_base64: bool = True,
        brute_xor: bool = True,
        brute_xor_min_printable: float = 0.85,
        deduplicate: bool = True,
    ) -> None:
        self.min_length = min_length
        self.max_length = max_length
        self.decode_base64 = decode_base64
        self.brute_xor = brute_xor
        self.brute_xor_min_printable = brute_xor_min_printable
        self.deduplicate = deduplicate

    def _make_string(
        self,
        value: str,
        encoding: StringEncoding,
        offset: int,
        xor_key: Optional[int] = None,
    ) -> ExtractedString:
        category, is_suspicious, notes = _categorize_string(value)
        entropy = _calculate_string_entropy(value)
        if entropy > 4.5 and len(value) > 20:
            is_suspicious = True
            notes.append(f"high entropy ({entropy:.2f})")
        return ExtractedString(
            value=value,
            encoding=encoding,
            offset=offset,
            length=len(value),
            category=category,
            xor_key=xor_key,
            entropy=entropy,
            is_suspicious=is_suspicious,
            notes=notes,
        )

    def _process_base64(
        self,
        ascii_strings: List[Tuple[str, int]],
        result: StringExtractionResult,
    ) -> None:
        for text, offset in ascii_strings:
            for m in _RE_BASE64.finditer(text):
                candidate = m.group(0)
                if len(candidate) < 20:
                    continue
                decoded = _try_decode_base64(candidate)
                if decoded:
                    result.base64_decoded.append((candidate, decoded))
                    # Recursively extract strings from decoded payload
                    try:
                        inner_text = decoded.decode("ascii", errors="replace")
                        if len(inner_text) >= self.min_length:
                            es = self._make_string(
                                inner_text[:self.max_length],
                                StringEncoding.BASE64,
                                offset + m.start(),
                            )
                            es.notes.append(f"decoded from base64 ({len(candidate)}b → {len(decoded)}b)")
                            result.strings.append(es)
                    except Exception:
                        pass

    def _brute_xor_scan(
        self,
        data: bytes,
        result: StringExtractionResult,
        chunk_size: int = 64,
        step: int = 1,
    ) -> None:
        """
        Slide a window over the binary and test single-byte XOR keys.
        When a key produces a high printable ratio, extract strings from the result.
        """
        seen_decoded: Set[str] = set()
        # Only scan chunks that have low natural printability (likely obfuscated)
        i = 0
        while i < len(data) - chunk_size:
            chunk = data[i:i + chunk_size]
            natural_ratio = sum(1 for b in chunk if 0x20 <= b < 0x7F) / chunk_size
            if natural_ratio > 0.6:
                i += step
                continue

            for key in self.XOR_KEYS_TO_TRY:
                decoded = _decode_xor(chunk, key)
                ratio = sum(1 for b in decoded if 0x20 <= b < 0x7F) / chunk_size
                if ratio >= self.brute_xor_min_printable:
                    text = decoded.decode("ascii", errors="replace").strip()
                    if len(text) >= self.min_length and text not in seen_decoded:
                        seen_decoded.add(text)
                        es = self._make_string(text, StringEncoding.XOR, i, xor_key=key)
                        es.notes.append(f"XOR key=0x{key:02x}, ratio={ratio:.2f}")
                        es.is_suspicious = True
                        result.xor_decoded.append(es)
                        result.strings.append(es)
                        break
            i += step

    def extract(self, data: bytes) -> StringExtractionResult:
        """Run full string extraction pipeline on binary data."""
        result = StringExtractionResult(total_bytes_scanned=len(data))
        seen: Set[str] = set()

        # ASCII strings
        ascii_strings = list(_extract_ascii_strings(data, self.min_length))
        for text, offset in ascii_strings:
            if len(text) > self.max_length:
                text = text[:self.max_length]
            key = f"ascii:{text}"
            if self.deduplicate and key in seen:
                continue
            seen.add(key)
            result.strings.append(
                self._make_string(text, StringEncoding.ASCII, offset)
            )

        # Wide (UTF-16LE) strings
        for text, offset in _extract_wide_strings(data, self.min_length):
            if len(text) > self.max_length:
                text = text[:self.max_length]
            key = f"wide:{text}"
            if self.deduplicate and key in seen:
                continue
            seen.add(key)
            result.strings.append(
                self._make_string(text, StringEncoding.UTF16LE, offset)
            )

        # Base64 decoding pass
        if self.decode_base64:
            self._process_base64(ascii_strings, result)

        # XOR brute-force
        if self.brute_xor and len(data) <= 5 * 1024 * 1024:  # skip huge files
            self._brute_xor_scan(data, result, chunk_size=32)

        return result

    def extract_from_file(self, path: str) -> StringExtractionResult:
        with open(path, "rb") as f:
            data = f.read()
        return self.extract(data)

    def extract_api_calls(self, data: bytes) -> List[str]:
        """Quick extract of Windows API function names only."""
        result = self.extract(data)
        return sorted({s.value for s in result.strings if s.category == StringCategory.API_CALL})

    def find_suspicious_strings(self, data: bytes) -> List[ExtractedString]:
        """Extract only suspicious strings for quick triage."""
        result = self.extract(data)
        return result.suspicious()
