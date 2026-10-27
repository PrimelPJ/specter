"""
Malware configuration extractor.

Extracts embedded configuration data from PE samples and arbitrary binary blobs:
C2 server addresses, encryption keys, mutex names, campaign identifiers,
sleep intervals, exfiltration endpoints, and botnet IDs.

Extraction strategy uses multi-pass scanning:
  1. Plain-text regex patterns for obvious configs
  2. XOR brute-force over each byte key (0x01–0xFF) with entropy filtering
  3. RC4 key search via key-length heuristics and decryption validation
  4. Base64 decode-then-scan pass
  5. Structured config block detection (common packing patterns)
"""

from __future__ import annotations

import base64
import hashlib
import re
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Enumerations and data classes
# ---------------------------------------------------------------------------

class ConfigFieldType(str, Enum):
    C2_ADDRESS = "c2_address"
    C2_PORT = "c2_port"
    ENCRYPTION_KEY = "encryption_key"
    MUTEX = "mutex"
    CAMPAIGN_ID = "campaign_id"
    BOTNET_ID = "botnet_id"
    SLEEP_INTERVAL = "sleep_interval"
    USER_AGENT = "user_agent"
    REGISTRY_KEY = "registry_key"
    INSTALL_PATH = "install_path"
    EXFIL_ENDPOINT = "exfil_endpoint"
    BEACON_INTERVAL = "beacon_interval"
    JITTER_PERCENT = "jitter_percent"
    PROXY_ADDRESS = "proxy_address"
    RAW_BYTES = "raw_bytes"
    UNKNOWN = "unknown"


@dataclass
class ConfigField:
    field_type: ConfigFieldType
    value: Any
    raw_bytes: bytes = field(default=b"", repr=False)
    offset: int = 0
    extraction_method: str = "plaintext"
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        val = self.value
        if isinstance(val, bytes):
            val = val.hex()
        return {
            "type": self.field_type.value,
            "value": val,
            "offset": self.offset,
            "method": self.extraction_method,
            "confidence": round(self.confidence, 3),
        }


@dataclass
class MalwareConfig:
    sample_hash: str
    extractor_version: str = "1.0"
    fields: List[ConfigField] = field(default_factory=list)
    xor_keys_tried: int = 0
    decode_passes: int = 0

    def add(self, cfg: ConfigField) -> None:
        self.fields.append(cfg)

    def by_type(self, t: ConfigFieldType) -> List[ConfigField]:
        return [f for f in self.fields if f.field_type == t]

    def c2_addresses(self) -> List[str]:
        return [f.value for f in self.by_type(ConfigFieldType.C2_ADDRESS)]

    def encryption_keys(self) -> List[Any]:
        return [f.value for f in self.by_type(ConfigFieldType.ENCRYPTION_KEY)]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_hash": self.sample_hash,
            "extractor_version": self.extractor_version,
            "field_count": len(self.fields),
            "xor_keys_tried": self.xor_keys_tried,
            "decode_passes": self.decode_passes,
            "fields": [f.to_dict() for f in self.fields],
        }


# ---------------------------------------------------------------------------
# Regex pattern library
# ---------------------------------------------------------------------------

# IPv4 + optional port  (handles 1.2.3.4:4444 and plain 1.2.3.4)
_RE_IP_PORT = re.compile(
    rb"(?<![.\d])"
    rb"((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))"
    rb"(?::(\d{1,5}))?(?![.\d])"
)

# Domain names likely used as C2 (>=2 labels, TLD 2-6 chars)
_RE_DOMAIN = re.compile(
    rb"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    rb"[a-zA-Z]{2,6}"
    rb"(?::\d{1,5})?"
)

# URL with scheme
_RE_URL = re.compile(
    rb"https?://[^\x00\s\"'<>]{8,256}"
)

# Windows mutex patterns  (starts uppercase/digit, contains typical chars)
_RE_MUTEX = re.compile(
    rb"(?:Mutex|mutex|MUTEX|mtx)[^\x00]{0,4}[A-Za-z0-9_\-]{4,48}"
)

# Global\Local\ prefix mutexes
_RE_MUTEX_PREFIX = re.compile(
    rb"(?:Global|Local)\\[A-Za-z0-9_\-\.]{4,64}"
)

# Registry keys
_RE_REGKEY = re.compile(
    rb"(?:HKEY_|HKCU\\|HKLM\\|HKCU/|HKLM/)[A-Za-z0-9\\ _\-\\.]{8,256}"
)

# Campaign / botnet identifiers embedded as null-terminated strings
_RE_CAMPAIGN = re.compile(
    rb"(?:campaign|bot(?:net)?|group|tag|ver(?:sion)?)[=:\x00\x20]"
    rb"([A-Za-z0-9_\-\.]{2,32})"
    rb"[\x00\x0a\x0d]",
    re.IGNORECASE,
)

# Sleep/beacon interval values in milliseconds (common malware config)
_RE_SLEEP_MS = re.compile(
    rb"(?:sleep|interval|beacon|delay)[=:\x00\x20]"
    rb"(\d{3,8})"
    rb"[\x00\x0a\x0d ]",
    re.IGNORECASE,
)

# User-Agent strings
_RE_USER_AGENT = re.compile(
    rb"Mozilla/[45]\.0 \([^\x00\n]{10,200}\)"
)

# RC4 / AES key marker patterns
_RE_KEY_MARKER = re.compile(
    rb"(?:key|KEY|secret|SECRET|pass(?:word)?|aes|rc4)[=:\x00\x20]"
    rb"([A-Za-z0-9+/=_\-\.]{8,64})"
    rb"[\x00\x0a\x0d]",
    re.IGNORECASE,
)

# Null-delimited hex-encoded key blobs (AES key material patterns)
_RE_HEX_KEY = re.compile(
    rb"[0-9a-fA-F]{32,64}"
)

# Base64-encoded blocks
_RE_BASE64 = re.compile(
    rb"[A-Za-z0-9+/]{40,}={0,2}"
)

# Windows install path
_RE_INSTALL_PATH = re.compile(
    rb"%(?:APPDATA|TEMP|SystemRoot|ProgramFiles|USERPROFILE)%"
    rb"[A-Za-z0-9\\\._\-]{0,128}"
)

# ---------------------------------------------------------------------------
# Private IP / localhost filter — skip RFC1918, loopback, broadcast
# ---------------------------------------------------------------------------

_PRIVATE_PREFIXES = [
    b"10.", b"127.", b"172.16.", b"172.17.", b"172.18.", b"172.19.",
    b"172.2", b"172.3", b"192.168.", b"169.254.", b"0.0.0.0",
    b"255.255.255.255",
]

def _is_private_ip(ip: bytes) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


# ---------------------------------------------------------------------------
# Entropy utilities
# ---------------------------------------------------------------------------

def _byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    import math
    entropy = 0.0
    for c in counts:
        if c:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 0x20 <= b <= 0x7E)
    return printable / len(data)


# ---------------------------------------------------------------------------
# XOR decoder
# ---------------------------------------------------------------------------

def _xor_decode(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def _xor_decode_multi(data: bytes, key: bytes) -> bytes:
    kl = len(key)
    return bytes(b ^ key[i % kl] for i, b in enumerate(data))


# ---------------------------------------------------------------------------
# RC4 stream cipher
# ---------------------------------------------------------------------------

def _rc4(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)


# ---------------------------------------------------------------------------
# Main extractor class
# ---------------------------------------------------------------------------

class ConfigExtractor:
    """
    Multi-pass malware configuration extractor.

    Scan order:
      1. Plaintext regex pass on raw binary
      2. XOR single-byte key brute-force (all 255 non-zero keys)
      3. Multi-byte XOR with common key lengths (2, 4, 8 bytes)
      4. Base64 decode pass on detected encoded blobs
      5. RC4 decryption with extracted candidate keys
    """

    def __init__(
        self,
        max_xor_passes: bool = True,
        max_b64_blobs: int = 64,
        min_string_len: int = 4,
    ) -> None:
        self.max_xor_passes = max_xor_passes
        self.max_b64_blobs = max_b64_blobs
        self.min_string_len = min_string_len

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def extract(self, data: bytes, sample_path: str = "") -> MalwareConfig:
        sha256 = hashlib.sha256(data).hexdigest()
        config = MalwareConfig(sample_hash=sha256)

        # Pass 1: plaintext scan
        self._plaintext_scan(data, config, offset_base=0, method="plaintext")

        # Pass 2: XOR single-byte brute-force
        if self.max_xor_passes:
            for key in range(1, 256):
                decoded = _xor_decode(data, key)
                # Only bother scanning if decode yields more printable text
                if _printable_ratio(decoded) > 0.35:
                    self._plaintext_scan(
                        decoded, config,
                        offset_base=0,
                        method=f"xor_0x{key:02x}",
                        confidence_multiplier=0.75,
                    )
            config.xor_keys_tried = 255

        # Pass 3: multi-byte XOR with keys extracted from plaintext
        for key_field in config.by_type(ConfigFieldType.ENCRYPTION_KEY):
            raw = key_field.raw_bytes
            if 2 <= len(raw) <= 16:
                decoded = _xor_decode_multi(data, raw)
                if _printable_ratio(decoded) > 0.35:
                    self._plaintext_scan(
                        decoded, config,
                        offset_base=0,
                        method=f"xor_multi_{raw.hex()[:8]}",
                        confidence_multiplier=0.65,
                    )

        # Pass 4: Base64 decode pass
        b64_count = 0
        for match in _RE_BASE64.finditer(data):
            if b64_count >= self.max_b64_blobs:
                break
            try:
                decoded = base64.b64decode(match.group(0), validate=True)
                if len(decoded) >= 8 and _printable_ratio(decoded) > 0.40:
                    self._plaintext_scan(
                        decoded, config,
                        offset_base=match.start(),
                        method="base64_decode",
                        confidence_multiplier=0.80,
                    )
                    b64_count += 1
            except Exception:
                pass
        config.decode_passes = b64_count

        # Pass 5: RC4 with candidate key material
        rc4_keys = self._collect_rc4_keys(data, config)
        for rc4_key in rc4_keys[:8]:
            try:
                decoded = _rc4(data[:16384], rc4_key)
                if _printable_ratio(decoded) > 0.40:
                    self._plaintext_scan(
                        decoded, config,
                        offset_base=0,
                        method=f"rc4_{rc4_key.hex()[:12]}",
                        confidence_multiplier=0.60,
                    )
            except Exception:
                pass

        self._deduplicate(config)
        return config

    # ------------------------------------------------------------------
    # Plaintext scanning
    # ------------------------------------------------------------------

    def _plaintext_scan(
        self,
        data: bytes,
        config: MalwareConfig,
        offset_base: int,
        method: str,
        confidence_multiplier: float = 1.0,
    ) -> None:
        seen_values: Set[str] = set()

        # C2 IPs
        for m in _RE_IP_PORT.finditer(data):
            ip = m.group(1)
            if _is_private_ip(ip):
                continue
            ip_str = ip.decode("ascii", errors="ignore")
            port_bytes = m.group(2)
            port = int(port_bytes) if port_bytes else None
            if 1 <= (port or 80) <= 65535:
                value = f"{ip_str}:{port}" if port else ip_str
                if value not in seen_values:
                    seen_values.add(value)
                    config.add(ConfigField(
                        field_type=ConfigFieldType.C2_ADDRESS,
                        value=value,
                        raw_bytes=m.group(0),
                        offset=offset_base + m.start(),
                        extraction_method=method,
                        confidence=0.85 * confidence_multiplier,
                    ))
                    if port:
                        config.add(ConfigField(
                            field_type=ConfigFieldType.C2_PORT,
                            value=port,
                            raw_bytes=port_bytes,
                            offset=offset_base + m.start(2),
                            extraction_method=method,
                            confidence=0.85 * confidence_multiplier,
                        ))

        # C2 domains
        for m in _RE_DOMAIN.finditer(data):
            raw = m.group(0)
            domain_str = raw.split(b":")[0].decode("ascii", errors="ignore").lower()
            # Skip very short or obviously not C2
            if len(domain_str) < 6 or "." not in domain_str:
                continue
            if domain_str in seen_values:
                continue
            seen_values.add(domain_str)
            config.add(ConfigField(
                field_type=ConfigFieldType.C2_ADDRESS,
                value=domain_str,
                raw_bytes=raw,
                offset=offset_base + m.start(),
                extraction_method=method,
                confidence=0.80 * confidence_multiplier,
            ))

        # URLs
        for m in _RE_URL.finditer(data):
            url = m.group(0).decode("ascii", errors="ignore").rstrip("\x00 \t")
            if url not in seen_values:
                seen_values.add(url)
                config.add(ConfigField(
                    field_type=ConfigFieldType.EXFIL_ENDPOINT,
                    value=url,
                    raw_bytes=m.group(0),
                    offset=offset_base + m.start(),
                    extraction_method=method,
                    confidence=0.90 * confidence_multiplier,
                ))

        # Mutexes
        for pattern in (_RE_MUTEX, _RE_MUTEX_PREFIX):
            for m in pattern.finditer(data):
                raw = m.group(0)
                mutex_str = raw.decode("ascii", errors="ignore").rstrip("\x00")
                if mutex_str not in seen_values:
                    seen_values.add(mutex_str)
                    config.add(ConfigField(
                        field_type=ConfigFieldType.MUTEX,
                        value=mutex_str,
                        raw_bytes=raw,
                        offset=offset_base + m.start(),
                        extraction_method=method,
                        confidence=0.88 * confidence_multiplier,
                    ))

        # Registry keys
        for m in _RE_REGKEY.finditer(data):
            raw = m.group(0)
            key_str = raw.decode("ascii", errors="ignore").rstrip("\x00 ")
            if key_str not in seen_values:
                seen_values.add(key_str)
                config.add(ConfigField(
                    field_type=ConfigFieldType.REGISTRY_KEY,
                    value=key_str,
                    raw_bytes=raw,
                    offset=offset_base + m.start(),
                    extraction_method=method,
                    confidence=0.87 * confidence_multiplier,
                ))

        # Campaign/botnet IDs
        for m in _RE_CAMPAIGN.finditer(data):
            val = m.group(1).decode("ascii", errors="ignore")
            if val not in seen_values:
                seen_values.add(val)
                config.add(ConfigField(
                    field_type=ConfigFieldType.CAMPAIGN_ID,
                    value=val,
                    raw_bytes=m.group(0),
                    offset=offset_base + m.start(),
                    extraction_method=method,
                    confidence=0.78 * confidence_multiplier,
                ))

        # Sleep intervals
        for m in _RE_SLEEP_MS.finditer(data):
            try:
                ms = int(m.group(1))
                key = f"sleep_{ms}"
                if key not in seen_values:
                    seen_values.add(key)
                    config.add(ConfigField(
                        field_type=ConfigFieldType.SLEEP_INTERVAL,
                        value=ms,
                        raw_bytes=m.group(1),
                        offset=offset_base + m.start(1),
                        extraction_method=method,
                        confidence=0.70 * confidence_multiplier,
                    ))
            except ValueError:
                pass

        # User-Agent
        for m in _RE_USER_AGENT.finditer(data):
            ua = m.group(0).decode("ascii", errors="ignore")
            if ua not in seen_values:
                seen_values.add(ua)
                config.add(ConfigField(
                    field_type=ConfigFieldType.USER_AGENT,
                    value=ua,
                    raw_bytes=m.group(0),
                    offset=offset_base + m.start(),
                    extraction_method=method,
                    confidence=0.92 * confidence_multiplier,
                ))

        # Key material (markers)
        for m in _RE_KEY_MARKER.finditer(data):
            raw = m.group(1)
            key_str = raw.decode("ascii", errors="ignore")
            if key_str not in seen_values:
                seen_values.add(key_str)
                config.add(ConfigField(
                    field_type=ConfigFieldType.ENCRYPTION_KEY,
                    value=key_str,
                    raw_bytes=raw,
                    offset=offset_base + m.start(1),
                    extraction_method=method,
                    confidence=0.75 * confidence_multiplier,
                ))

        # Hex key blobs (high-entropy)
        for m in _RE_HEX_KEY.finditer(data):
            raw = m.group(0)
            if len(raw) not in (32, 40, 48, 64):  # MD5/SHA1/SHA384/SHA256 lengths
                continue
            if _byte_entropy(raw) < 3.5:  # low-entropy hex = probably not a key
                continue
            hex_val = raw.decode("ascii", errors="ignore").lower()
            if hex_val not in seen_values:
                seen_values.add(hex_val)
                config.add(ConfigField(
                    field_type=ConfigFieldType.ENCRYPTION_KEY,
                    value=hex_val,
                    raw_bytes=raw,
                    offset=offset_base + m.start(),
                    extraction_method=method,
                    confidence=0.60 * confidence_multiplier,
                ))

        # Install path
        for m in _RE_INSTALL_PATH.finditer(data):
            raw = m.group(0)
            path_str = raw.decode("ascii", errors="ignore")
            if path_str not in seen_values:
                seen_values.add(path_str)
                config.add(ConfigField(
                    field_type=ConfigFieldType.INSTALL_PATH,
                    value=path_str,
                    raw_bytes=raw,
                    offset=offset_base + m.start(),
                    extraction_method=method,
                    confidence=0.82 * confidence_multiplier,
                ))

    # ------------------------------------------------------------------
    # RC4 key collection heuristics
    # ------------------------------------------------------------------

    def _collect_rc4_keys(self, data: bytes, config: MalwareConfig) -> List[bytes]:
        keys: List[bytes] = []
        for f in config.by_type(ConfigFieldType.ENCRYPTION_KEY):
            raw = f.raw_bytes
            if 5 <= len(raw) <= 32:
                keys.append(raw)
            val = f.value
            if isinstance(val, str) and 5 <= len(val) <= 32:
                keys.append(val.encode())

        # Also scan for high-entropy 16-32 byte segments
        chunk_size = 32
        for offset in range(0, min(len(data), 65536), chunk_size):
            chunk = data[offset:offset + chunk_size]
            if 16 <= len(chunk) <= 32 and _byte_entropy(chunk) > 5.5:
                keys.append(chunk[:16])
        return keys

    # ------------------------------------------------------------------
    # Deduplication — remove fields with identical (type, value)
    # ------------------------------------------------------------------

    def _deduplicate(self, config: MalwareConfig) -> None:
        seen: Set[Tuple[str, Any]] = set()
        unique: List[ConfigField] = []
        for f in config.fields:
            key = (f.field_type.value, str(f.value))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        config.fields = unique


# ---------------------------------------------------------------------------
# Structured config block scanner
# ---------------------------------------------------------------------------

class StructuredConfigScanner:
    """
    Scans for common structured config block patterns found in commodity malware.

    Looks for:
    - Size-prefixed string tables (Pascal-style)
    - Fixed-offset config structs common in older RATs
    - Null-delimited key=value config blocks
    """

    MAX_BLOCK_SIZE = 4096

    def scan(self, data: bytes) -> List[ConfigField]:
        fields: List[ConfigField] = []
        fields.extend(self._scan_pascal_strings(data))
        fields.extend(self._scan_kv_blocks(data))
        fields.extend(self._scan_null_separated_lists(data))
        return fields

    def _scan_pascal_strings(self, data: bytes) -> List[ConfigField]:
        results: List[ConfigField] = []
        i = 0
        while i < len(data) - 2:
            length = struct.unpack_from("H", data, i)[0]
            if 4 <= length <= 512:
                end = i + 2 + length
                if end <= len(data):
                    candidate = data[i + 2:end]
                    ratio = _printable_ratio(candidate)
                    if ratio > 0.90:
                        text = candidate.decode("ascii", errors="replace")
                        field_type = _classify_string(text)
                        if field_type != ConfigFieldType.UNKNOWN:
                            results.append(ConfigField(
                                field_type=field_type,
                                value=text,
                                raw_bytes=candidate,
                                offset=i,
                                extraction_method="pascal_string",
                                confidence=0.65,
                            ))
            i += 1
        return results

    def _scan_kv_blocks(self, data: bytes) -> List[ConfigField]:
        results: List[ConfigField] = []
        pattern = re.compile(rb"([A-Za-z_]{2,24})=([^\x00\n\r]{1,256})[\x00\n\r]")
        for m in pattern.finditer(data):
            key_b = m.group(1).lower()
            val_b = m.group(2)
            val_str = val_b.decode("ascii", errors="ignore").strip()
            field_type = _kv_key_to_field_type(key_b)
            if field_type != ConfigFieldType.UNKNOWN:
                results.append(ConfigField(
                    field_type=field_type,
                    value=val_str,
                    raw_bytes=m.group(0),
                    offset=m.start(),
                    extraction_method="kv_block",
                    confidence=0.80,
                ))
        return results

    def _scan_null_separated_lists(self, data: bytes) -> List[ConfigField]:
        results: List[ConfigField] = []
        # Look for runs of null-separated strings in a window that looks config-like
        chunk_size = 512
        for base in range(0, len(data) - chunk_size, chunk_size // 4):
            chunk = data[base:base + chunk_size]
            parts = chunk.split(b"\x00")
            printable_parts = [
                p for p in parts
                if 4 <= len(p) <= 256 and _printable_ratio(p) > 0.90
            ]
            if len(printable_parts) >= 3:
                for p in printable_parts:
                    text = p.decode("ascii", errors="ignore")
                    field_type = _classify_string(text)
                    if field_type != ConfigFieldType.UNKNOWN:
                        results.append(ConfigField(
                            field_type=field_type,
                            value=text,
                            raw_bytes=p,
                            offset=base,
                            extraction_method="null_list",
                            confidence=0.55,
                        ))
        return results


def _classify_string(text: str) -> ConfigFieldType:
    if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text):
        return ConfigFieldType.C2_ADDRESS
    if re.match(r"https?://", text):
        return ConfigFieldType.EXFIL_ENDPOINT
    if re.match(r"(?:HKCU|HKLM|HKEY_)\\", text):
        return ConfigFieldType.REGISTRY_KEY
    if re.match(r"%(?:APPDATA|TEMP|SystemRoot)%", text):
        return ConfigFieldType.INSTALL_PATH
    if re.search(r"(?:mutex|mtx|Global\\|Local\\)", text, re.IGNORECASE):
        return ConfigFieldType.MUTEX
    if len(text) in (32, 40, 64) and re.match(r"[0-9a-fA-F]+$", text):
        return ConfigFieldType.ENCRYPTION_KEY
    return ConfigFieldType.UNKNOWN


def _kv_key_to_field_type(key: bytes) -> ConfigFieldType:
    mapping = {
        b"host": ConfigFieldType.C2_ADDRESS,
        b"server": ConfigFieldType.C2_ADDRESS,
        b"c2": ConfigFieldType.C2_ADDRESS,
        b"domain": ConfigFieldType.C2_ADDRESS,
        b"port": ConfigFieldType.C2_PORT,
        b"mutex": ConfigFieldType.MUTEX,
        b"mtx": ConfigFieldType.MUTEX,
        b"campaign": ConfigFieldType.CAMPAIGN_ID,
        b"group": ConfigFieldType.BOTNET_ID,
        b"botid": ConfigFieldType.BOTNET_ID,
        b"sleep": ConfigFieldType.SLEEP_INTERVAL,
        b"delay": ConfigFieldType.SLEEP_INTERVAL,
        b"interval": ConfigFieldType.BEACON_INTERVAL,
        b"key": ConfigFieldType.ENCRYPTION_KEY,
        b"password": ConfigFieldType.ENCRYPTION_KEY,
        b"useragent": ConfigFieldType.USER_AGENT,
        b"ua": ConfigFieldType.USER_AGENT,
        b"install": ConfigFieldType.INSTALL_PATH,
        b"path": ConfigFieldType.INSTALL_PATH,
        b"url": ConfigFieldType.EXFIL_ENDPOINT,
        b"endpoint": ConfigFieldType.EXFIL_ENDPOINT,
    }
    return mapping.get(key, ConfigFieldType.UNKNOWN)


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------

def extract_config(data: bytes, sample_path: str = "") -> MalwareConfig:
    extractor = ConfigExtractor()
    config = extractor.extract(data, sample_path=sample_path)
    structured = StructuredConfigScanner().scan(data)
    for f in structured:
        config.add(f)
    extractor._deduplicate(config)
    return config
