"""
Network indicator extractor for binary analysis.
Extracts IP addresses, domains, URLs, email addresses, and other network IOCs
from PE files and arbitrary binary content.
"""

from __future__ import annotations

import ipaddress
import re
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, Iterator, List, Optional, Set, Tuple


class NetworkIndicatorType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    USER_AGENT = "user_agent"
    URI_PATH = "uri_path"
    MUTEX = "mutex"


# Ranges excluded from IOC reporting (RFC 1918, loopback, multicast, etc.)
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("255.255.255.255/32"),
]

_BENIGN_DOMAINS: FrozenSet[str] = frozenset({
    "microsoft.com", "windows.com", "windowsupdate.com",
    "msftncsi.com", "msftconnecttest.com",
    "apple.com", "icloud.com",
    "example.com", "example.org", "localhost",
    "schema.org", "w3.org", "xmlsoap.org",
    "digicert.com", "verisign.com", "comodo.com",
    "ocsp.disa.mil",
})

# Pattern definitions
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

_RE_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
    r"|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b",
    re.IGNORECASE,
)

_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:com|net|org|info|biz|io|co|cc|ru|cn|de|uk|fr|nl|br|"
    r"xyz|top|club|site|online|live|win|download|click|link|"
    r"dyndns\.\w+|no-ip\.\w+)\b",
    re.IGNORECASE,
)

_RE_URL = re.compile(
    r"https?://[^\s\x00-\x1f\"'<>]{4,512}",
    re.IGNORECASE,
)

_RE_EMAIL = re.compile(
    r"\b[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,255}\.[a-zA-Z]{2,}\b"
)

_RE_USER_AGENT = re.compile(
    r"(?:Mozilla|Opera|curl|Python|Go-http|libcurl|Wget|PostmanRuntime)"
    r"[^\x00-\x1f\r\n\"]{5,200}",
    re.IGNORECASE,
)

_RE_MUTEX = re.compile(
    r"(?:Global|Local)\\[a-zA-Z0-9_\-\.]{4,64}"
)

_RE_URI_PATH = re.compile(
    r"/[a-zA-Z0-9._\-/]{3,128}(?:\.php|\.asp|\.jsp|\.cgi|\.pl|\.exe|\.dll|\.bin)\b",
    re.IGNORECASE,
)


@dataclass
class NetworkIndicator:
    indicator_type: NetworkIndicatorType
    value: str
    offset: int  # byte offset in the binary
    encoding: str  # "ascii", "utf-16le", "wide"
    context: bytes = b""  # surrounding bytes for reference
    is_suspicious: bool = False
    notes: List[str] = field(default_factory=list)

    def __hash__(self) -> int:
        return hash((self.indicator_type, self.value.lower()))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NetworkIndicator):
            return NotImplemented
        return (self.indicator_type == other.indicator_type
                and self.value.lower() == other.value.lower())


@dataclass
class NetworkExtractionResult:
    ipv4_addresses: List[NetworkIndicator] = field(default_factory=list)
    ipv6_addresses: List[NetworkIndicator] = field(default_factory=list)
    domains: List[NetworkIndicator] = field(default_factory=list)
    urls: List[NetworkIndicator] = field(default_factory=list)
    emails: List[NetworkIndicator] = field(default_factory=list)
    user_agents: List[NetworkIndicator] = field(default_factory=list)
    uri_paths: List[NetworkIndicator] = field(default_factory=list)
    mutexes: List[NetworkIndicator] = field(default_factory=list)
    total_bytes_scanned: int = 0

    @property
    def all_indicators(self) -> List[NetworkIndicator]:
        return (
            self.ipv4_addresses + self.ipv6_addresses + self.domains +
            self.urls + self.emails + self.user_agents +
            self.uri_paths + self.mutexes
        )

    @property
    def suspicious_indicators(self) -> List[NetworkIndicator]:
        return [ind for ind in self.all_indicators if ind.is_suspicious]

    def summary(self) -> Dict[str, int]:
        return {
            "ipv4": len(self.ipv4_addresses),
            "ipv6": len(self.ipv6_addresses),
            "domains": len(self.domains),
            "urls": len(self.urls),
            "emails": len(self.emails),
            "user_agents": len(self.user_agents),
            "uri_paths": len(self.uri_paths),
            "mutexes": len(self.mutexes),
            "suspicious": len(self.suspicious_indicators),
        }


def _is_private_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def _is_benign_domain(domain: str) -> bool:
    domain_lower = domain.lower()
    # Check exact match or suffix match
    return any(
        domain_lower == bd or domain_lower.endswith("." + bd)
        for bd in _BENIGN_DOMAINS
    )


def _get_context(data: bytes, offset: int, window: int = 16) -> bytes:
    start = max(0, offset - window)
    end = min(len(data), offset + window)
    return data[start:end]


def _extract_wide_strings(data: bytes, min_len: int = 4) -> Iterator[Tuple[str, int]]:
    """
    Extract UTF-16 LE encoded strings (Windows wide char).
    Returns (decoded_string, byte_offset).
    """
    i = 0
    start = -1
    chars = []
    while i < len(data) - 1:
        lo = data[i]
        hi = data[i + 1]
        if hi == 0 and 0x20 <= lo < 0x7F:
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


def _extract_ascii_strings(data: bytes, min_len: int = 4) -> Iterator[Tuple[str, int]]:
    """
    Extract printable ASCII strings from binary data.
    Returns (string, byte_offset).
    """
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


class NetworkExtractor:
    """
    Extracts network-related indicators from binary files.

    Scans both ASCII and wide (UTF-16LE) strings. Filters out:
    - Private and reserved IP ranges
    - Known-benign domains (Microsoft update, CDN endpoints, etc.)
    - Version strings that look like IPs (4.0.0.0 etc.)
    """

    def __init__(
        self,
        include_private_ips: bool = False,
        include_benign_domains: bool = False,
        context_window: int = 32,
        min_string_length: int = 4,
    ) -> None:
        self.include_private_ips = include_private_ips
        self.include_benign_domains = include_benign_domains
        self.context_window = context_window
        self.min_string_length = min_string_length

    def _scan_string(
        self,
        text: str,
        offset: int,
        data: bytes,
        encoding: str,
        result: NetworkExtractionResult,
        seen: Set[Tuple[str, str]],
    ) -> None:
        """Apply all regex extractors to a single string."""
        # URLs - highest priority, most specific
        for m in _RE_URL.finditer(text):
            url = m.group(0).rstrip(".,;)")
            key = ("url", url.lower())
            if key not in seen:
                seen.add(key)
                ind = NetworkIndicator(
                    indicator_type=NetworkIndicatorType.URL,
                    value=url,
                    offset=offset + m.start(),
                    encoding=encoding,
                    context=_get_context(data, offset + m.start(), self.context_window),
                    is_suspicious=True,
                )
                result.urls.append(ind)

        # Emails
        for m in _RE_EMAIL.finditer(text):
            email = m.group(0).lower()
            key = ("email", email)
            if key not in seen:
                seen.add(key)
                ind = NetworkIndicator(
                    indicator_type=NetworkIndicatorType.EMAIL,
                    value=email,
                    offset=offset + m.start(),
                    encoding=encoding,
                    context=_get_context(data, offset + m.start(), self.context_window),
                )
                result.emails.append(ind)

        # IPv4
        for m in _RE_IPV4.finditer(text):
            ip = m.group(0)
            if not self.include_private_ips and _is_private_ip(ip):
                continue
            # Filter out version-style strings like 1.2.3.4 in "version=1.2.3.4"
            pre = text[max(0, m.start() - 8):m.start()]
            if any(c in pre for c in ("=", "(", "v", "V")):
                continue
            key = ("ipv4", ip)
            if key not in seen:
                seen.add(key)
                ind = NetworkIndicator(
                    indicator_type=NetworkIndicatorType.IPV4,
                    value=ip,
                    offset=offset + m.start(),
                    encoding=encoding,
                    context=_get_context(data, offset + m.start(), self.context_window),
                    is_suspicious=True,
                )
                result.ipv4_addresses.append(ind)

        # Domains (only if not already captured as part of a URL)
        for m in _RE_DOMAIN.finditer(text):
            domain = m.group(0).lower()
            if not self.include_benign_domains and _is_benign_domain(domain):
                continue
            # Skip if part of an already-extracted URL
            if any(domain in url.value.lower() for url in result.urls):
                continue
            key = ("domain", domain)
            if key not in seen:
                seen.add(key)
                ind = NetworkIndicator(
                    indicator_type=NetworkIndicatorType.DOMAIN,
                    value=domain,
                    offset=offset + m.start(),
                    encoding=encoding,
                    context=_get_context(data, offset + m.start(), self.context_window),
                    is_suspicious=True,
                )
                result.domains.append(ind)

        # User-agent strings
        for m in _RE_USER_AGENT.finditer(text):
            ua = m.group(0)
            key = ("ua", ua.lower()[:80])
            if key not in seen:
                seen.add(key)
                result.user_agents.append(NetworkIndicator(
                    indicator_type=NetworkIndicatorType.USER_AGENT,
                    value=ua,
                    offset=offset + m.start(),
                    encoding=encoding,
                ))

        # Mutex names
        for m in _RE_MUTEX.finditer(text):
            mutex = m.group(0)
            key = ("mutex", mutex.lower())
            if key not in seen:
                seen.add(key)
                result.mutexes.append(NetworkIndicator(
                    indicator_type=NetworkIndicatorType.MUTEX,
                    value=mutex,
                    offset=offset + m.start(),
                    encoding=encoding,
                    is_suspicious=True,
                ))

        # URI paths (script/binary extensions)
        for m in _RE_URI_PATH.finditer(text):
            path = m.group(0).lower()
            key = ("uri", path)
            if key not in seen:
                seen.add(key)
                result.uri_paths.append(NetworkIndicator(
                    indicator_type=NetworkIndicatorType.URI_PATH,
                    value=path,
                    offset=offset + m.start(),
                    encoding=encoding,
                ))

    def extract(self, data: bytes) -> NetworkExtractionResult:
        """
        Run full network indicator extraction over binary data.
        Scans both ASCII and UTF-16LE encoded strings.
        """
        result = NetworkExtractionResult(total_bytes_scanned=len(data))
        seen: Set[Tuple[str, str]] = set()

        # ASCII pass
        for text, offset in _extract_ascii_strings(data, self.min_string_length):
            self._scan_string(text, offset, data, "ascii", result, seen)

        # Wide string (UTF-16LE) pass
        for text, offset in _extract_wide_strings(data):
            if len(text) >= self.min_string_length:
                self._scan_string(text, offset, data, "utf-16le", result, seen)

        return result

    def extract_from_file(self, path: str) -> NetworkExtractionResult:
        """Load file and run extraction."""
        with open(path, "rb") as f:
            data = f.read()
        return self.extract(data)

    def get_c2_candidates(self, result: NetworkExtractionResult) -> List[NetworkIndicator]:
        """
        Return indicators most likely to be C2 infrastructure.
        Heuristics: IPs not in CDN ranges, domains with DGA patterns,
        URLs with non-standard paths.
        """
        candidates = []

        for ip_ind in result.ipv4_addresses:
            candidates.append(ip_ind)

        for domain_ind in result.domains:
            d = domain_ind.value
            # High consonant ratio suggests DGA
            vowels = sum(1 for c in d if c in "aeiou")
            letters = sum(1 for c in d if c.isalpha())
            if letters > 6 and vowels / max(1, letters) < 0.25:
                domain_ind.is_suspicious = True
                domain_ind.notes.append("possible DGA domain (low vowel ratio)")
            candidates.append(domain_ind)

        for url_ind in result.urls:
            candidates.append(url_ind)

        return candidates
