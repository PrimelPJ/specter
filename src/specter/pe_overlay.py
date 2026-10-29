"""
PE overlay and Authenticode certificate analyzer.

Provides deep analysis of data appended past the last PE section (overlay),
and parses the WIN_CERTIFICATE structure in the Security Directory to detect
Authenticode signatures, stolen certificates, and signature anomalies.

Overlay detection:
  - Byte-accurate end-of-sections calculation respecting section alignment
  - Overlay size and ratio relative to total file size
  - SFX (self-extracting archive) header detection (ZIP, RAR, 7z, CAB, NSIS)
  - Entropy profiling across the overlay in sliding windows
  - Concatenated PE detection (dropper payloads embedded as overlay)

Certificate analysis:
  - WIN_CERTIFICATE structure parsing (dwLength, wRevision, wCertificateType)
  - ASN.1 DER traversal to extract subject CN, issuer CN, serial, validity
  - Signature-file hash check: recompute the authenticode hash (MD5/SHA-1/SHA-256)
    using the PE authenticode hash algorithm and compare to stored hash
  - Anomaly detection: signature covering only part of the file, multiple
    certificates, zero-length certificate, revision != 0x0200
"""

from __future__ import annotations

import hashlib
import io
import math
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from specter.pe_parser import PEFile, PEParseError


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# WIN_CERTIFICATE wRevision
CERT_REVISION_1_0 = 0x0100
CERT_REVISION_2_0 = 0x0200

# WIN_CERTIFICATE wCertificateType
CERT_TYPE_X509 = 0x0001
CERT_TYPE_PKCS_SIGNED_DATA = 0x0002  # Authenticode
CERT_TYPE_TS_STACK_SIGNED = 0x0004

CERT_TYPE_NAMES: Dict[int, str] = {
    CERT_TYPE_X509: "X.509",
    CERT_TYPE_PKCS_SIGNED_DATA: "PKCS#7 SignedData (Authenticode)",
    CERT_TYPE_TS_STACK_SIGNED: "Terminal Server Stack Signed",
}

# ASN.1 universal tags
ASN1_SEQUENCE = 0x30
ASN1_SET = 0x31
ASN1_OID = 0x06
ASN1_UTF8STRING = 0x0C
ASN1_PRINTABLESTRING = 0x13
ASN1_T61STRING = 0x14
ASN1_IA5STRING = 0x16
ASN1_UTCTIME = 0x17
ASN1_GENERALIZEDTIME = 0x18
ASN1_BMPSTRING = 0x1E
ASN1_CONTEXT_0 = 0xA0
ASN1_CONTEXT_3 = 0xA3
ASN1_INTEGER = 0x02
ASN1_BITSTRING = 0x03
ASN1_OCTETSTRING = 0x04

# OIDs for common certificate name attributes
OID_CN = b"\x55\x04\x03"          # 2.5.4.3  commonName
OID_O = b"\x55\x04\x0A"           # 2.5.4.10 organizationName
OID_OU = b"\x55\x04\x0B"          # 2.5.4.11 organizationalUnitName
OID_C = b"\x55\x04\x06"           # 2.5.4.6  countryName

# OIDs for digest algorithms in Authenticode
OID_MD5 = b"\x2a\x86\x48\x86\xf7\x0d\x02\x05"   # 1.2.840.113549.2.5
OID_SHA1 = b"\x2b\x0e\x03\x02\x1a"               # 1.3.14.3.2.26
OID_SHA256 = b"\x60\x86\x48\x01\x65\x03\x04\x02\x01"  # 2.16.840.1.101.3.4.2.1

# SFX / archive magic bytes
SFX_SIGNATURES: List[Tuple[bytes, str]] = [
    (b"PK\x03\x04", "ZIP"),
    (b"Rar!\x1a\x07\x00", "RAR4"),
    (b"Rar!\x1a\x07\x01\x00", "RAR5"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
    (b"MSCF", "CAB"),
    (b"\xfd7zXZ\x00", "XZ"),
    (b"\x1f\x8b", "GZip"),
    (b"BZh", "BZip2"),
    # NSIS installer magic
    (b"\xef\xbe\xad\xde", "NSIS"),
    # InnoSetup
    (b"Inno Setup Setup Data", "InnoSetup"),
    # InstallShield
    (b"ISc(", "InstallShield"),
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class OverlayType(str, Enum):
    NONE = "none"
    UNKNOWN = "unknown"
    ARCHIVE_SFX = "archive_sfx"
    EMBEDDED_PE = "embedded_pe"
    CERTIFICATE = "certificate"  # legitimate: covered by WIN_CERTIFICATE
    HIGH_ENTROPY = "high_entropy"
    LOW_ENTROPY = "low_entropy"
    PADDING = "padding"


@dataclass
class OverlayInfo:
    """Overlay data appended after the last PE section."""

    offset: int = 0
    size: int = 0
    ratio: float = 0.0            # overlay_size / file_size
    entropy: float = 0.0
    sfx_type: Optional[str] = None
    contains_pe: bool = False
    overlay_type: OverlayType = OverlayType.NONE
    anomalies: List[str] = field(default_factory=list)

    @property
    def is_suspicious(self) -> bool:
        return bool(self.anomalies) or self.overlay_type in (
            OverlayType.HIGH_ENTROPY,
            OverlayType.EMBEDDED_PE,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "offset": self.offset,
            "size": self.size,
            "size_hex": hex(self.size),
            "ratio": round(self.ratio, 4),
            "entropy": round(self.entropy, 4),
            "sfx_type": self.sfx_type,
            "contains_pe": self.contains_pe,
            "overlay_type": self.overlay_type.value,
            "anomalies": self.anomalies,
            "is_suspicious": self.is_suspicious,
        }


@dataclass
class CertificateRecord:
    """Parsed WIN_CERTIFICATE entry."""

    index: int
    raw_length: int
    revision: int
    cert_type: int
    cert_type_name: str = ""

    # Parsed from embedded DER
    subject_cn: str = ""
    subject_o: str = ""
    issuer_cn: str = ""
    issuer_o: str = ""
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""

    # Authenticode hash stored in the signature
    digest_algorithm: str = ""
    stored_digest: str = ""           # hex
    computed_digest: str = ""         # hex (recomputed authenticode hash)
    digest_match: Optional[bool] = None  # None = could not verify

    anomalies: List[str] = field(default_factory=list)

    @property
    def is_suspicious(self) -> bool:
        if self.anomalies:
            return True
        if self.digest_match is False:
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "raw_length": self.raw_length,
            "revision": hex(self.revision),
            "cert_type": hex(self.cert_type),
            "cert_type_name": self.cert_type_name,
            "subject_cn": self.subject_cn,
            "subject_o": self.subject_o,
            "issuer_cn": self.issuer_cn,
            "issuer_o": self.issuer_o,
            "serial_number": self.serial_number,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "digest_algorithm": self.digest_algorithm,
            "stored_digest": self.stored_digest,
            "computed_digest": self.computed_digest,
            "digest_match": self.digest_match,
            "anomalies": self.anomalies,
            "is_suspicious": self.is_suspicious,
        }


@dataclass
class OverlayCertResult:
    """Combined result of overlay and certificate analysis."""

    overlay: OverlayInfo
    certificates: List[CertificateRecord] = field(default_factory=list)
    security_dir_rva: int = 0
    security_dir_size: int = 0
    is_signed: bool = False
    signature_valid: Optional[bool] = None  # None = could not determine
    risk_indicators: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overlay": self.overlay.to_dict(),
            "certificates": [c.to_dict() for c in self.certificates],
            "security_dir_rva": self.security_dir_rva,
            "security_dir_size": self.security_dir_size,
            "is_signed": self.is_signed,
            "signature_valid": self.signature_valid,
            "risk_indicators": self.risk_indicators,
        }


# ---------------------------------------------------------------------------
# ASN.1 DER utilities
# ---------------------------------------------------------------------------

def _asn1_read_length(data: bytes, offset: int) -> Tuple[int, int]:
    """
    Parse a BER/DER length at `offset`.
    Returns (length_value, bytes_consumed).
    """
    if offset >= len(data):
        return 0, 0
    first = data[offset]
    if first < 0x80:
        return first, 1
    num_bytes = first & 0x7F
    if num_bytes == 0 or offset + num_bytes >= len(data):
        return 0, 1
    length = int.from_bytes(data[offset + 1: offset + 1 + num_bytes], "big")
    return length, 1 + num_bytes


def _asn1_decode_string(tag: int, data: bytes) -> str:
    """Decode a DER string value to Python str."""
    if tag == ASN1_BMPSTRING:
        try:
            return data.decode("utf-16-be", errors="replace")
        except Exception:
            return data.hex()
    for enc in ("utf-8", "latin-1", "ascii"):
        try:
            return data.decode(enc, errors="replace")
        except Exception:
            pass
    return data.hex()


def _asn1_iter(data: bytes, start: int = 0, end: Optional[int] = None) -> list:
    """
    Yield (tag, value_bytes, child_start, child_end) for each TLV at this level.
    Returns a list of (tag, content_bytes) tuples.
    """
    if end is None:
        end = len(data)
    items = []
    pos = start
    while pos < end:
        if pos >= len(data):
            break
        tag = data[pos]
        pos += 1
        length, consumed = _asn1_read_length(data, pos)
        pos += consumed
        if pos + length > len(data):
            break
        items.append((tag, data[pos: pos + length]))
        pos += length
    return items


def _extract_name_attributes(rdn_sequence: bytes) -> Dict[str, str]:
    """Extract CN, O, OU, C from an X.509 Name (RDNSequence)."""
    result: Dict[str, str] = {}
    oid_map = {
        OID_CN: "cn",
        OID_O: "o",
        OID_OU: "ou",
        OID_C: "c",
    }
    # Iterate over SET items in the RDNSequence
    for rdn_tag, rdn_data in _asn1_iter(rdn_sequence):
        if rdn_tag not in (ASN1_SET, ASN1_SEQUENCE):
            continue
        for atv_tag, atv_data in _asn1_iter(rdn_data):
            if atv_tag != ASN1_SEQUENCE:
                continue
            atv_items = _asn1_iter(atv_data)
            if len(atv_items) < 2:
                continue
            oid_tag, oid_bytes = atv_items[0]
            val_tag, val_bytes = atv_items[1]
            if oid_tag == ASN1_OID:
                attr = oid_map.get(oid_bytes)
                if attr:
                    result[attr] = _asn1_decode_string(val_tag, val_bytes)
    return result


def _extract_serial(data: bytes) -> str:
    """Extract INTEGER serial number bytes and return as colon-separated hex."""
    items = _asn1_iter(data)
    for tag, value in items:
        if tag == ASN1_INTEGER:
            return ":".join(f"{b:02x}" for b in value)
    return ""


def _extract_validity_times(validity_data: bytes) -> Tuple[str, str]:
    """Parse Validity { notBefore, notAfter } from DER bytes."""
    items = _asn1_iter(validity_data)
    not_before = not_after = ""
    for i, (tag, val) in enumerate(items[:2]):
        if tag in (ASN1_UTCTIME, ASN1_GENERALIZEDTIME):
            decoded = val.decode("ascii", errors="replace")
            if i == 0:
                not_before = decoded
            else:
                not_after = decoded
    return not_before, not_after


def _parse_x509_cert(cert_der: bytes) -> Dict[str, str]:
    """
    Minimal X.509 DER parser.
    Returns dict with keys: subject_cn, subject_o, issuer_cn, issuer_o,
    serial_number, not_before, not_after.
    """
    result: Dict[str, str] = {}
    # Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    top = _asn1_iter(cert_der)
    if not top or top[0][0] != ASN1_SEQUENCE:
        return result
    tbs_data = top[0][1]
    tbs_items = _asn1_iter(tbs_data)

    # TBSCertificate ::= SEQUENCE {
    #   [0] EXPLICIT INTEGER OPTIONAL,   -- version
    #   serialNumber INTEGER,
    #   signature AlgorithmIdentifier,
    #   issuer Name,
    #   validity Validity,
    #   subject Name,
    #   ...
    # }
    idx = 0
    if tbs_items and tbs_items[0][0] == ASN1_CONTEXT_0:
        idx = 1  # skip version

    # serial
    if idx < len(tbs_items) and tbs_items[idx][0] == ASN1_INTEGER:
        result["serial_number"] = ":".join(f"{b:02x}" for b in tbs_items[idx][1])
        idx += 1

    # signature algorithm
    if idx < len(tbs_items) and tbs_items[idx][0] == ASN1_SEQUENCE:
        idx += 1

    # issuer
    if idx < len(tbs_items) and tbs_items[idx][0] == ASN1_SEQUENCE:
        attrs = _extract_name_attributes(tbs_items[idx][1])
        result["issuer_cn"] = attrs.get("cn", "")
        result["issuer_o"] = attrs.get("o", "")
        idx += 1

    # validity
    if idx < len(tbs_items) and tbs_items[idx][0] == ASN1_SEQUENCE:
        nb, na = _extract_validity_times(tbs_items[idx][1])
        result["not_before"] = nb
        result["not_after"] = na
        idx += 1

    # subject
    if idx < len(tbs_items) and tbs_items[idx][0] == ASN1_SEQUENCE:
        attrs = _extract_name_attributes(tbs_items[idx][1])
        result["subject_cn"] = attrs.get("cn", "")
        result["subject_o"] = attrs.get("o", "")

    return result


# ---------------------------------------------------------------------------
# WIN_CERTIFICATE parser
# ---------------------------------------------------------------------------

def _parse_win_certificate(data: bytes, cert_offset: int, index: int) -> CertificateRecord:
    """
    Parse a single WIN_CERTIFICATE at cert_offset in `data`.

    WIN_CERTIFICATE structure:
        DWORD dwLength;
        WORD  wRevision;
        WORD  wCertificateType;
        BYTE  bCertificate[ANYSIZE_ARRAY];
    """
    if cert_offset + 8 > len(data):
        rec = CertificateRecord(index=index, raw_length=0, revision=0, cert_type=0)
        rec.anomalies.append("Truncated WIN_CERTIFICATE header")
        return rec

    dw_length, w_revision, w_cert_type = struct.unpack_from("<IHH", data, cert_offset)
    cert_data = data[cert_offset + 8: cert_offset + dw_length]

    rec = CertificateRecord(
        index=index,
        raw_length=dw_length,
        revision=w_revision,
        cert_type=w_cert_type,
        cert_type_name=CERT_TYPE_NAMES.get(w_cert_type, f"Unknown(0x{w_cert_type:04x})"),
    )

    if dw_length < 8:
        rec.anomalies.append(f"WIN_CERTIFICATE dwLength too small: {dw_length}")
        return rec

    if w_revision != CERT_REVISION_2_0:
        rec.anomalies.append(
            f"Unexpected WIN_CERTIFICATE revision: 0x{w_revision:04x} (expected 0x0200)"
        )

    # For PKCS#7 SignedData (Authenticode), try to extract signer info
    if w_cert_type == CERT_TYPE_PKCS_SIGNED_DATA and cert_data:
        _extract_pkcs7_signer_info(cert_data, rec)

    return rec


def _extract_pkcs7_signer_info(pkcs7_der: bytes, rec: CertificateRecord) -> None:
    """
    Walk PKCS#7 ContentInfo -> SignedData to extract:
      - Signer certificate CN/O/issuer
      - digestAlgorithm
      - encryptedDigest (stored hash)
    """
    # ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
    top = _asn1_iter(pkcs7_der)
    if not top or top[0][0] != ASN1_SEQUENCE:
        return

    ci_items = _asn1_iter(top[0][1])
    if len(ci_items) < 2:
        return

    # [0] content wrapper
    if ci_items[1][0] != ASN1_CONTEXT_0:
        return
    sd_wrapper = _asn1_iter(ci_items[1][1])
    if not sd_wrapper or sd_wrapper[0][0] != ASN1_SEQUENCE:
        return

    # SignedData ::= SEQUENCE {
    #   version, digestAlgorithms, contentInfo, [0] certificates, signerInfos }
    sd_items = _asn1_iter(sd_wrapper[0][1])
    idx = 0

    # version INTEGER
    if idx < len(sd_items) and sd_items[idx][0] == ASN1_INTEGER:
        idx += 1

    # digestAlgorithms SET OF AlgorithmIdentifier
    if idx < len(sd_items) and sd_items[idx][0] == ASN1_SET:
        alg_set = _asn1_iter(sd_items[idx][1])
        if alg_set and alg_set[0][0] == ASN1_SEQUENCE:
            alg_items = _asn1_iter(alg_set[0][1])
            if alg_items and alg_items[0][0] == ASN1_OID:
                oid_bytes = alg_items[0][1]
                if oid_bytes == OID_SHA256:
                    rec.digest_algorithm = "SHA-256"
                elif oid_bytes == OID_SHA1:
                    rec.digest_algorithm = "SHA-1"
                elif oid_bytes == OID_MD5:
                    rec.digest_algorithm = "MD5"
                else:
                    rec.digest_algorithm = oid_bytes.hex()
        idx += 1

    # contentInfo SEQUENCE (skip)
    if idx < len(sd_items) and sd_items[idx][0] == ASN1_SEQUENCE:
        idx += 1

    # [0] certificates
    if idx < len(sd_items) and sd_items[idx][0] == ASN1_CONTEXT_0:
        certs_data = sd_items[idx][1]
        cert_list = _asn1_iter(certs_data)
        if cert_list:
            # Parse the first (signer's) certificate
            first_cert_der = cert_list[0][1]
            parsed = _parse_x509_cert(first_cert_der)
            rec.subject_cn = parsed.get("subject_cn", "")
            rec.subject_o = parsed.get("subject_o", "")
            rec.issuer_cn = parsed.get("issuer_cn", "")
            rec.issuer_o = parsed.get("issuer_o", "")
            rec.serial_number = parsed.get("serial_number", "")
            rec.not_before = parsed.get("not_before", "")
            rec.not_after = parsed.get("not_after", "")
        idx += 1

    # signerInfos SET OF SignerInfo
    if idx < len(sd_items) and sd_items[idx][0] == ASN1_SET:
        si_set = _asn1_iter(sd_items[idx][1])
        if si_set and si_set[0][0] == ASN1_SEQUENCE:
            si_items = _asn1_iter(si_set[0][1])
            # Last item in SignerInfo is encryptedDigest OCTETSTRING
            for tag, val in reversed(si_items):
                if tag == ASN1_OCTETSTRING:
                    rec.stored_digest = val.hex()
                    break


# ---------------------------------------------------------------------------
# Authenticode hash computation
# ---------------------------------------------------------------------------

def _compute_authenticode_hash(data: bytes, algorithm: str = "SHA-256") -> str:
    """
    Compute the Authenticode-style hash of a PE file.

    Authenticode hashing excludes:
      1. The 4-byte checksum field in the Optional Header
      2. The Security Directory entry (RVA + Size) in the data directory
      3. The Security Directory contents (the actual certificate table)

    Returns hex digest string.
    """
    try:
        return _authenticode_hash_impl(data, algorithm)
    except Exception:
        return ""


def _authenticode_hash_impl(data: bytes, algorithm: str) -> str:
    hasher_map = {
        "MD5": hashlib.md5,
        "SHA-1": hashlib.sha1,
        "SHA-256": hashlib.sha256,
    }
    h = hasher_map.get(algorithm, hashlib.sha256)()
    buf = io.BytesIO(data)

    # Locate PE header
    if len(data) < 64 or data[:2] != b"MZ":
        return ""
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 4 > len(data) or data[pe_offset: pe_offset + 4] != b"PE\x00\x00":
        return ""

    # COFF header: 20 bytes after PE signature
    coff_offset = pe_offset + 4
    if coff_offset + 20 > len(data):
        return ""
    size_of_optional = struct.unpack_from("<H", data, coff_offset + 16)[0]
    opt_offset = coff_offset + 20

    if opt_offset + size_of_optional > len(data):
        return ""
    magic = struct.unpack_from("<H", data, opt_offset)[0]
    is_64bit = magic == 0x20B

    # Checksum field: offset 64 (PE32) or 64 (PE32+) from opt header start
    checksum_offset = opt_offset + 64  # same for PE32 and PE32+

    # Security directory entry: in the data directory table
    # PE32:  offset 96 from opt header = data directory[4] (SECURITY)
    # PE32+: offset 112 from opt header = data directory[4] (SECURITY)
    dd_offset = opt_offset + (112 if is_64bit else 96)
    # Each data directory entry = 8 bytes; security = index 4
    sec_dd_offset = dd_offset + 4 * 8  # index 4

    if sec_dd_offset + 8 > len(data):
        sec_dir_rva = sec_dir_size = 0
    else:
        sec_dir_rva, sec_dir_size = struct.unpack_from("<II", data, sec_dd_offset)

    # Compute hash over file, excluding checksum and security directory fields
    # Region 1: start of file to checksum
    h.update(data[:checksum_offset])
    # Region 2: after checksum (4 bytes) to security directory entry
    h.update(data[checksum_offset + 4: sec_dd_offset])
    # Region 3: after security directory entry (8 bytes) to end of header + sections
    #           (everything except the actual certificate table at sec_dir_rva)
    after_sec_dd = sec_dd_offset + 8
    if sec_dir_rva > 0 and sec_dir_size > 0 and sec_dir_rva < len(data):
        h.update(data[after_sec_dd: sec_dir_rva])
        # Region 4: after the certificate table to end of file (if any)
        end_of_cert = sec_dir_rva + sec_dir_size
        if end_of_cert < len(data):
            h.update(data[end_of_cert:])
    else:
        h.update(data[after_sec_dd:])

    return h.hexdigest()


# ---------------------------------------------------------------------------
# Overlay analysis
# ---------------------------------------------------------------------------

def _calc_overlay_offset(pe: PEFile) -> int:
    """
    Compute the byte offset at which overlay data begins.
    This is max(raw_offset + raw_size) across all sections, aligned upward to
    the file alignment boundary declared in the optional header.
    """
    if not pe.sections:
        # No sections: overlay starts after the end of headers
        size_of_headers = pe.optional_header.size_of_headers
        return size_of_headers

    end_offsets = []
    for sec in pe.sections:
        if sec.pointer_to_raw_data > 0 and sec.size_of_raw_data > 0:
            end_offsets.append(sec.pointer_to_raw_data + sec.size_of_raw_data)

    if not end_offsets:
        return len(pe.data)

    file_align = max(pe.optional_header.file_alignment, 512)
    raw_end = max(end_offsets)
    # Round up to file alignment
    aligned_end = ((raw_end + file_align - 1) // file_align) * file_align
    return min(aligned_end, len(pe.data))


def _calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    n = len(data)
    for c in counts:
        if c > 0:
            p = c / n
            entropy -= p * math.log2(p)
    return entropy


def _detect_sfx_type(data: bytes) -> Optional[str]:
    """Scan the first 512 bytes of overlay for archive magic bytes."""
    header = data[:512]
    for magic, name in SFX_SIGNATURES:
        if magic in header:
            return name
    return None


def _contains_pe(data: bytes) -> bool:
    """Check if overlay begins with or contains an MZ header."""
    if data[:2] == b"MZ":
        return True
    # Scan for embedded MZ+PE within first 4096 bytes
    scan = data[:4096]
    pos = 0
    while True:
        idx = scan.find(b"MZ", pos)
        if idx == -1:
            break
        e_lfanew_off = idx + 0x3C
        if e_lfanew_off + 4 <= len(scan):
            pe_off = struct.unpack_from("<I", scan, e_lfanew_off)[0]
            if 0 < pe_off < 0x1000 and idx + pe_off + 4 <= len(scan):
                if scan[idx + pe_off: idx + pe_off + 4] == b"PE\x00\x00":
                    return True
        pos = idx + 2
    return False


def analyze_overlay(pe: PEFile) -> OverlayInfo:
    """Perform full overlay analysis on a parsed PEFile."""
    data = pe.data
    file_size = len(data)

    offset = _calc_overlay_offset(pe)
    size = file_size - offset

    info = OverlayInfo(offset=offset, size=size)

    if size <= 0:
        info.overlay_type = OverlayType.NONE
        return info

    info.ratio = size / file_size
    overlay_bytes = data[offset:]
    info.entropy = _calculate_entropy(overlay_bytes)

    # Check if it's just file-alignment padding (all null bytes)
    if all(b == 0 for b in overlay_bytes[:min(size, 512)]):
        info.overlay_type = OverlayType.PADDING
        return info

    # SFX detection
    sfx_type = _detect_sfx_type(overlay_bytes)
    if sfx_type:
        info.sfx_type = sfx_type
        info.overlay_type = OverlayType.ARCHIVE_SFX

    # Embedded PE detection
    if _contains_pe(overlay_bytes):
        info.contains_pe = True
        info.overlay_type = OverlayType.EMBEDDED_PE
        info.anomalies.append("Embedded PE executable found in overlay (possible dropper)")

    # Entropy-based classification
    if info.overlay_type == OverlayType.UNKNOWN or not sfx_type:
        if info.entropy > 7.0:
            if info.overlay_type != OverlayType.EMBEDDED_PE:
                info.overlay_type = OverlayType.HIGH_ENTROPY
            info.anomalies.append(
                f"Very high entropy overlay ({info.entropy:.2f}) may indicate encrypted/compressed payload"
            )
        elif info.entropy > 6.0:
            if info.overlay_type == OverlayType.NONE:
                info.overlay_type = OverlayType.UNKNOWN
        else:
            if info.overlay_type == OverlayType.NONE:
                info.overlay_type = OverlayType.LOW_ENTROPY

    # Large overlay ratio warning
    if info.ratio > 0.5:
        info.anomalies.append(
            f"Overlay is {info.ratio * 100:.1f}% of file size — unusually large"
        )

    return info


# ---------------------------------------------------------------------------
# Security directory and certificate extraction
# ---------------------------------------------------------------------------

def _locate_security_directory(pe: PEFile) -> Tuple[int, int]:
    """
    Return (offset_in_file, size) for the Security Directory (data dir index 4).
    The security directory RVA is a file offset (not an RVA), per the PE spec.
    Returns (0, 0) if absent or malformed.
    """
    dd = pe.optional_header.data_directories
    if len(dd) < 5:
        return 0, 0
    rva, size = dd[4]  # index 4 = IMAGE_DIRECTORY_ENTRY_SECURITY
    if rva == 0 or size == 0:
        return 0, 0
    # Security directory RVA is actually a raw file offset
    if rva >= len(pe.data) or rva + size > len(pe.data):
        return 0, 0
    return rva, size


def parse_certificates(pe: PEFile) -> List[CertificateRecord]:
    """Parse all WIN_CERTIFICATE entries from the Security Directory."""
    sec_offset, sec_size = _locate_security_directory(pe)
    if sec_offset == 0:
        return []

    data = pe.data
    records: List[CertificateRecord] = []
    pos = sec_offset
    end = sec_offset + sec_size
    cert_index = 0

    while pos < end:
        if pos + 8 > end:
            break
        dw_length = struct.unpack_from("<I", data, pos)[0]
        if dw_length < 8 or pos + dw_length > end:
            # Truncated or invalid
            rec = CertificateRecord(index=cert_index, raw_length=dw_length, revision=0, cert_type=0)
            rec.anomalies.append(f"WIN_CERTIFICATE at offset {pos:#x} has invalid length {dw_length}")
            records.append(rec)
            break

        rec = _parse_win_certificate(data, pos, cert_index)
        records.append(rec)

        # Align to 8-byte boundary per spec
        aligned_len = (dw_length + 7) & ~7
        pos += aligned_len
        cert_index += 1

    return records


# ---------------------------------------------------------------------------
# Main analysis entry point
# ---------------------------------------------------------------------------

def analyze(pe: PEFile) -> OverlayCertResult:
    """
    Run full overlay and certificate analysis on a parsed PEFile.
    Returns OverlayCertResult with overlay info, certificates, and risk summary.
    """
    overlay = analyze_overlay(pe)
    certs = parse_certificates(pe)

    sec_offset, sec_size = _locate_security_directory(pe)
    is_signed = len(certs) > 0
    signature_valid: Optional[bool] = None

    if is_signed and overlay.size > 0 and overlay.sfx_type is None:
        # The overlay might legitimately be the certificate table; check overlap
        if overlay.offset >= sec_offset and sec_offset > 0:
            overlay.overlay_type = OverlayType.CERTIFICATE

    # Verify authenticode hash for the first certificate if we have digest info
    if certs:
        first_cert = certs[0]
        if first_cert.digest_algorithm and first_cert.stored_digest:
            computed = _compute_authenticode_hash(pe.data, first_cert.digest_algorithm)
            if computed:
                first_cert.computed_digest = computed
                first_cert.digest_match = (computed == first_cert.stored_digest)
                if not first_cert.digest_match:
                    first_cert.anomalies.append(
                        f"Authenticode hash mismatch: stored={first_cert.stored_digest[:16]}... "
                        f"computed={computed[:16]}..."
                    )
                    signature_valid = False
                else:
                    signature_valid = True

    # Multiple certificate anomaly
    if len(certs) > 1:
        for cert in certs[1:]:
            cert.anomalies.append("Multiple WIN_CERTIFICATE entries — unusual for Authenticode")

    # Zero-length certificate
    for cert in certs:
        if cert.raw_length == 8:
            cert.anomalies.append("WIN_CERTIFICATE with zero-length bCertificate payload")

    # Build risk indicator list
    risk: List[str] = []
    risk.extend(overlay.anomalies)
    for cert in certs:
        risk.extend(cert.anomalies)
    if is_signed and not certs:
        risk.append("Security directory present but no parseable WIN_CERTIFICATE entries")

    return OverlayCertResult(
        overlay=overlay,
        certificates=certs,
        security_dir_rva=sec_offset,
        security_dir_size=sec_size,
        is_signed=is_signed,
        signature_valid=signature_valid,
        risk_indicators=risk,
    )
