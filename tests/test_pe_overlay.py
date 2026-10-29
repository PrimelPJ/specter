"""
Tests for PE overlay and Authenticode certificate analysis.
"""

from __future__ import annotations

import hashlib
import io
import struct
from dataclasses import dataclass
from typing import List, Optional
from unittest.mock import MagicMock, patch

import pytest

from specter.pe_overlay import (
    CERT_REVISION_2_0,
    CERT_TYPE_PKCS_SIGNED_DATA,
    CERT_TYPE_X509,
    OverlayCertResult,
    OverlayInfo,
    OverlayType,
    _asn1_read_length,
    _calculate_entropy,
    _compute_authenticode_hash,
    _contains_pe,
    _detect_sfx_type,
    analyze,
    analyze_overlay,
    parse_certificates,
)
from specter.pe_parser import PEFile, PEParser


# ---------------------------------------------------------------------------
# Minimal PE builder for testing
# ---------------------------------------------------------------------------

class MinimalPEBuilder:
    """Builds syntactically valid minimal PE files for testing."""

    DOS_STUB_SIZE = 0x40  # 64-byte DOS header

    def __init__(self, machine: int = 0x014C, is_64bit: bool = False) -> None:
        self.machine = machine
        self.is_64bit = is_64bit
        self.sections: List[dict] = []
        self.overlay: bytes = b""
        self.certificate_table: bytes = b""

    def add_section(self, name: str, data: bytes, characteristics: int = 0x60000020) -> "MinimalPEBuilder":
        self.sections.append({"name": name, "data": data, "characteristics": characteristics})
        return self

    def set_overlay(self, data: bytes) -> "MinimalPEBuilder":
        self.overlay = data
        return self

    def set_certificate_table(self, cert_bytes: bytes) -> "MinimalPEBuilder":
        self.certificate_table = cert_bytes
        return self

    def build(self) -> bytes:
        file_align = 0x200
        sect_align = 0x1000

        # --- DOS header (64 bytes) ---
        pe_offset = self.DOS_STUB_SIZE
        dos = bytearray(self.DOS_STUB_SIZE)
        dos[0:2] = b"MZ"
        struct.pack_into("<I", dos, 0x3C, pe_offset)

        # --- COFF header ---
        n_sections = len(self.sections)
        # optional header size: PE32=0xE0, PE32+=0xF0
        opt_size = 0xF0 if self.is_64bit else 0xE0
        coff = struct.pack(
            "<HHIIIHH",
            self.machine,    # Machine
            n_sections,      # NumberOfSections
            0,               # TimeDateStamp
            0,               # PointerToSymbolTable
            0,               # NumberOfSymbols
            opt_size,        # SizeOfOptionalHeader
            0x0002,          # Characteristics (executable)
        )

        # --- Optional header ---
        # Compute section layout
        headers_size = pe_offset + 4 + 20 + opt_size + n_sections * 40
        headers_size = ((headers_size + file_align - 1) // file_align) * file_align

        # Lay out sections
        raw_offset = headers_size
        section_layouts = []
        current_rva = sect_align
        for sec in self.sections:
            raw_size = ((len(sec["data"]) + file_align - 1) // file_align) * file_align
            section_layouts.append({
                "name": sec["name"],
                "data": sec["data"],
                "vsize": len(sec["data"]),
                "vaddr": current_rva,
                "raw_size": raw_size,
                "raw_offset": raw_offset,
                "characteristics": sec["characteristics"],
            })
            raw_offset += raw_size
            current_rva = ((current_rva + len(sec["data"]) + sect_align - 1) // sect_align) * sect_align

        image_size = current_rva

        # Certificate table placement
        cert_rva = 0
        cert_size = 0
        if self.certificate_table:
            cert_rva = raw_offset  # file offset (Security Directory uses file offsets)
            cert_size = len(self.certificate_table)

        if not self.is_64bit:
            # PE32 optional header
            n_dd = 16
            dd_bytes = bytearray(n_dd * 8)
            if cert_rva:
                struct.pack_into("<II", dd_bytes, 4 * 8, cert_rva, cert_size)

            opt = struct.pack(
                "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
                0x010B,          # Magic PE32
                14, 0,           # MajorLinkerVersion, MinorLinkerVersion
                0,               # SizeOfCode
                0,               # SizeOfInitializedData
                0,               # SizeOfUninitializedData
                sect_align,      # AddressOfEntryPoint
                0,               # BaseOfCode
                0,               # BaseOfData (PE32 only)
                0x400000,        # ImageBase
                sect_align,      # SectionAlignment
                file_align,      # FileAlignment
                6, 0,            # MajorOSVersion, MinorOSVersion
                0, 0,            # MajorImageVersion, MinorImageVersion
                6, 0,            # MajorSubsystemVersion, MinorSubsystemVersion
                0,               # Win32VersionValue
                image_size,      # SizeOfImage
                headers_size,    # SizeOfHeaders
                0,               # CheckSum  ← will be 0 for tests
                2,               # Subsystem WINDOWS_GUI
                0,               # DllCharacteristics
                0x100000, 0x1000,  # SizeOfStackReserve, SizeOfStackCommit
                0x100000, 0x1000,  # SizeOfHeapReserve, SizeOfHeapCommit
                0,               # LoaderFlags
                n_dd,            # NumberOfRvaAndSizes
            )
        else:
            # PE32+ optional header
            n_dd = 16
            dd_bytes = bytearray(n_dd * 8)
            if cert_rva:
                struct.pack_into("<II", dd_bytes, 4 * 8, cert_rva, cert_size)

            opt = struct.pack(
                "<HBBIIIIIIqIIHHHHHHIIIIhhQQQQ",
                0x020B,          # Magic PE32+
                14, 0,           # Linker version
                0,               # SizeOfCode
                0,               # SizeOfInitializedData
                0,               # SizeOfUninitializedData
                sect_align,      # AddressOfEntryPoint
                0,               # BaseOfCode
                0x400000,        # ImageBase (8 bytes)
                sect_align,      # SectionAlignment
                file_align,      # FileAlignment
                6, 0,            # MajorOSVersion, MinorOSVersion
                0, 0,            # MajorImageVersion, MinorImageVersion
                6, 0,            # MajorSubsystemVersion, MinorSubsystemVersion
                0,               # Win32VersionValue
                image_size,      # SizeOfImage
                headers_size,    # SizeOfHeaders
                0,               # CheckSum
                2,               # Subsystem
                0,               # DllCharacteristics
                0x100000,        # SizeOfStackReserve
                0x1000,          # SizeOfStackCommit
                0x100000,        # SizeOfHeapReserve
                0x1000,          # SizeOfHeapCommit
                0,               # LoaderFlags
                n_dd,            # NumberOfRvaAndSizes
            )
        # Pad opt to the declared size
        opt_padded = opt + bytes(dd_bytes) + bytes(max(0, opt_size - len(opt) - len(dd_bytes)))

        # --- Section headers ---
        sec_headers = bytearray()
        for sl in section_layouts:
            name_bytes = sl["name"].encode("ascii")[:8].ljust(8, b"\x00")
            sec_headers += struct.pack(
                "<8sIIIIIIHHI",
                name_bytes,
                sl["vsize"],
                sl["vaddr"],
                sl["raw_size"],
                sl["raw_offset"],
                0, 0, 0, 0,
                sl["characteristics"],
            )

        # --- Assemble file ---
        header_blob = (
            bytes(dos)
            + b"PE\x00\x00"
            + coff
            + opt_padded[:opt_size]
            + bytes(sec_headers)
        )
        # Pad headers to headers_size
        header_blob = header_blob.ljust(headers_size, b"\x00")

        section_blob = bytearray()
        for sl in section_layouts:
            padded = sl["data"].ljust(sl["raw_size"], b"\x00")
            section_blob += padded

        cert_blob = self.certificate_table

        return header_blob + bytes(section_blob) + cert_blob + self.overlay


def build_simple_pe(overlay: bytes = b"", cert_table: bytes = b"") -> bytes:
    return (
        MinimalPEBuilder()
        .add_section(".text", b"\x90" * 256)
        .add_section(".data", b"\x00" * 128)
        .set_overlay(overlay)
        .set_certificate_table(cert_table)
        .build()
    )


def parse_pe(data: bytes) -> PEFile:
    return PEParser().parse(data)


# ---------------------------------------------------------------------------
# ASN.1 helpers
# ---------------------------------------------------------------------------

class TestAsn1ReadLength:
    def test_short_form(self):
        length, consumed = _asn1_read_length(b"\x10", 0)
        assert length == 16
        assert consumed == 1

    def test_long_form_1_byte(self):
        data = bytes([0x81, 0x80])
        length, consumed = _asn1_read_length(data, 0)
        assert length == 128
        assert consumed == 2

    def test_long_form_2_bytes(self):
        data = bytes([0x82, 0x01, 0x00])
        length, consumed = _asn1_read_length(data, 0)
        assert length == 256
        assert consumed == 3

    def test_zero_length(self):
        length, consumed = _asn1_read_length(b"\x00", 0)
        assert length == 0
        assert consumed == 1

    def test_empty_data(self):
        length, consumed = _asn1_read_length(b"", 0)
        assert length == 0
        assert consumed == 0


# ---------------------------------------------------------------------------
# Entropy helper
# ---------------------------------------------------------------------------

class TestCalculateEntropy:
    def test_zero_entropy(self):
        assert _calculate_entropy(b"\x00" * 1000) == 0.0

    def test_max_entropy(self):
        data = bytes(range(256)) * 4
        assert abs(_calculate_entropy(data) - 8.0) < 0.01

    def test_empty_data(self):
        assert _calculate_entropy(b"") == 0.0

    def test_high_entropy_random_like(self):
        data = bytes(i % 256 for i in range(10000))
        assert _calculate_entropy(data) > 6.0

    def test_text_low_entropy(self):
        data = b"hello world " * 500
        assert _calculate_entropy(data) < 4.0


# ---------------------------------------------------------------------------
# SFX detection
# ---------------------------------------------------------------------------

class TestDetectSfxType:
    def test_zip_magic(self):
        assert _detect_sfx_type(b"PK\x03\x04" + b"\x00" * 100) == "ZIP"

    def test_rar4_magic(self):
        assert _detect_sfx_type(b"Rar!\x1a\x07\x00" + b"\x00" * 100) == "RAR4"

    def test_7zip_magic(self):
        assert _detect_sfx_type(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 100) == "7-Zip"

    def test_cab_magic(self):
        assert _detect_sfx_type(b"MSCF" + b"\x00" * 100) == "CAB"

    def test_nsis_magic(self):
        data = b"\x00" * 10 + b"\xef\xbe\xad\xde" + b"\x00" * 100
        assert _detect_sfx_type(data) == "NSIS"

    def test_no_match(self):
        assert _detect_sfx_type(b"\xde\xad\xbe\xef" * 100) is None

    def test_empty(self):
        assert _detect_sfx_type(b"") is None

    def test_magic_within_first_512(self):
        data = b"\x00" * 400 + b"PK\x03\x04"
        assert _detect_sfx_type(data) == "ZIP"


# ---------------------------------------------------------------------------
# Embedded PE detection
# ---------------------------------------------------------------------------

class TestContainsPe:
    def test_overlay_starting_with_mz(self):
        mz_pe = b"MZ" + b"\x00" * 60 + b"\x40\x00\x00\x00" + b"\x00" * 0
        assert _contains_pe(b"MZ" + b"\x00" * 100) is True

    def test_no_pe_marker(self):
        assert _contains_pe(b"\x00" * 1000) is False

    def test_high_entropy_no_mz(self):
        data = bytes(i % 256 for i in range(2000))
        # No MZ marker at start
        assert not _contains_pe(data)

    def test_empty(self):
        assert _contains_pe(b"") is False


# ---------------------------------------------------------------------------
# Overlay analysis
# ---------------------------------------------------------------------------

class TestAnalyzeOverlay:
    def test_no_overlay(self):
        pe_data = build_simple_pe(overlay=b"")
        pe = parse_pe(pe_data)
        result = analyze_overlay(pe)
        assert result.overlay_type in (OverlayType.NONE, OverlayType.PADDING)

    def test_zip_sfx_detected(self):
        overlay = b"PK\x03\x04" + b"\x00" * 200
        pe_data = build_simple_pe(overlay=overlay)
        pe = parse_pe(pe_data)
        result = analyze_overlay(pe)
        assert result.sfx_type == "ZIP"
        assert result.overlay_type == OverlayType.ARCHIVE_SFX

    def test_7zip_sfx_detected(self):
        overlay = b"7z\xbc\xaf\x27\x1c" + b"\x00" * 200
        pe_data = build_simple_pe(overlay=overlay)
        pe = parse_pe(pe_data)
        result = analyze_overlay(pe)
        assert result.sfx_type == "7-Zip"

    def test_null_padding_not_flagged(self):
        overlay = b"\x00" * 512
        pe_data = build_simple_pe(overlay=overlay)
        pe = parse_pe(pe_data)
        result = analyze_overlay(pe)
        assert result.overlay_type == OverlayType.PADDING

    def test_high_entropy_overlay_flagged(self):
        # High entropy: 256-byte cycle repeated
        overlay = bytes(range(256)) * 40
        pe_data = build_simple_pe(overlay=overlay)
        pe = parse_pe(pe_data)
        result = analyze_overlay(pe)
        assert result.entropy > 7.5
        assert any("entropy" in a.lower() for a in result.anomalies)

    def test_large_ratio_anomaly(self):
        # Overlay larger than 50% of the file size
        pe_data_small = build_simple_pe()
        big_overlay = b"\x41" * (len(pe_data_small) * 2)
        pe_data = build_simple_pe(overlay=big_overlay)
        pe = parse_pe(pe_data)
        result = analyze_overlay(pe)
        assert result.ratio > 0.5
        assert any("%" in a for a in result.anomalies)

    def test_overlay_size_is_accurate(self):
        overlay = b"\xAA" * 512
        pe_data = build_simple_pe(overlay=overlay)
        pe = parse_pe(pe_data)
        result = analyze_overlay(pe)
        # Size should be at least 512 (may include alignment padding)
        assert result.size >= 512

    def test_overlay_offset_positive(self):
        overlay = b"PK\x03\x04" + b"\x00" * 100
        pe_data = build_simple_pe(overlay=overlay)
        pe = parse_pe(pe_data)
        result = analyze_overlay(pe)
        assert result.offset > 0

    def test_overlay_ratio_between_0_and_1(self):
        overlay = b"\xBB" * 100
        pe_data = build_simple_pe(overlay=overlay)
        pe = parse_pe(pe_data)
        result = analyze_overlay(pe)
        if result.size > 0:
            assert 0.0 < result.ratio <= 1.0

    def test_overlay_to_dict(self):
        overlay = b"PK\x03\x04" + b"\x00" * 50
        pe_data = build_simple_pe(overlay=overlay)
        pe = parse_pe(pe_data)
        result = analyze_overlay(pe)
        d = result.to_dict()
        assert "offset" in d
        assert "entropy" in d
        assert "overlay_type" in d
        assert "is_suspicious" in d


# ---------------------------------------------------------------------------
# parse_certificates with mock PEFile
# ---------------------------------------------------------------------------

def make_mock_pe(data: bytes, sec_dd: tuple = (0, 0)) -> MagicMock:
    """Build a MagicMock PEFile with controlled security directory."""
    pe = MagicMock()
    pe.data = data
    dd = [(0, 0)] * 16
    dd[4] = sec_dd
    pe.optional_header.data_directories = dd
    pe.optional_header.size_of_headers = 0x200
    pe.optional_header.file_alignment = 0x200
    pe.sections = []
    return pe


def build_win_certificate(cert_bytes: bytes, cert_type: int = CERT_TYPE_PKCS_SIGNED_DATA, revision: int = CERT_REVISION_2_0) -> bytes:
    """Pack a WIN_CERTIFICATE structure."""
    total_len = 8 + len(cert_bytes)
    return struct.pack("<IHH", total_len, revision, cert_type) + cert_bytes


class TestParseCertificates:
    def test_no_security_directory_returns_empty(self):
        pe = make_mock_pe(b"\x00" * 1024, sec_dd=(0, 0))
        assert parse_certificates(pe) == []

    def test_truncated_security_directory(self):
        data = bytearray(1024)
        offset = 0x200
        struct.pack_into("<I", data, offset, 4)  # Length too small (< 8)
        pe = make_mock_pe(bytes(data), sec_dd=(offset, 8))
        certs = parse_certificates(pe)
        assert len(certs) == 1
        assert certs[0].anomalies

    def test_valid_certificate_parsed(self):
        cert_data = b"\x00" * 64  # dummy cert
        win_cert = build_win_certificate(cert_data)
        data = bytearray(0x500)
        offset = 0x300
        data[offset: offset + len(win_cert)] = win_cert
        pe = make_mock_pe(bytes(data), sec_dd=(offset, len(win_cert)))
        certs = parse_certificates(pe)
        assert len(certs) == 1
        assert certs[0].cert_type == CERT_TYPE_PKCS_SIGNED_DATA

    def test_x509_cert_type_recognized(self):
        cert_data = b"\x00" * 32
        win_cert = build_win_certificate(cert_data, cert_type=CERT_TYPE_X509)
        data = bytearray(0x500)
        offset = 0x300
        data[offset: offset + len(win_cert)] = win_cert
        pe = make_mock_pe(bytes(data), sec_dd=(offset, len(win_cert)))
        certs = parse_certificates(pe)
        assert certs[0].cert_type == CERT_TYPE_X509
        assert "X.509" in certs[0].cert_type_name

    def test_wrong_revision_flagged(self):
        cert_data = b"\x00" * 32
        win_cert = build_win_certificate(cert_data, revision=0x0100)
        data = bytearray(0x500)
        offset = 0x300
        data[offset: offset + len(win_cert)] = win_cert
        pe = make_mock_pe(bytes(data), sec_dd=(offset, len(win_cert)))
        certs = parse_certificates(pe)
        assert len(certs) == 1
        assert any("revision" in a.lower() for a in certs[0].anomalies)

    def test_certificate_to_dict(self):
        cert_data = b"\x00" * 32
        win_cert = build_win_certificate(cert_data)
        data = bytearray(0x500)
        offset = 0x300
        data[offset: offset + len(win_cert)] = win_cert
        pe = make_mock_pe(bytes(data), sec_dd=(offset, len(win_cert)))
        certs = parse_certificates(pe)
        d = certs[0].to_dict()
        assert "cert_type_name" in d
        assert "serial_number" in d
        assert "digest_algorithm" in d


# ---------------------------------------------------------------------------
# Authenticode hash computation
# ---------------------------------------------------------------------------

class TestComputeAuthenticodeHash:
    def test_non_pe_returns_empty(self):
        assert _compute_authenticode_hash(b"not a pe file") == ""

    def test_valid_pe_returns_hash(self):
        pe_data = build_simple_pe()
        result = _compute_authenticode_hash(pe_data, "SHA-256")
        assert len(result) == 64  # SHA-256 = 32 bytes = 64 hex chars

    def test_sha1_hash_length(self):
        pe_data = build_simple_pe()
        result = _compute_authenticode_hash(pe_data, "SHA-1")
        assert len(result) == 40  # SHA-1 = 20 bytes

    def test_md5_hash_length(self):
        pe_data = build_simple_pe()
        result = _compute_authenticode_hash(pe_data, "MD5")
        assert len(result) == 32  # MD5 = 16 bytes

    def test_different_pe_different_hash(self):
        pe1 = build_simple_pe(overlay=b"\x00" * 100)
        pe2 = build_simple_pe(overlay=b"\xFF" * 100)
        h1 = _compute_authenticode_hash(pe1, "SHA-256")
        h2 = _compute_authenticode_hash(pe2, "SHA-256")
        assert h1 != h2

    def test_same_pe_same_hash(self):
        pe_data = build_simple_pe()
        h1 = _compute_authenticode_hash(pe_data, "SHA-256")
        h2 = _compute_authenticode_hash(pe_data, "SHA-256")
        assert h1 == h2

    def test_unknown_algorithm_falls_back(self):
        pe_data = build_simple_pe()
        result = _compute_authenticode_hash(pe_data, "UNKNOWN-ALG")
        # Falls back to SHA-256
        assert len(result) == 64


# ---------------------------------------------------------------------------
# Full analyze() integration
# ---------------------------------------------------------------------------

class TestAnalyze:
    def test_unsigned_pe_is_not_signed(self):
        pe_data = build_simple_pe()
        pe = parse_pe(pe_data)
        result = analyze(pe)
        assert not result.is_signed
        assert result.certificates == []

    def test_result_has_overlay_info(self):
        pe_data = build_simple_pe()
        pe = parse_pe(pe_data)
        result = analyze(pe)
        assert isinstance(result.overlay, OverlayInfo)

    def test_zip_overlay_in_result(self):
        overlay = b"PK\x03\x04" + b"\x00" * 200
        pe_data = build_simple_pe(overlay=overlay)
        pe = parse_pe(pe_data)
        result = analyze(pe)
        assert result.overlay.sfx_type == "ZIP"

    def test_result_to_dict_structure(self):
        pe_data = build_simple_pe()
        pe = parse_pe(pe_data)
        result = analyze(pe)
        d = result.to_dict()
        assert "overlay" in d
        assert "certificates" in d
        assert "is_signed" in d
        assert "signature_valid" in d
        assert "risk_indicators" in d

    def test_high_entropy_overlay_in_risk_indicators(self):
        overlay = bytes(range(256)) * 40  # 10240 bytes, near-max entropy
        pe_data = build_simple_pe(overlay=overlay)
        pe = parse_pe(pe_data)
        result = analyze(pe)
        assert any("entropy" in r.lower() for r in result.risk_indicators)

    def test_no_risk_indicators_for_clean_pe(self):
        pe_data = build_simple_pe()
        pe = parse_pe(pe_data)
        result = analyze(pe)
        assert isinstance(result.risk_indicators, list)
        # Clean PE should have no overlay anomalies
        assert len([r for r in result.risk_indicators if "entropy" in r.lower()]) == 0
