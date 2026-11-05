"""Tests for the advanced PE packer detection engine."""

from __future__ import annotations

import hashlib
import struct
from typing import List

import pytest

from specter.packer_detector import (
    PackerAnalysisResult,
    PackerDetector,
    PackerSignal,
    _chi_square_uniformity,
    _has_rich_header,
    _is_name_suspicious,
    _size_ratio,
    _validate_pe_checksum,
)
from specter.pe_parser import PEParseError, SectionHeader


# ---------------------------------------------------------------------------
# Minimal PE builder for testing (no external files needed)
# ---------------------------------------------------------------------------

def _build_minimal_pe(
    num_sections: int = 2,
    ep_rva: int = 0x1000,
    section_names: List[str] | None = None,
    fill_byte: int = 0x90,
    make_packed: bool = False,
) -> bytes:
    """
    Build a minimal valid PE32 binary in memory.
    Follows the PE32 optional header layout precisely at byte offsets
    so that PEParser can parse it without errors.
    """
    section_names = section_names or [".text", ".data"][:num_sections]
    num_sections = min(num_sections, len(section_names))

    section_raw_size = 0x200
    section_vsize = 0x1000
    e_lfanew = 0x80          # leave 0x40..0x7F for a stub / fake Rich header
    opt_header_size = 224    # PE32: 96 base + 16 x 8 data dirs

    sections_tbl_start = e_lfanew + 4 + 20 + opt_header_size
    raw_headers_end = sections_tbl_start + num_sections * 40
    headers_raw_size = (raw_headers_end + 0x1FF) & ~0x1FF
    image_size = headers_raw_size + num_sections * section_vsize

    buf = bytearray(headers_raw_size + num_sections * section_raw_size)

    buf[0] = ord('M')
    buf[1] = ord('Z')
    struct.pack_into("<I", buf, 0x3C, e_lfanew)

    buf[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"

    coff_off = e_lfanew + 4
    struct.pack_into(
        "<HHIIIHH", buf, coff_off,
        0x014C, num_sections, 0x5F000000, 0, 0, opt_header_size, 0x0002,
    )

    opt = coff_off + 20
    struct.pack_into("<H",  buf, opt + 0,  0x010B)
    struct.pack_into("<BB", buf, opt + 2,  14, 0)
    struct.pack_into("<I",  buf, opt + 4,  section_raw_size)
    struct.pack_into("<I",  buf, opt + 8,  0)
    struct.pack_into("<I",  buf, opt + 12, 0)
    struct.pack_into("<I",  buf, opt + 16, ep_rva)
    struct.pack_into("<I",  buf, opt + 20, 0x1000)
    struct.pack_into("<I",  buf, opt + 24, 0x2000)
    struct.pack_into("<I",  buf, opt + 28, 0x00400000)
    struct.pack_into("<I",  buf, opt + 32, 0x1000)
    struct.pack_into("<I",  buf, opt + 36, 0x200)
    struct.pack_into("<HH", buf, opt + 40, 6, 0)
    struct.pack_into("<HH", buf, opt + 44, 0, 0)
    struct.pack_into("<HH", buf, opt + 48, 6, 0)
    struct.pack_into("<I",  buf, opt + 52, 0)
    struct.pack_into("<I",  buf, opt + 56, image_size)
    struct.pack_into("<I",  buf, opt + 60, headers_raw_size)
    struct.pack_into("<I",  buf, opt + 64, 0)
    struct.pack_into("<H",  buf, opt + 68, 2)
    struct.pack_into("<H",  buf, opt + 70, 0)
    struct.pack_into("<I",  buf, opt + 72, 0x100000)
    struct.pack_into("<I",  buf, opt + 76, 0x1000)
    struct.pack_into("<I",  buf, opt + 80, 0x100000)
    struct.pack_into("<I",  buf, opt + 84, 0x1000)
    struct.pack_into("<I",  buf, opt + 88, 0)
    struct.pack_into("<I",  buf, opt + 92, 16)

    for i, name in enumerate(section_names):
        name_bytes = name.encode("ascii")[:8].ljust(8, b"\x00")
        sec_vaddr = 0x1000 + i * section_vsize
        sec_raw_off = headers_raw_size + i * section_raw_size
        st_off = sections_tbl_start + i * 40
        struct.pack_into(
            "<8sIIIIIHHI", buf, st_off,
            name_bytes, section_vsize, sec_vaddr,
            section_raw_size, sec_raw_off, 0, 0, 0, 0x60000020,
        )

    for i in range(num_sections):
        raw_off = headers_raw_size + i * section_raw_size
        if make_packed:
            seed = 0xDEADBEEF ^ (i * 0x1234)
            for j in range(section_raw_size):
                seed = (seed * 1664525 + 1013904223) & 0xFFFFFFFF
                buf[raw_off + j] = seed & 0xFF
        else:
            for j in range(section_raw_size):
                buf[raw_off + j] = fill_byte

    return bytes(buf)


# ---------------------------------------------------------------------------
# Unit tests: standalone helpers
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_has_rich_header_absent(self):
        data = _build_minimal_pe()
        assert _has_rich_header(data) is False

    def test_has_rich_header_present(self):
        data = bytearray(_build_minimal_pe())
        data[0x60:0x64] = b"Rich"
        assert _has_rich_header(bytes(data)) is True

    def test_validate_pe_checksum_zero(self):
        data = _build_minimal_pe()
        assert _validate_pe_checksum(data, 0) is True

    def test_is_name_suspicious_known_normal(self):
        for name in [".text", ".data", ".rsrc", ".reloc", ".rdata"]:
            assert _is_name_suspicious(name) is False

    def test_is_name_suspicious_no_dot_prefix(self):
        for name in ["UPX0", "UPX1", "nsp0", "mpress1"]:
            assert _is_name_suspicious(name) is True

    def test_size_ratio_normal(self):
        sec = SectionHeader(
            name=".text", virtual_size=0x1000, virtual_address=0x1000,
            size_of_raw_data=0x1000, pointer_to_raw_data=0x200, characteristics=0x60000020,
        )
        assert _size_ratio(sec) == pytest.approx(1.0)

    def test_size_ratio_packed(self):
        sec = SectionHeader(
            name=".pack", virtual_size=0x80000, virtual_address=0x1000,
            size_of_raw_data=0x200, pointer_to_raw_data=0x200, characteristics=0x60000020,
        )
        ratio = _size_ratio(sec)
        assert ratio is not None and ratio >= 8.0

    def test_size_ratio_zero_raw(self):
        sec = SectionHeader(
            name=".bss", virtual_size=0x1000, virtual_address=0x2000,
            size_of_raw_data=0, pointer_to_raw_data=0, characteristics=0x80000000,
        )
        assert _size_ratio(sec) is None

    def test_chi_square_near_uniform(self):
        seed = 0xDEAD
        data = bytearray(65536)
        for i in range(len(data)):
            seed = (seed * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFF
            data[i] = seed & 0xFF
        chi = _chi_square_uniformity(bytes(data))
        assert chi < 500

    def test_chi_square_all_zeros(self):
        data = bytes(65536)
        chi = _chi_square_uniformity(data)
        assert chi > 100000

    def test_chi_square_too_small(self):
        assert _chi_square_uniformity(b"\x00" * 10) == float("inf")


# ---------------------------------------------------------------------------
# Integration tests: PackerDetector with minimal PE
# ---------------------------------------------------------------------------

class TestPackerDetector:
    def test_analyze_clean_pe_no_error(self):
        data = _build_minimal_pe(make_packed=False)
        result = PackerDetector().analyze(data)
        assert result is not None
        assert 0.0 <= result.packed_confidence <= 1.0

    def test_analyze_high_entropy_pe_higher_confidence(self):
        clean_result = PackerDetector().analyze(_build_minimal_pe(make_packed=False))
        packed_result = PackerDetector().analyze(_build_minimal_pe(make_packed=True))
        assert packed_result.packed_confidence >= clean_result.packed_confidence

    def test_upx_section_names_detected(self):
        data = _build_minimal_pe(section_names=["UPX0", "UPX1"], make_packed=True)
        result = PackerDetector().analyze(data)
        upx_signals = [s for s in result.signals if "UPX" in (s.packer_hint or "")]
        assert len(upx_signals) >= 1

    def test_result_sha256_matches(self):
        data = _build_minimal_pe()
        expected_sha = hashlib.sha256(data).hexdigest()
        assert PackerDetector().analyze(data).file_sha256 == expected_sha

    def test_result_to_dict_has_required_keys(self):
        d = PackerDetector().analyze(_build_minimal_pe()).to_dict()
        required_keys = {
            "file_sha256", "packed_confidence", "probable_packer",
            "signals", "section_entropy_map", "entry_point_section",
            "import_count", "has_tls", "has_rich_header", "pe_checksum_valid",
        }
        assert required_keys.issubset(d.keys())
        assert isinstance(d["signals"], list)
        assert isinstance(d["section_entropy_map"], dict)

    def test_confidence_aggregate_no_signals(self):
        assert PackerDetector._aggregate_confidence([]) == 0.0

    def test_confidence_aggregate_full_signal(self):
        assert PackerDetector._aggregate_confidence(
            [PackerSignal("s1", "d1", 1.0)]
        ) == pytest.approx(1.0)

    def test_confidence_aggregate_diminishing_returns(self):
        signals = [PackerSignal("s1", "d1", 0.5), PackerSignal("s2", "d2", 0.5)]
        assert PackerDetector._aggregate_confidence(signals) == pytest.approx(0.75)

    def test_summary_packed(self):
        result = PackerAnalysisResult(file_sha256="abc", packed_confidence=0.85, probable_packer="UPX")
        assert "likely packed" in result.summary
        assert "UPX" in result.summary

    def test_summary_clean(self):
        result = PackerAnalysisResult(file_sha256="abc", packed_confidence=0.15, probable_packer=None)
        assert "probably clean" in result.summary

    def test_is_likely_packed_threshold(self):
        assert PackerAnalysisResult(file_sha256="a", packed_confidence=0.5, probable_packer="X").is_likely_packed is True
        assert PackerAnalysisResult(file_sha256="b", packed_confidence=0.49, probable_packer=None).is_likely_packed is False

    def test_section_entropy_map_populated(self):
        result = PackerDetector().analyze(_build_minimal_pe(section_names=[".text", ".data"]))
        assert ".text" in result.section_entropy_map or len(result.section_entropy_map) > 0

    def test_ep_in_last_section_detected(self):
        data = _build_minimal_pe(ep_rva=0x2000, section_names=[".text", ".packed"])
        result = PackerDetector().analyze(data)
        ep_signals = [s for s in result.signals if s.name == "ep_in_last_section"]
        assert len(ep_signals) >= 1
