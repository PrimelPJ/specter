"""
Tests for entropy analysis module.
"""

import math
import pytest

from specter.entropy import EntropyAnalyzer, SectionEntropyResult


class TestShannonEntropy:
    def test_zero_entropy_single_byte(self):
        data = b"\x00" * 1000
        e = EntropyAnalyzer.shannon_entropy(data)
        assert e == 0.0

    def test_max_entropy_uniform(self):
        # Uniform distribution over 256 values -> entropy = 8
        data = bytes(range(256)) * 4
        e = EntropyAnalyzer.shannon_entropy(data)
        assert abs(e - 8.0) < 0.01

    def test_empty_data(self):
        e = EntropyAnalyzer.shannon_entropy(b"")
        assert e == 0.0

    def test_text_has_low_entropy(self):
        data = b"hello world " * 1000
        e = EntropyAnalyzer.shannon_entropy(data)
        assert e < 4.0

    def test_high_entropy_random_like(self):
        import os
        data = bytes([i % 256 for i in range(10000)])
        e = EntropyAnalyzer.shannon_entropy(data)
        assert e > 6.0


class TestEntropyAnalyzer:
    def setup_method(self):
        self.analyzer = EntropyAnalyzer(window_size=64, step_size=32)

    def test_analyze_section_basic(self):
        data = b"\x00" * 512
        result = self.analyzer.analyze_section(".data", data, file_offset=0x1000)
        assert isinstance(result, SectionEntropyResult)
        assert result.name == ".data"
        assert result.entropy == 0.0
        assert not result.is_packed

    def test_analyze_section_empty(self):
        result = self.analyzer.analyze_section(".bss", b"")
        assert result.size == 0
        assert result.entropy == 0.0

    def test_packed_detection(self):
        # High entropy data simulates packed section
        data = bytes(i % 256 for i in range(2048))
        result = self.analyzer.analyze_section(".text", data)
        assert result.entropy > 6.0

    def test_bins_produced(self):
        data = bytes(range(256)) * 8
        result = self.analyzer.analyze_section(".text", data)
        assert len(result.bins) > 0

    def test_offset_in_bins(self):
        data = b"\xaa\xbb" * 512
        result = self.analyzer.analyze_section(".data", data, file_offset=0x400)
        if result.bins:
            assert result.bins[0].offset >= 0x400

    def test_high_entropy_region_detection(self):
        low = b"\x00" * 512
        high = bytes(i % 256 for i in range(1024))
        data = low + high + low
        regions = self.analyzer.find_high_entropy_regions(data, threshold=6.0, min_region_size=64)
        assert len(regions) > 0
        for start, end, avg_e in regions:
            assert avg_e >= 6.0

    def test_compression_detection_gzip(self):
        gzip_magic = b"\x1f\x8b" + b"\x00" * 512
        is_compressed, entropy, method = self.analyzer.detect_compression(gzip_magic)
        assert method == "gzip"

    def test_byte_frequency_analysis(self):
        data = b"\x00" * 100 + b"\xff" * 100
        result = self.analyzer.byte_frequency_analysis(data)
        assert "chi_square" in result
        assert "entropy" in result
        assert result["zero_bytes"] == 100

    def test_invalid_window(self):
        with pytest.raises(ValueError):
            EntropyAnalyzer(window_size=8)

    def test_classify_encrypted(self):
        data = bytes(i % 256 for i in range(4096))
        result = self.analyzer.analyze_section(".rsrc", data)
        if result.entropy > 7.2:
            assert result.is_encrypted
        elif result.entropy > 6.5:
            assert result.is_packed


class TestSectionEntropyResult:
    def test_classification_plaintext(self):
        r = SectionEntropyResult(name=".text", offset=0, size=100, entropy=2.0)
        assert r.classification == "plaintext"

    def test_classification_text_data(self):
        r = SectionEntropyResult(name=".rdata", offset=0, size=100, entropy=4.0)
        assert r.classification == "text_data"

    def test_classification_compiled_code(self):
        r = SectionEntropyResult(name=".text", offset=0, size=100, entropy=5.5)
        assert r.classification == "compiled_code"

    def test_classification_packed(self):
        r = SectionEntropyResult(name=".text", offset=0, size=100, entropy=6.8)
        assert r.classification == "packed"

    def test_classification_encrypted(self):
        r = SectionEntropyResult(name=".data", offset=0, size=100, entropy=7.5)
        assert r.classification == "encrypted/compressed"
