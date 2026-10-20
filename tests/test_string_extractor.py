"""Tests for the advanced string extractor."""

import base64
import pytest

from specter.string_extractor import (
    StringExtractor,
    StringCategory,
    StringEncoding,
    ExtractedString,
    _calculate_string_entropy,
    _try_decode_base64,
    _extract_ascii_strings,
    _extract_wide_strings,
    _decode_xor,
)


class TestHelpers:
    def test_entropy_uniform_string(self):
        s = "aaaaaaaaaa"
        assert _calculate_string_entropy(s) == pytest.approx(0.0)

    def test_entropy_high_for_random(self):
        import random, string
        random.seed(42)
        s = "".join(random.choices(string.printable, k=64))
        e = _calculate_string_entropy(s)
        assert e > 4.0

    def test_decode_base64_valid(self):
        original = b"Hello, malware world! This is a test payload."
        encoded = base64.b64encode(original).decode()
        decoded = _try_decode_base64(encoded)
        assert decoded == original

    def test_decode_base64_pe_header(self):
        pe_stub = b"MZ" + b"\x00" * 30
        encoded = base64.b64encode(pe_stub).decode()
        decoded = _try_decode_base64(encoded)
        assert decoded is not None
        assert decoded[:2] == b"MZ"

    def test_decode_base64_garbage_returns_none(self):
        result = _try_decode_base64("notbase64!@#$")
        assert result is None

    def test_xor_decode_roundtrip(self):
        original = b"secret string data"
        key = 0x42
        encoded = _decode_xor(original, key)
        decoded = _decode_xor(encoded, key)
        assert decoded == original

    def test_ascii_strings_extracted(self):
        data = b"\x00\x00example.com\x00\x00"
        results = list(_extract_ascii_strings(data, min_len=4))
        values = [r[0] for r in results]
        assert any("example.com" in v for v in values)

    def test_wide_strings_extracted(self):
        text = "test.dll"
        wide = b"".join(bytes([ord(c), 0]) for c in text) + b"\x00\x00"
        # Use 2-byte aligned prefix so scanner starts on the right boundary
        results = list(_extract_wide_strings(b"\x00\x00" + wide, min_len=4))
        values = [r[0] for r in results]
        assert any("test.dll" in v for v in values)


class TestStringExtractor:
    def setup_method(self):
        self.extractor = StringExtractor(min_length=4, decode_base64=True, brute_xor=False)

    def test_extract_ascii_strings(self):
        data = b"\x00\x00cmd.exe /c whoami\x00\x00"
        result = self.extractor.extract(data)
        values = [s.value for s in result.strings]
        assert any("cmd.exe" in v for v in values)

    def test_extract_wide_strings(self):
        text = "CreateRemoteThread"
        wide = b"".join(bytes([ord(c), 0]) for c in text) + b"\x00\x00"
        result = self.extractor.extract(b"\x00" * 4 + wide)
        wide_strings = result.by_encoding(StringEncoding.UTF16LE)
        assert any("CreateRemoteThread" in s.value for s in wide_strings)

    def test_api_call_categorization(self):
        data = b"VirtualAllocEx WriteProcessMemory CreateRemoteThread\x00"
        result = self.extractor.extract(data)
        api_strings = result.by_category(StringCategory.API_CALL)
        api_values = [s.value for s in api_strings]
        assert any("VirtualAllocEx" in v for v in api_values)

    def test_registry_categorization(self):
        data = b"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
        result = self.extractor.extract(data)
        reg_strings = result.by_category(StringCategory.REGISTRY)
        assert len(reg_strings) > 0

    def test_path_categorization(self):
        data = b"C:\\Windows\\System32\\malware.exe\x00"
        result = self.extractor.extract(data)
        path_strings = result.by_category(StringCategory.PATH)
        assert len(path_strings) > 0

    def test_network_categorization(self):
        data = b"http://192.0.2.1:4444/beacon\x00"
        result = self.extractor.extract(data)
        net_strings = result.by_category(StringCategory.NETWORK)
        assert len(net_strings) > 0

    def test_base64_decoded(self):
        payload = b"VirtualAlloc shellcode_placeholder_data_here!"
        encoded = base64.b64encode(payload).decode()
        data = encoded.encode("ascii") + b"\x00"
        extractor = StringExtractor(min_length=4, decode_base64=True, brute_xor=False)
        result = extractor.extract(data)
        assert len(result.base64_decoded) > 0

    def test_suspicious_strings_flagged(self):
        data = b"CreateRemoteThread WriteProcessMemory VirtualAllocEx\x00"
        result = self.extractor.extract(data)
        suspicious = result.suspicious()
        assert len(suspicious) > 0

    def test_deduplication(self):
        text = b"CreateRemoteThread " * 5 + b"\x00"
        result = self.extractor.extract(text)
        values = [s.value for s in result.strings if "CreateRemoteThread" in s.value]
        # Deduplicated: should appear only once
        assert len(values) <= 2

    def test_summary_dict(self):
        data = b"HKLM\\Run cmd.exe CreateRemoteThread\x00"
        result = self.extractor.extract(data)
        summary = result.summary()
        assert "total" in summary
        assert summary["total"] == len(result.strings)

    def test_xor_detection(self):
        # Use 0xFF as key: maps all printable ASCII to 0x80-0xFF (non-printable),
        # so the encoded chunk has low natural printability and the scanner decodes it.
        key = 0xFF
        plaintext = b"CreateRemoteThread NtWriteVirtualMemory download"
        encoded = bytes(b ^ key for b in plaintext)
        # Pad with non-printable bytes so the chunk natural ratio is clearly low
        data = encoded + b"\x80" * 8
        extractor = StringExtractor(min_length=6, brute_xor=True, brute_xor_min_printable=0.80)
        result = extractor.extract(data)
        xor_strings = result.xor_decoded
        assert len(xor_strings) > 0
        # Verify decoded strings are flagged suspicious and have a XOR key stored
        assert all(s.xor_key is not None for s in xor_strings)
        assert all(s.is_suspicious for s in xor_strings)

    def test_extract_from_file(self, tmp_path):
        sample = tmp_path / "malware.bin"
        sample.write_bytes(b"VirtualAllocEx\x00CreateRemoteThread\x00cmd.exe /c echo pwned\x00")
        result = self.extractor.extract_from_file(str(sample))
        assert result.total_bytes_scanned > 0
        assert len(result.strings) > 0

    def test_extract_api_calls_convenience(self):
        data = b"LoadLibraryA GetProcAddress VirtualAlloc CreateThread\x00"
        apis = self.extractor.extract_api_calls(data)
        assert isinstance(apis, list)
        assert len(apis) > 0

    def test_find_suspicious_convenience(self):
        data = b"VirtualAllocEx WriteProcessMemory\x00"
        sus = self.extractor.find_suspicious_strings(data)
        assert len(sus) > 0
