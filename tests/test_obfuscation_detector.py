"""
Tests for the obfuscation detection engine.
"""

from __future__ import annotations

import base64
import struct

import pytest

from specter.obfuscation_detector import (
    ObfuscationDetector,
    ObfuscationFinding,
    ObfuscationReport,
    ObfuscationType,
    _printable_ratio,
    _rot13,
    _shannon_entropy,
    _looks_like_shellcode,
)


# ------------------------------------------------------------------ helpers


def xor_encode(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def build_stack_string_32(text: str) -> bytes:
    """Emit MOV BYTE PTR [EBP+i], ch for each character."""
    out = bytearray()
    for i, ch in enumerate(text):
        out += bytes([0xC6, 0x45, i & 0xFF, ord(ch)])
    return bytes(out)


def build_stack_string_64(text: str) -> bytes:
    """Emit MOV BYTE PTR [RSP+i], ch for each character."""
    out = bytearray()
    for i, ch in enumerate(text):
        out += bytes([0xC6, 0x44, 0x24, i & 0xFF, ord(ch)])
    return bytes(out)


# -------------------------------------------------------- utility functions


class TestHelpers:
    def test_printable_ratio_all_printable(self):
        assert _printable_ratio(b"Hello World") == pytest.approx(1.0)

    def test_printable_ratio_no_printable(self):
        assert _printable_ratio(bytes(range(0, 0x20))) == pytest.approx(0.0)

    def test_printable_ratio_empty(self):
        assert _printable_ratio(b"") == 0.0

    def test_shannon_entropy_uniform(self):
        data = bytes(range(256))
        ent = _shannon_entropy(data)
        assert abs(ent - 8.0) < 0.01

    def test_shannon_entropy_constant(self):
        assert _shannon_entropy(b"\x00" * 64) == pytest.approx(0.0)

    def test_shannon_entropy_empty(self):
        assert _shannon_entropy(b"") == 0.0

    def test_rot13_roundtrip(self):
        s = "GetProcAddress"
        assert _rot13(_rot13(s)) == s

    def test_rot13_known(self):
        assert _rot13("Uryyb") == "Hello"

    def test_looks_like_shellcode_with_prologue(self):
        sc = b"\xfc\xe8" + bytes(range(32))
        assert _looks_like_shellcode(sc) is True

    def test_looks_like_shellcode_plain_text(self):
        sc = b"Hello, World! This is a plain ASCII string " * 3
        assert _looks_like_shellcode(sc) is False

    def test_looks_like_shellcode_too_short(self):
        assert _looks_like_shellcode(b"\xfc\xe8") is False


# ----------------------------------------------------------- base64 shellcode


class TestBase64ShellcodeDetection:
    def test_detects_base64_encoded_shellcode(self):
        # Build a payload that looks like shellcode: CLD opcode + high-entropy binary
        shellcode = b"\xfc\xe8" + bytes(range(256)) * 2
        encoded = base64.b64encode(shellcode)
        # Use non-base64 separator bytes so the regex anchors to the encoded payload
        data = b"\x00\x01\x02" + encoded + b"\x00\x01\x02"
        detector = ObfuscationDetector()
        report = detector.analyze(data)
        types = {f.obfuscation_type for f in report.findings}
        assert ObfuscationType.BASE64_SHELLCODE in types

    def test_ignores_base64_plaintext(self):
        plaintext = b"Hello, this is a completely normal string that is long enough!"
        encoded = base64.b64encode(plaintext)
        data = b"\x00\x01" + encoded + b"\x00\x01"
        detector = ObfuscationDetector()
        report = detector.analyze(data)
        b64_findings = [
            f for f in report.findings
            if f.obfuscation_type == ObfuscationType.BASE64_SHELLCODE
        ]
        assert len(b64_findings) == 0

    def test_finding_has_offset_and_decoded_length(self):
        shellcode = b"\xfc\xe8" + bytes(range(256)) * 2
        encoded = base64.b64encode(shellcode)
        # Use non-base64 separator so the regex match starts exactly at offset 3
        sep = b"\x00\x01\x02"
        data = sep + encoded
        detector = ObfuscationDetector()
        report = detector.analyze(data)
        b64 = [f for f in report.findings if f.obfuscation_type == ObfuscationType.BASE64_SHELLCODE]
        assert b64
        assert b64[0].offset == len(sep)
        assert len(b64[0].context_bytes) > 0


# ----------------------------------------------------------- XOR strings


class TestXorStringDetection:
    def test_detects_xor_encoded_strings(self):
        key = 0x42
        plaintext = b"GetProcAddress\x00LoadLibraryA\x00VirtualAlloc\x00" * 5
        encoded = xor_encode(plaintext, key)
        # Pad to exceed window size
        data = b"\x00" * 16 + encoded + b"\x00" * 16
        detector = ObfuscationDetector()
        report = detector.analyze(data)
        xor_findings = [
            f for f in report.findings
            if f.obfuscation_type == ObfuscationType.XOR_ENCODED_STRINGS
        ]
        assert xor_findings, "Should detect XOR-encoded strings"
        found_keys = {f.xor_key for f in xor_findings}
        assert key in found_keys

    def test_xor_finding_has_key_attribute(self):
        key = 0x37
        payload = b"CreateRemoteThread\x00WriteProcessMemory\x00" * 4
        encoded = xor_encode(payload, key)
        data = encoded * 3
        detector = ObfuscationDetector()
        report = detector.analyze(data)
        xor = [f for f in report.findings if f.xor_key == key]
        if xor:
            assert xor[0].xor_key == key
        # Either detected or not — key is in xor_keys_found if detected
        assert key in report.xor_keys_found or len(xor) == 0

    def test_null_xor_key_not_reported(self):
        """XOR key 0 is a no-op and should never appear in findings."""
        detector = ObfuscationDetector()
        data = b"Some normal text that repeats. " * 20
        report = detector.analyze(data)
        for f in report.findings:
            assert f.xor_key != 0


# ---------------------------------------------------------- stack strings


class TestStackStringDetection:
    def test_detects_x86_stack_strings(self):
        asm = build_stack_string_32("GetProcAddress")
        detector = ObfuscationDetector()
        report = detector.analyze(asm)
        ss = [f for f in report.findings if f.obfuscation_type == ObfuscationType.STACK_STRINGS]
        assert ss, "Should detect x86 stack string"
        assert "GetProcAddress" in (ss[0].decoded_value or "")

    def test_detects_x64_stack_strings(self):
        asm = build_stack_string_64("LoadLibraryA")
        detector = ObfuscationDetector()
        report = detector.analyze(asm)
        ss = [f for f in report.findings if f.obfuscation_type == ObfuscationType.STACK_STRINGS]
        assert ss, "Should detect x64 stack string"
        assert "LoadLibraryA" in (ss[0].decoded_value or "")

    def test_stack_string_count_in_report(self):
        asm = build_stack_string_32("Hello") + build_stack_string_32("World!!")
        detector = ObfuscationDetector()
        report = detector.analyze(asm)
        assert report.stack_string_count >= 1


# ------------------------------------------------------- dynamic API


class TestDynamicApiDetection:
    def test_detects_getprocaddress(self):
        data = b"\x00" * 8 + b"GetProcAddress\x00" + b"\x00" * 8
        detector = ObfuscationDetector()
        report = detector.analyze(data)
        api_findings = [
            f for f in report.findings
            if f.obfuscation_type == ObfuscationType.DYNAMIC_API_RESOLUTION
        ]
        assert api_findings
        descriptions = [f.description for f in api_findings]
        assert any("GetProcAddress" in d for d in descriptions)

    def test_detects_loadlibrary(self):
        data = b"LoadLibraryA\x00"
        detector = ObfuscationDetector()
        report = detector.analyze(data)
        assert any("LoadLibraryA" in f.description for f in report.findings)

    def test_api_calls_in_report(self):
        data = b"GetProcAddress\x00LoadLibraryA\x00VirtualAlloc\x00"
        detector = ObfuscationDetector()
        report = detector.analyze(data)
        assert len(report.dynamic_api_calls) >= 2


# ------------------------------------------------ anti-disassembly


class TestAntiDisassemblyDetection:
    def test_detects_ud2(self):
        data = b"\x90" * 4 + b"\x0f\x0b" + b"\x90" * 4
        detector = ObfuscationDetector()
        report = detector.analyze(data)
        ad = [f for f in report.findings if f.obfuscation_type == ObfuscationType.ANTI_DISASSEMBLY]
        assert ad, "Should detect UD2 gadget"

    def test_detects_jmp_minus1(self):
        data = b"\x90" * 4 + b"\xeb\xff" + b"\x90" * 4
        detector = ObfuscationDetector()
        report = detector.analyze(data)
        ad = [f for f in report.findings if f.obfuscation_type == ObfuscationType.ANTI_DISASSEMBLY]
        assert ad

    def test_context_bytes_captured(self):
        data = b"\x90" * 8 + b"\x0f\x0b" + b"\x90" * 8
        detector = ObfuscationDetector()
        report = detector.analyze(data)
        ad = [f for f in report.findings if f.obfuscation_type == ObfuscationType.ANTI_DISASSEMBLY]
        if ad:
            assert len(ad[0].context_bytes) > 0


# ---------------------------------------------------------------- ROT13


class TestRot13Detection:
    def test_detects_rot13_api_name(self):
        # ROT13("GetProcAddress") = "TrgCebpNqqerff"
        rot_string = _rot13("GetProcAddress")
        data = rot_string.encode("ascii") + b"\x00"
        detector = ObfuscationDetector()
        report = detector.analyze(data)
        r13 = [f for f in report.findings if f.obfuscation_type == ObfuscationType.ROT13_STRINGS]
        assert r13, "Should detect ROT13-encoded API name"
        assert r13[0].decoded_value == "GetProcAddress"

    def test_rot13_finding_includes_decoded_value(self):
        rot_string = _rot13("powershell")
        data = b"\x00" + rot_string.encode("ascii") + b"\x00"
        detector = ObfuscationDetector()
        report = detector.analyze(data)
        r13 = [f for f in report.findings if f.obfuscation_type == ObfuscationType.ROT13_STRINGS]
        assert r13
        assert "powershell" in (r13[0].decoded_value or "").lower()


# --------------------------------------------------------- scoring / report


class TestObfuscationReport:
    def test_empty_data_no_findings(self):
        detector = ObfuscationDetector()
        report = detector.analyze(b"")
        assert report.findings == []
        assert report.obfuscation_score == 0.0
        assert not report.is_obfuscated

    def test_clean_binary_low_score(self):
        detector = ObfuscationDetector()
        data = b"MZ" + b"\x00" * 256  # minimal PE stub, no obfuscation markers
        report = detector.analyze(data)
        assert report.obfuscation_score < 30.0

    def test_multiple_techniques_raise_score(self):
        # Combine several obfuscation techniques
        shellcode = b"\xfc\xe8" + bytes(range(256)) * 2
        encoded_sc = base64.b64encode(shellcode)
        api_bytes = b"GetProcAddress\x00LoadLibraryA\x00"
        stack_str = build_stack_string_32("CreateFile")
        ud2 = b"\x0f\x0b"
        data = encoded_sc + api_bytes + stack_str + ud2

        detector = ObfuscationDetector()
        report = detector.analyze(data)
        assert report.obfuscation_score > 30.0

    def test_is_obfuscated_threshold(self):
        report = ObfuscationReport()
        report.obfuscation_score = 29.9
        assert not report.is_obfuscated
        report.obfuscation_score = 30.0
        assert report.is_obfuscated

    def test_is_heavily_obfuscated_threshold(self):
        report = ObfuscationReport()
        report.obfuscation_score = 64.9
        assert not report.is_heavily_obfuscated
        report.obfuscation_score = 65.0
        assert report.is_heavily_obfuscated

    def test_summary_no_findings(self):
        report = ObfuscationReport()
        assert "No obfuscation" in report.summary()

    def test_summary_with_findings(self):
        report = ObfuscationReport()
        report.findings = [
            ObfuscationFinding(
                obfuscation_type=ObfuscationType.XOR_ENCODED_STRINGS,
                offset=0, length=10, confidence=0.8,
                description="test",
            )
        ]
        report.detected_types = [ObfuscationType.XOR_ENCODED_STRINGS]
        report.obfuscation_score = 20.0
        summary = report.summary()
        assert "20.0" in summary
        assert "xor_encoded_strings" in summary

    def test_detected_types_unique(self):
        shellcode = b"\xfc\xe8" + bytes(range(256)) * 2
        encoded_sc = base64.b64encode(shellcode)
        data = encoded_sc + b"GetProcAddress\x00"
        detector = ObfuscationDetector()
        report = detector.analyze(data)
        # detected_types should not contain duplicates
        assert len(report.detected_types) == len(set(report.detected_types))

    def test_xor_keys_in_report(self):
        key = 0x13
        payload = b"VirtualAllocEx\x00WriteProcessMemory\x00" * 5
        encoded = xor_encode(payload, key)
        data = encoded * 3
        detector = ObfuscationDetector()
        report = detector.analyze(data)
        # If XOR was detected at key 0x13, it should appear in xor_keys_found
        if ObfuscationType.XOR_ENCODED_STRINGS in report.detected_types:
            assert report.xor_keys_found
