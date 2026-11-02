"""Tests for the PDF malware analyzer."""

from __future__ import annotations

import zlib
from typing import List

import pytest

from specter.pdf_analyzer import (
    PDFAnalyzer,
    PDFAnalysisResult,
    PDFParser,
    PDFSuspiciousFeature,
    EmbeddedFile,
    JavaScriptBlock,
)


# ---------------------------------------------------------------------------
# PDF construction helpers
# ---------------------------------------------------------------------------

def make_pdf(objects: List[bytes] = None, extra_eof: bool = False) -> bytes:
    """Build a minimal but structurally valid PDF for testing."""
    header = b"%PDF-1.7\n"
    body = b""
    if objects:
        for obj_bytes in objects:
            body += obj_bytes
    trailer = b"\n%%EOF\n"
    if extra_eof:
        trailer += b"%%EOF\n"
    return header + body + trailer


def make_object(obj_id: int, content: bytes) -> bytes:
    return f"{obj_id} 0 obj\n".encode() + content + b"\nendobj\n"


def make_stream_object(obj_id: int, stream: bytes, extra_dict: bytes = b"") -> bytes:
    compressed = zlib.compress(stream)
    length = len(compressed)
    return (
        f"{obj_id} 0 obj\n".encode()
        + b"<< /Filter /FlateDecode /Length " + str(length).encode() + b" " + extra_dict + b" >>\n"
        + b"stream\n"
        + compressed
        + b"\nendstream\nendobj\n"
    )


def make_js_action_object(obj_id: int, js_code: str) -> bytes:
    """Create a /Action dictionary with embedded JS literal."""
    js_bytes = js_code.encode("latin-1", errors="replace")
    return make_object(obj_id, b"<< /Type /Action /S /JavaScript /JS (" + js_bytes + b") >>")


def make_openaction_object(obj_id: int) -> bytes:
    return make_object(obj_id, b"<< /OpenAction << /S /JavaScript /JS (alert(1)) >> >>")


def make_launch_object(obj_id: int) -> bytes:
    return make_object(obj_id, b"<< /Type /Action /S /Launch /F (cmd.exe) >>")


def make_embedded_file_object(obj_id: int, filename: str = "malware.exe") -> bytes:
    fn = filename.encode("latin-1")
    return make_object(obj_id, b"<< /Type /Filespec /F (" + fn + b") /EF << /F 99 0 R >> >>")


# ---------------------------------------------------------------------------
# PDFParser unit tests
# ---------------------------------------------------------------------------

class TestPDFParser:
    def test_parse_header_version(self):
        data = b"%PDF-1.7\n%comment\n"
        parser = PDFParser(data)
        assert parser.parse_pdf_header() == "1.7"

    def test_parse_header_missing(self):
        parser = PDFParser(b"not a pdf")
        assert parser.parse_pdf_header() == ""

    def test_count_eof_single(self):
        data = make_pdf()
        parser = PDFParser(data)
        assert parser.count_eof_markers() == 1

    def test_count_eof_multiple(self):
        data = make_pdf(extra_eof=True)
        parser = PDFParser(data)
        assert parser.count_eof_markers() == 2

    def test_iter_objects_basic(self):
        obj_bytes = make_object(1, b"<< /Type /Page >>")
        data = make_pdf([obj_bytes])
        parser = PDFParser(data)
        objs = list(parser.iter_objects())
        assert any(o.obj_id == 1 for o in objs)

    def test_iter_objects_stream_decompressed(self):
        payload = b"Hello decompressed stream content"
        obj_bytes = make_stream_object(2, payload)
        data = make_pdf([obj_bytes])
        parser = PDFParser(data)
        objs = list(parser.iter_objects())
        stream_objs = [o for o in objs if o.is_stream]
        assert stream_objs
        # Decoded content should match original payload
        assert payload in stream_objs[0].decoded_stream

    def test_extract_filters_single(self):
        parser = PDFParser(b"")
        filters = parser._extract_filters(b"/Filter /FlateDecode /Length 10")
        assert "FlateDecode" in filters

    def test_extract_filters_array(self):
        parser = PDFParser(b"")
        filters = parser._extract_filters(b"/Filter [/FlateDecode /ASCIIHexDecode]")
        assert "FlateDecode" in filters
        assert "ASCIIHexDecode" in filters

    def test_has_key_present(self):
        parser = PDFParser(b"")
        assert parser.has_key(b"<< /JS (code) /Other val >>", b"JS")

    def test_has_key_absent(self):
        parser = PDFParser(b"")
        assert not parser.has_key(b"<< /Type /Page >>", b"JS")


# ---------------------------------------------------------------------------
# PDFAnalyzer integration tests
# ---------------------------------------------------------------------------

class TestPDFAnalyzer:
    def _analyzer(self) -> PDFAnalyzer:
        return PDFAnalyzer()

    def test_clean_pdf_low_score(self):
        """A PDF with only a page object should score very low."""
        obj = make_object(1, b"<< /Type /Page /MediaBox [0 0 612 792] >>")
        data = make_pdf([obj])
        result = self._analyzer().analyze(data)
        assert result.risk_score < 30.0
        assert not result.is_suspicious

    def test_pdf_version_extracted(self):
        data = make_pdf()
        result = self._analyzer().analyze(data)
        assert result.pdf_version == "1.7"

    def test_file_size_recorded(self):
        data = make_pdf()
        result = self._analyzer().analyze(data)
        assert result.file_size == len(data)

    def test_eof_count_single(self):
        data = make_pdf()
        result = self._analyzer().analyze(data)
        assert result.eof_count == 1
        assert PDFSuspiciousFeature.INCREMENTAL_UPDATE not in result.features

    def test_incremental_update_detected(self):
        data = make_pdf(extra_eof=True)
        result = self._analyzer().analyze(data)
        assert result.eof_count == 2
        assert PDFSuspiciousFeature.INCREMENTAL_UPDATE in result.features

    def test_javascript_in_literal_string(self):
        js_obj = make_js_action_object(1, "app.alert('hello');")
        data = make_pdf([js_obj])
        result = self._analyzer().analyze(data)
        assert PDFSuspiciousFeature.EMBEDDED_JAVASCRIPT in result.features
        assert len(result.javascript_blocks) > 0

    def test_javascript_in_stream(self):
        js_code = b"app.alert('hello from stream');"
        obj = make_stream_object(3, js_code, b"/Type /Action /S /JavaScript /JS 3 0 R")
        data = make_pdf([obj])
        result = self._analyzer().analyze(data)
        # Stream object decompresses and is detected
        assert result.stream_count >= 1

    def test_openaction_detected(self):
        obj = make_openaction_object(2)
        data = make_pdf([obj])
        result = self._analyzer().analyze(data)
        assert PDFSuspiciousFeature.AUTO_OPEN_ACTION in result.features
        assert PDFSuspiciousFeature.EMBEDDED_JAVASCRIPT in result.features

    def test_launch_action_detected(self):
        obj = make_launch_object(3)
        data = make_pdf([obj])
        result = self._analyzer().analyze(data)
        assert PDFSuspiciousFeature.LAUNCH_ACTION in result.features

    def test_embedded_file_detected(self):
        obj = make_embedded_file_object(4, "payload.exe")
        data = make_pdf([obj])
        result = self._analyzer().analyze(data)
        assert PDFSuspiciousFeature.EMBEDDED_FILE in result.features
        # The filename should appear in embedded_files or feature_details
        filenames = [ef.filename for ef in result.embedded_files]
        detail_text = str(result.feature_details)
        assert "payload.exe" in filenames or "payload.exe" in detail_text

    def test_eval_javascript_detected(self):
        js_obj = make_js_action_object(5, "eval(unescape('%61%6c%65%72%74%28%31%29'));")
        data = make_pdf([js_obj])
        result = self._analyzer().analyze(data)
        assert PDFSuspiciousFeature.JAVASCRIPT_EVAL in result.features

    def test_encrypted_document_detected(self):
        obj = make_object(6, b"<< /Encrypt << /Filter /Standard >> >>")
        data = make_pdf([obj])
        # Encrypt key anywhere in the data triggers the feature
        result = self._analyzer().analyze(data)
        assert PDFSuspiciousFeature.ENCRYPTED_DOCUMENT in result.features

    def test_risk_score_increases_with_features(self):
        """More suspicious features should produce higher risk score."""
        clean = make_pdf([make_object(1, b"<< /Type /Page >>")])
        malicious = make_pdf([
            make_js_action_object(1, "eval(unescape('...'));"),
            make_openaction_object(2),
            make_launch_object(3),
            make_embedded_file_object(4),
        ])
        clean_result = self._analyzer().analyze(clean)
        mal_result = self._analyzer().analyze(malicious)
        assert mal_result.risk_score > clean_result.risk_score

    def test_is_likely_malicious_with_heavy_features(self):
        """Document with JS + OpenAction + Launch + EmbeddedFile should be likely malicious."""
        objects = [
            make_js_action_object(1, "eval(unescape('shellcode_here'));"),
            make_openaction_object(2),
            make_launch_object(3),
            make_embedded_file_object(4),
        ]
        data = make_pdf(objects)
        result = self._analyzer().analyze(data)
        assert result.is_likely_malicious

    def test_to_dict_keys(self):
        data = make_pdf()
        result = self._analyzer().analyze(data)
        d = result.to_dict()
        expected_keys = [
            "file_size", "pdf_version", "page_count", "object_count",
            "stream_count", "features", "risk_score", "is_suspicious",
        ]
        for key in expected_keys:
            assert key in d

    def test_object_count_matches(self):
        objects = [
            make_object(1, b"<< /Type /Page >>"),
            make_object(2, b"<< /Type /Pages /Kids [1 0 R] /Count 1 >>"),
        ]
        data = make_pdf(objects)
        result = self._analyzer().analyze(data)
        assert result.object_count >= 2

    def test_stream_count_matches(self):
        stream = make_stream_object(10, b"content stream data")
        data = make_pdf([stream])
        result = self._analyzer().analyze(data)
        assert result.stream_count >= 1

    def test_shellcode_pattern_nop_sled(self):
        """Long hex NOP sled inside JS should be flagged."""
        nop_sled = "0x90" * 15
        js_obj = make_js_action_object(7, f"var x = '{nop_sled}';")
        data = make_pdf([js_obj])
        result = self._analyzer().analyze(data)
        assert PDFSuspiciousFeature.SHELLCODE_PATTERN in result.features

    def test_risk_score_capped_at_100(self):
        """Risk score must never exceed 100."""
        objects = [
            make_js_action_object(i, f"eval(unescape('x{i}'));")
            for i in range(1, 20)
        ] + [make_launch_object(20), make_embedded_file_object(21)]
        data = make_pdf(objects)
        result = self._analyzer().analyze(data)
        assert result.risk_score <= 100.0

    def test_obfuscated_stream_high_entropy(self):
        """A non-FlateDecode stream with high entropy should be flagged."""
        # Use raw random-looking bytes with high entropy by just using all byte values
        high_entropy = bytes(range(256)) * 4  # all 256 values equally -> max entropy
        raw_obj = (
            b"99 0 obj\n"
            b"<< /Length " + str(len(high_entropy)).encode() + b" >>\n"
            b"stream\n"
            + high_entropy
            + b"\nendstream\nendobj\n"
        )
        data = make_pdf([raw_obj])
        result = self._analyzer().analyze(data)
        # Should flag high entropy stream as obfuscated
        assert PDFSuspiciousFeature.OBFUSCATED_STREAM in result.features
