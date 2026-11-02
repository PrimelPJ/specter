"""
PDF malware analyzer: static analysis of PDF documents.

Parses PDF cross-reference table and object graph, decompresses FlateDecode
streams, extracts embedded JavaScript, detects embedded files, and scores
suspicious features for malware triage.
"""

from __future__ import annotations

import io
import logging
import math
import re
import struct
import zlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PDF structural constants
# ---------------------------------------------------------------------------

PDF_HEADER_RE = re.compile(rb"%PDF-(\d+\.\d+)")
PDF_EOF_RE = re.compile(rb"%%EOF")

# Object definition: "<id> <gen> obj"
OBJ_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj\s*", re.DOTALL)

# Cross-reference entry: 20-byte records in traditional xref tables
XREF_ENTRY_RE = re.compile(rb"(\d{10})\s(\d{5})\s([fn])")

# Stream boundaries
STREAM_START_RE = re.compile(rb"stream\s*\r?\n", re.DOTALL)
STREAM_END_RE = re.compile(rb"\r?\nendstream", re.DOTALL)

# Dictionary key/value
DICT_RE = re.compile(rb"/(\w+)\s*(?:/([\w]+)|(\d+)|(\(.*?\))|(<[0-9a-fA-F]*>)|\[([^\]]*)\])?", re.DOTALL)

# JavaScript triggers in dictionaries
JS_KEYS = {b"JS", b"JavaScript"}
JS_TRIGGER_KEYS = {b"OpenAction", b"AA", b"AcroForm"}
LAUNCH_KEYS = {b"Launch", b"SubmitForm", b"GoToR", b"URI", b"ImportData"}

# Suspicious PDF features
class PDFSuspiciousFeature(str, Enum):
    EMBEDDED_JAVASCRIPT = "embedded_javascript"
    AUTO_OPEN_ACTION = "auto_open_action"
    LAUNCH_ACTION = "launch_action"
    URI_ACTION = "uri_action"
    EMBEDDED_FILE = "embedded_file"
    ACROFORM_JAVASCRIPT = "acroform_javascript"
    OBFUSCATED_STREAM = "obfuscated_stream"
    ENCRYPTED_DOCUMENT = "encrypted_document"
    SUSPICIOUS_NAMES = "suspicious_names"   # /Names with obfuscated JS
    INCREMENTAL_UPDATE = "incremental_update"  # multiple %%EOF -> possible hiding
    JAVASCRIPT_EVAL = "javascript_eval"     # eval() / unescape() in JS
    SHELLCODE_PATTERN = "shellcode_pattern" # NOP sled / heap spray patterns
    MANY_STREAMS = "many_streams"           # unusually large number of streams


# Score contribution per feature (0-100 scale)
FEATURE_SCORES: Dict[PDFSuspiciousFeature, int] = {
    PDFSuspiciousFeature.EMBEDDED_JAVASCRIPT: 30,
    PDFSuspiciousFeature.AUTO_OPEN_ACTION: 25,
    PDFSuspiciousFeature.LAUNCH_ACTION: 40,
    PDFSuspiciousFeature.URI_ACTION: 10,
    PDFSuspiciousFeature.EMBEDDED_FILE: 20,
    PDFSuspiciousFeature.ACROFORM_JAVASCRIPT: 30,
    PDFSuspiciousFeature.OBFUSCATED_STREAM: 15,
    PDFSuspiciousFeature.ENCRYPTED_DOCUMENT: 10,
    PDFSuspiciousFeature.SUSPICIOUS_NAMES: 20,
    PDFSuspiciousFeature.INCREMENTAL_UPDATE: 10,
    PDFSuspiciousFeature.JAVASCRIPT_EVAL: 35,
    PDFSuspiciousFeature.SHELLCODE_PATTERN: 45,
    PDFSuspiciousFeature.MANY_STREAMS: 5,
}


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class PDFObject:
    """Parsed PDF indirect object."""
    obj_id: int
    gen: int
    raw_dict: bytes = b""
    raw_stream: bytes = b""        # compressed/raw stream bytes
    decoded_stream: bytes = b""    # after FlateDecode (or empty if not a stream)
    stream_filters: List[str] = field(default_factory=list)
    is_stream: bool = False

    @property
    def stream_text(self) -> str:
        data = self.decoded_stream or self.raw_stream
        try:
            return data.decode("latin-1")
        except Exception:
            return ""


@dataclass
class EmbeddedFile:
    """A file embedded inside a PDF via /EmbeddedFile or /Filespec."""
    obj_id: int
    filename: str
    size: int = 0
    md5: str = ""
    data: bytes = b""
    mime_type: str = ""


@dataclass
class JavaScriptBlock:
    """Extracted JavaScript code fragment from a PDF stream or action."""
    obj_id: int
    source_key: str   # OpenAction, AA, AcroForm, JS, etc.
    code: str
    has_eval: bool = False
    has_unescape: bool = False


@dataclass
class PDFAnalysisResult:
    """Full static analysis result for a PDF file."""
    file_size: int = 0
    pdf_version: str = ""
    page_count: int = 0
    object_count: int = 0
    stream_count: int = 0
    eof_count: int = 0              # >1 signals incremental updates

    # Extracted content
    javascript_blocks: List[JavaScriptBlock] = field(default_factory=list)
    embedded_files: List[EmbeddedFile] = field(default_factory=list)

    # Detected suspicious features
    features: List[PDFSuspiciousFeature] = field(default_factory=list)
    feature_details: Dict[str, Any] = field(default_factory=dict)

    # Composite risk score 0-100
    risk_score: float = 0.0

    # Errors encountered during parsing (non-fatal)
    errors: List[str] = field(default_factory=list)

    @property
    def is_suspicious(self) -> bool:
        return self.risk_score >= 30.0

    @property
    def is_likely_malicious(self) -> bool:
        return self.risk_score >= 60.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_size": self.file_size,
            "pdf_version": self.pdf_version,
            "page_count": self.page_count,
            "object_count": self.object_count,
            "stream_count": self.stream_count,
            "eof_count": self.eof_count,
            "javascript_block_count": len(self.javascript_blocks),
            "embedded_file_count": len(self.embedded_files),
            "embedded_filenames": [ef.filename for ef in self.embedded_files],
            "features": [f.value for f in self.features],
            "risk_score": round(self.risk_score, 2),
            "is_suspicious": self.is_suspicious,
            "is_likely_malicious": self.is_likely_malicious,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# PDF Parser
# ---------------------------------------------------------------------------

class PDFParser:
    """
    Low-level PDF parser that extracts objects, streams, and dictionary entries.
    Handles FlateDecode stream decompression and cross-reference table parsing.
    """

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._size = len(data)

    # ---- Top-level object scan ------------------------------------------

    def iter_objects(self) -> Iterator[PDFObject]:
        """
        Scan the raw PDF bytes for all indirect object definitions.
        Uses regex rather than following the xref table so we catch hidden objects
        that don't appear in the xref (a common evasion technique).
        """
        for m in OBJ_RE.finditer(self._data):
            obj_id = int(m.group(1))
            gen = int(m.group(2))
            start = m.end()

            # Find the matching "endobj"
            end_marker = self._data.find(b"endobj", start)
            if end_marker == -1:
                continue
            body = self._data[start:end_marker]

            obj = PDFObject(obj_id=obj_id, gen=gen)

            # Detect stream
            sm = STREAM_START_RE.search(body)
            if sm:
                dict_part = body[: sm.start()]
                stream_body = body[sm.end():]
                # Trim trailing endstream
                em = STREAM_END_RE.search(stream_body)
                if em:
                    stream_body = stream_body[: em.start()]
                obj.raw_dict = dict_part
                obj.raw_stream = stream_body
                obj.is_stream = True

                # Parse filters
                filters = self._extract_filters(dict_part)
                obj.stream_filters = filters

                # Decompress FlateDecode
                if "FlateDecode" in filters or "Fl" in filters:
                    try:
                        obj.decoded_stream = zlib.decompress(stream_body)
                    except zlib.error as e:
                        # Try wbits=-15 (raw deflate without zlib header)
                        try:
                            obj.decoded_stream = zlib.decompress(stream_body, -15)
                        except zlib.error:
                            obj.decoded_stream = b""
                elif not filters:
                    obj.decoded_stream = stream_body
            else:
                obj.raw_dict = body

            yield obj

    def _extract_filters(self, dict_bytes: bytes) -> List[str]:
        """Extract /Filter entries from a dictionary blob."""
        filters: List[str] = []
        # Single filter: /Filter /FlateDecode
        single = re.search(rb"/Filter\s+/(\w+)", dict_bytes)
        if single:
            filters.append(single.group(1).decode("latin-1"))
            return filters
        # Array: /Filter [/FlateDecode /ASCIIHexDecode]
        arr = re.search(rb"/Filter\s*\[([^\]]+)\]", dict_bytes)
        if arr:
            for tok in re.finditer(rb"/(\w+)", arr.group(1)):
                filters.append(tok.group(1).decode("latin-1"))
        return filters

    def parse_pdf_header(self) -> str:
        """Extract PDF version string."""
        m = PDF_HEADER_RE.search(self._data[:20])
        if m:
            return m.group(1).decode("ascii")
        return ""

    def count_eof_markers(self) -> int:
        return len(PDF_EOF_RE.findall(self._data))

    def extract_dict_value(self, dict_bytes: bytes, key: bytes) -> Optional[bytes]:
        """Return the raw value for a given /Key in a PDF dictionary."""
        pattern = re.compile(
            rb"/" + key + rb"\s*(?:/([\w]+)|(\d+)|(\(.*?\))|(<[0-9a-fA-F\s]*>)|\[([^\]]*)\])",
            re.DOTALL,
        )
        m = pattern.search(dict_bytes)
        if not m:
            return None
        for g in m.groups():
            if g is not None:
                return g
        return None

    def has_key(self, dict_bytes: bytes, key: bytes) -> bool:
        return bool(re.search(rb"/" + key + rb"[\s/\[(<]", dict_bytes))


# ---------------------------------------------------------------------------
# PDF Malware Analyzer
# ---------------------------------------------------------------------------

class PDFAnalyzer:
    """
    Static malware analyzer for PDF documents.

    Pipeline:
    1. Parse PDF header and count EOF markers (incremental updates).
    2. Enumerate all indirect objects via raw scan (catches hidden xref objects).
    3. For each stream object, decompress FlateDecode content.
    4. Extract JavaScript blocks from /JS, /OpenAction, /AA, /AcroForm actions.
    5. Detect embedded files via /EmbeddedFile and /Filespec entries.
    6. Score suspicious features using weighted sum, capped at 100.
    """

    # Entropy threshold above which a stream is considered obfuscated
    HIGH_ENTROPY_THRESHOLD = 7.2

    # Unusual number of streams in a simple document
    MANY_STREAMS_THRESHOLD = 50

    # Regex patterns for malicious JavaScript indicators
    JS_EVAL_RE = re.compile(r"\beval\s*\(|\bunescape\s*\(", re.IGNORECASE)
    SHELLCODE_RE = re.compile(
        r"(?:\\u0{1,2}[0-9a-fA-F]{2}){12,}"  # Unicode escape sled
        r"|(?:%[0-9a-fA-F]{2}){20,}"           # URL-encoded sled
        r"|(?:0x90){10,}",                      # NOP sled hex
        re.IGNORECASE,
    )

    def analyze(self, data: bytes) -> PDFAnalysisResult:
        """Analyze raw PDF bytes and return a full PDFAnalysisResult."""
        result = PDFAnalysisResult(file_size=len(data))
        parser = PDFParser(data)

        result.pdf_version = parser.parse_pdf_header()
        result.eof_count = parser.count_eof_markers()

        if result.eof_count > 1:
            self._add_feature(result, PDFSuspiciousFeature.INCREMENTAL_UPDATE,
                              f"{result.eof_count} %%EOF markers found")

        # Check for /Encrypt entry (quick scan)
        if b"/Encrypt" in data:
            self._add_feature(result, PDFSuspiciousFeature.ENCRYPTED_DOCUMENT,
                              "Document uses /Encrypt dictionary")

        # Enumerate all objects
        objects: List[PDFObject] = []
        try:
            for obj in parser.iter_objects():
                objects.append(obj)
        except Exception as e:
            result.errors.append(f"Object enumeration error: {e}")

        result.object_count = len(objects)
        result.stream_count = sum(1 for o in objects if o.is_stream)

        if result.stream_count > self.MANY_STREAMS_THRESHOLD:
            self._add_feature(result, PDFSuspiciousFeature.MANY_STREAMS,
                              f"{result.stream_count} streams (threshold {self.MANY_STREAMS_THRESHOLD})")

        # Page count heuristic (count /Page objects)
        result.page_count = sum(
            1 for o in objects
            if b"/Page" in o.raw_dict and b"/Pages" not in o.raw_dict
        )

        # Process each object
        for obj in objects:
            self._analyze_object(obj, result, parser)

        # Score
        result.risk_score = self._compute_risk_score(result)
        return result

    def analyze_file(self, path: str) -> PDFAnalysisResult:
        """Convenience: analyze a PDF file by path."""
        with open(path, "rb") as f:
            data = f.read()
        return self.analyze(data)

    # ---- Per-object analysis --------------------------------------------

    def _analyze_object(
        self, obj: PDFObject, result: PDFAnalysisResult, parser: PDFParser
    ) -> None:
        dict_bytes = obj.raw_dict

        # JavaScript in dict (e.g. /Action << /S /JavaScript /JS (...) >>)
        if parser.has_key(dict_bytes, b"JS") or parser.has_key(dict_bytes, b"JavaScript"):
            js_code = self._extract_js_from_object(obj, parser)
            if js_code:
                source = self._infer_js_source(dict_bytes, parser)
                js_block = JavaScriptBlock(
                    obj_id=obj.obj_id,
                    source_key=source,
                    code=js_code,
                    has_eval=bool(self.JS_EVAL_RE.search(js_code)),
                    has_unescape=bool(re.search(r"\bunescape\b", js_code, re.I)),
                )
                result.javascript_blocks.append(js_block)
                self._add_feature(result, PDFSuspiciousFeature.EMBEDDED_JAVASCRIPT,
                                  f"obj {obj.obj_id}: JS ({len(js_code)} chars)")
                if js_block.has_eval:
                    self._add_feature(result, PDFSuspiciousFeature.JAVASCRIPT_EVAL,
                                      f"obj {obj.obj_id}: eval/unescape in JS")
                if self.SHELLCODE_RE.search(js_code):
                    self._add_feature(result, PDFSuspiciousFeature.SHELLCODE_PATTERN,
                                      f"obj {obj.obj_id}: shellcode-like pattern in JS")

        # OpenAction at document level
        if parser.has_key(dict_bytes, b"OpenAction"):
            action_type = self._get_action_type(dict_bytes, parser)
            self._add_feature(result, PDFSuspiciousFeature.AUTO_OPEN_ACTION,
                              f"obj {obj.obj_id}: /OpenAction ({action_type})")

        # AA (Additional Actions) dict
        if parser.has_key(dict_bytes, b"AA"):
            self._add_feature(result, PDFSuspiciousFeature.AUTO_OPEN_ACTION,
                              f"obj {obj.obj_id}: /AA additional actions")

        # AcroForm with JavaScript
        if parser.has_key(dict_bytes, b"AcroForm"):
            if parser.has_key(dict_bytes, b"JS") or parser.has_key(dict_bytes, b"JavaScript"):
                self._add_feature(result, PDFSuspiciousFeature.ACROFORM_JAVASCRIPT,
                                  f"obj {obj.obj_id}: AcroForm with JavaScript")

        # Launch action
        if parser.has_key(dict_bytes, b"Launch"):
            self._add_feature(result, PDFSuspiciousFeature.LAUNCH_ACTION,
                              f"obj {obj.obj_id}: /Launch action")

        # URI action
        if parser.has_key(dict_bytes, b"URI"):
            uri_val = parser.extract_dict_value(dict_bytes, b"URI")
            self._add_feature(result, PDFSuspiciousFeature.URI_ACTION,
                              f"obj {obj.obj_id}: /URI action {uri_val!r:.60}")

        # Embedded files via /EmbeddedFile
        if parser.has_key(dict_bytes, b"EmbeddedFile") or parser.has_key(dict_bytes, b"Filespec"):
            ef = self._extract_embedded_file(obj, parser)
            if ef:
                result.embedded_files.append(ef)
                self._add_feature(result, PDFSuspiciousFeature.EMBEDDED_FILE,
                                  f"obj {obj.obj_id}: embedded file '{ef.filename}'")

        # EF (Embedded Files) dict key
        if parser.has_key(dict_bytes, b"EF"):
            ef = self._extract_embedded_file(obj, parser)
            if ef:
                result.embedded_files.append(ef)
                self._add_feature(result, PDFSuspiciousFeature.EMBEDDED_FILE,
                                  f"obj {obj.obj_id}: /EF embedded file '{ef.filename}'")

        # /Names obfuscation (Names array with JS)
        if parser.has_key(dict_bytes, b"Names"):
            content = obj.stream_text
            if "JavaScript" in content or "eval" in content.lower():
                self._add_feature(result, PDFSuspiciousFeature.SUSPICIOUS_NAMES,
                                  f"obj {obj.obj_id}: /Names with suspicious JavaScript content")

        # Stream entropy check:
        # Flag if high entropy AND either (a) has filters but failed to decode,
        # or (b) no filter at all (unencoded high-entropy bytes are suspicious).
        if obj.is_stream and obj.raw_stream:
            entropy = self._stream_entropy(obj.raw_stream)
            filtered_failed = bool(obj.stream_filters) and not obj.decoded_stream
            no_filter_suspicious = not obj.stream_filters
            if entropy >= self.HIGH_ENTROPY_THRESHOLD and (filtered_failed or no_filter_suspicious):
                self._add_feature(result, PDFSuspiciousFeature.OBFUSCATED_STREAM,
                                  f"obj {obj.obj_id}: high entropy stream ({entropy:.2f} bits)")

    # ---- JavaScript extraction ------------------------------------------

    def _extract_js_from_object(self, obj: PDFObject, parser: PDFParser) -> str:
        """Extract JavaScript code from an object's dictionary or stream."""
        # Try stream content first (most common: /Filter /FlateDecode stream)
        if obj.is_stream and obj.decoded_stream:
            return obj.decoded_stream.decode("latin-1", errors="replace")

        # Literal string value: /JS (code goes here)
        m = re.search(rb"/JS\s*\(([^)]*)\)", obj.raw_dict, re.DOTALL)
        if m:
            return m.group(1).decode("latin-1", errors="replace")

        # Hex string: /JS <48656c6c6f>
        m = re.search(rb"/JS\s*<([0-9a-fA-F\s]*)>", obj.raw_dict)
        if m:
            hex_str = re.sub(rb"\s+", b"", m.group(1))
            try:
                return bytes.fromhex(hex_str.decode()).decode("latin-1", errors="replace")
            except Exception:
                pass

        # Reference: /JS <obj_id> 0 R — we can't resolve cross-references in
        # a single-pass scan, so return empty here (caller may see it in streams)
        return ""

    def _infer_js_source(self, dict_bytes: bytes, parser: PDFParser) -> str:
        for key in [b"OpenAction", b"AA", b"AcroForm", b"Names"]:
            if parser.has_key(dict_bytes, key):
                return key.decode()
        return "JS"

    # ---- Action type extraction -----------------------------------------

    def _get_action_type(self, dict_bytes: bytes, parser: PDFParser) -> str:
        """Extract the /S (subtype) of an action dictionary."""
        m = re.search(rb"/S\s*/(\w+)", dict_bytes)
        if m:
            return m.group(1).decode("latin-1")
        return "unknown"

    # ---- Embedded file extraction ---------------------------------------

    def _extract_embedded_file(self, obj: PDFObject, parser: PDFParser) -> Optional[EmbeddedFile]:
        """Try to extract filename and data from an embedded file object."""
        dict_bytes = obj.raw_dict

        # /F or /UF key gives the filename
        filename = ""
        for key in (b"UF", b"F"):
            val = parser.extract_dict_value(dict_bytes, key)
            if val:
                try:
                    filename = val.decode("latin-1", errors="replace").strip("()")
                    break
                except Exception:
                    pass

        if not filename:
            filename = f"obj_{obj.obj_id}_embedded"

        # Size from /Params >> /Size or /Length
        size = 0
        size_m = re.search(rb"/Size\s+(\d+)", dict_bytes)
        if size_m:
            size = int(size_m.group(1))

        data = obj.decoded_stream or obj.raw_stream

        # MIME type from /Subtype
        mime_type = ""
        subtype_m = re.search(rb"/Subtype\s*/(\w+)", dict_bytes)
        if subtype_m:
            mime_type = subtype_m.group(1).decode("latin-1")

        return EmbeddedFile(
            obj_id=obj.obj_id,
            filename=filename,
            size=size or len(data),
            data=data,
            mime_type=mime_type,
        )

    # ---- Entropy ---------------------------------------------------------

    def _stream_entropy(self, data: bytes) -> float:
        """Shannon entropy of byte data in bits per byte."""
        if not data:
            return 0.0
        freq: Dict[int, int] = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    # ---- Feature management ---------------------------------------------

    def _add_feature(
        self,
        result: PDFAnalysisResult,
        feature: PDFSuspiciousFeature,
        detail: str = "",
    ) -> None:
        if feature not in result.features:
            result.features.append(feature)
        # Accumulate details
        existing = result.feature_details.get(feature.value, [])
        if detail and detail not in existing:
            if isinstance(existing, list):
                existing.append(detail)
            else:
                existing = [existing, detail]
            result.feature_details[feature.value] = existing

    # ---- Risk scoring ---------------------------------------------------

    def _compute_risk_score(self, result: PDFAnalysisResult) -> float:
        """
        Weighted sum of feature scores, capped at 100.

        The score is non-linear: later features add diminishing returns
        to prevent a single "hot" document from always hitting 100.
        We use a sigmoid-like accumulation.
        """
        raw_sum = sum(FEATURE_SCORES.get(f, 5) for f in result.features)

        # Apply diminishing returns via a saturation function
        # score = 100 * (1 - exp(-raw_sum / 80))
        score = 100.0 * (1.0 - math.exp(-raw_sum / 80.0))
        return min(100.0, round(score, 2))
