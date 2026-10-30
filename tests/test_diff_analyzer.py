"""
Tests for the differential analysis engine.

Uses synthetic minimal PE-shaped byte sequences to validate diff logic
without requiring real malware samples.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from specter.diff_analyzer import (
    BehavioralDelta,
    DiffAnalyzer,
    DiffReport,
    HeaderDelta,
    ImportDelta,
    SectionDelta,
    StringDelta,
)
from specter.models import Severity


# ---------------------------------------------------------------------------
# Helpers to build mock PEAnalysisResult objects
# ---------------------------------------------------------------------------

def _make_header(
    machine: str = "AMD64",
    subsystem: str = "WINDOWS_GUI",
    timestamp: int = 1700000000,
    entry_point: int = 0x1000,
    image_base: int = 0x400000,
    is_dll: bool = False,
    characteristics: Optional[List[str]] = None,
) -> MagicMock:
    h = MagicMock()
    h.machine = machine
    h.subsystem = subsystem
    h.timestamp = timestamp
    h.address_of_entry_point = entry_point
    h.image_base = image_base
    h.is_dll = is_dll
    h.characteristics = characteristics or ["EXECUTABLE_IMAGE"]
    return h


def _make_section(
    name: str,
    raw_offset: int = 0x1000,
    raw_size: int = 0x200,
    characteristics: Optional[List[str]] = None,
) -> MagicMock:
    s = MagicMock()
    s.name = name
    s.raw_data_offset = raw_offset
    s.raw_data_size = raw_size
    s.characteristics_flags = characteristics or ["READ", "EXECUTE"]
    return s


def _make_import_entry(dll: str, funcs: List[str]) -> MagicMock:
    entry = MagicMock()
    entry.dll_name = dll
    func_mocks = []
    for f in funcs:
        fm = MagicMock()
        fm.name = f
        fm.ordinal_str = ""
        func_mocks.append(fm)
    entry.functions = func_mocks
    return entry


def _make_result(
    header=None,
    sections=None,
    imports=None,
    detected_packers=None,
    behavioral_indicators=None,
) -> MagicMock:
    r = MagicMock()
    r.header = header or _make_header()
    r.sections = sections or []
    r.imports = imports or []
    r.detected_packers = detected_packers or []
    r.behavioral_indicators = behavioral_indicators or []
    return r


# ---------------------------------------------------------------------------
# Unit tests for individual delta components
# ---------------------------------------------------------------------------

class TestSectionDelta:
    def test_entropy_delta(self):
        d = SectionDelta(
            name=".text", status="modified",
            entropy_a=5.0, entropy_b=7.5,
        )
        assert abs(d.entropy_delta - 2.5) < 1e-9

    def test_size_delta(self):
        d = SectionDelta(name=".data", status="modified", size_a=512, size_b=1024)
        assert d.size_delta == 512

    def test_to_dict_contains_keys(self):
        d = SectionDelta(
            name=".text", status="unchanged",
            entropy_a=5.0, entropy_b=5.1,
            size_a=0x200, size_b=0x200,
        )
        dd = d.to_dict()
        assert dd["name"] == ".text"
        assert dd["status"] == "unchanged"
        assert "entropy_delta" in dd


class TestImportDelta:
    def test_total_added_removed(self):
        d = ImportDelta(
            added_dlls=["new.dll"],
            removed_dlls=[],
            added_imports={"new.dll": ["Func1", "Func2"]},
            removed_imports={},
        )
        assert d.total_added == 2
        assert d.total_removed == 0

    def test_to_dict(self):
        d = ImportDelta(
            added_dlls=["new.dll"],
            removed_dlls=["old.dll"],
            common_dlls=["kernel32.dll"],
        )
        dd = d.to_dict()
        assert "kernel32.dll" in dd["common_dlls"]


class TestStringDelta:
    def test_jaccard_all_common(self):
        d = StringDelta(added=[], removed=[], common=["a", "b", "c"])
        assert d.jaccard == 1.0

    def test_jaccard_no_overlap(self):
        d = StringDelta(added=["x"], removed=["y"], common=[])
        assert d.jaccard == 0.0

    def test_jaccard_partial(self):
        d = StringDelta(added=["new"], removed=[], common=["shared"])
        # union = 1 + 0 + 1 = 2, common = 1
        assert abs(d.jaccard - 0.5) < 1e-9

    def test_to_dict_counts(self):
        d = StringDelta(
            added=["a", "b"],
            removed=["c"],
            common=["d", "e", "f"],
        )
        dd = d.to_dict()
        assert dd["added_count"] == 2
        assert dd["removed_count"] == 1
        assert dd["common_count"] == 3


class TestHeaderDelta:
    def test_machine_changed(self):
        h = HeaderDelta(machine_a="i386", machine_b="AMD64")
        assert h.machine_changed

    def test_machine_unchanged(self):
        h = HeaderDelta(machine_a="AMD64", machine_b="AMD64")
        assert not h.machine_changed

    def test_to_dict_structure(self):
        h = HeaderDelta(
            machine_a="AMD64", machine_b="AMD64",
            entry_point_a=0x1000, entry_point_b=0x2000,
        )
        dd = h.to_dict()
        assert "machine" in dd
        assert dd["machine"]["changed"] is False
        assert "entry_point" in dd


# ---------------------------------------------------------------------------
# Integration tests via mocked parser
# ---------------------------------------------------------------------------

class TestDiffAnalyzer:
    """
    Integration tests that mock out PEParser to avoid needing real PE files,
    while still exercising the full diff pipeline.
    """

    def _make_analyzer(self) -> DiffAnalyzer:
        return DiffAnalyzer()

    def test_identical_samples_high_similarity(self):
        data = b"MZ" + b"\x00" * 256
        analyzer = self._make_analyzer()
        with patch.object(analyzer, "_safe_parse", return_value=_make_result()) as _, \
             patch.object(analyzer, "_diff_strings",
                          return_value=StringDelta(added=[], removed=[], common=["str1", "str2"])):
            report = analyzer.compare(data, data, "same.exe", "same.exe")
        assert report.sha256_a == report.sha256_b

    def test_section_added_detected(self):
        analyzer = self._make_analyzer()
        r_a = _make_result(sections=[_make_section(".text")])
        r_b = _make_result(sections=[
            _make_section(".text"),
            _make_section(".newpack"),
        ])
        data_stub = b"MZ" + b"\x00" * 0x2000
        with patch.object(analyzer, "_safe_parse", side_effect=[r_a, r_b]), \
             patch.object(analyzer._entropy, "analyze_section",
                          return_value=MagicMock(entropy=6.8)):
            report = analyzer.compare(data_stub, data_stub)
        statuses = {s.name: s.status for s in report.sections}
        assert ".newpack" in statuses
        assert statuses[".newpack"] == "added"
        assert statuses[".text"] in ("unchanged", "modified")

    def test_section_removed_detected(self):
        analyzer = self._make_analyzer()
        r_a = _make_result(sections=[
            _make_section(".text"),
            _make_section(".rsrc"),
        ])
        r_b = _make_result(sections=[_make_section(".text")])
        data_stub = b"MZ" + b"\x00" * 0x2000
        with patch.object(analyzer, "_safe_parse", side_effect=[r_a, r_b]), \
             patch.object(analyzer._entropy, "analyze_section",
                          return_value=MagicMock(entropy=5.0)):
            report = analyzer.compare(data_stub, data_stub)
        statuses = {s.name: s.status for s in report.sections}
        assert statuses[".rsrc"] == "removed"

    def test_import_delta_new_dll(self):
        analyzer = self._make_analyzer()
        r_a = _make_result(imports=[
            _make_import_entry("kernel32.dll", ["CreateFile", "ReadFile"]),
        ])
        r_b = _make_result(imports=[
            _make_import_entry("kernel32.dll", ["CreateFile", "ReadFile"]),
            _make_import_entry("wininet.dll", ["InternetOpen", "InternetConnect"]),
        ])
        data_stub = b"MZ" + b"\x00" * 100
        with patch.object(analyzer, "_safe_parse", side_effect=[r_a, r_b]), \
             patch.object(analyzer, "_diff_strings",
                          return_value=StringDelta()):
            report = analyzer.compare(data_stub, data_stub)
        assert "wininet.dll" in report.imports.added_dlls
        assert report.imports.total_added == 2

    def test_import_delta_removed_api(self):
        analyzer = self._make_analyzer()
        r_a = _make_result(imports=[
            _make_import_entry("kernel32.dll", ["CreateFile", "DeleteFile"]),
        ])
        r_b = _make_result(imports=[
            _make_import_entry("kernel32.dll", ["CreateFile"]),
        ])
        data_stub = b"MZ" + b"\x00" * 100
        with patch.object(analyzer, "_safe_parse", side_effect=[r_a, r_b]), \
             patch.object(analyzer, "_diff_strings",
                          return_value=StringDelta()):
            report = analyzer.compare(data_stub, data_stub)
        assert "DeleteFile" in report.imports.removed_imports.get("kernel32.dll", [])

    def test_behavioral_delta(self):
        analyzer = self._make_analyzer()
        r_a = _make_result(behavioral_indicators=["process_injection", "registry_persistence"])
        r_b = _make_result(behavioral_indicators=["registry_persistence", "network_c2"])
        data_stub = b"MZ" + b"\x00" * 100
        with patch.object(analyzer, "_safe_parse", side_effect=[r_a, r_b]), \
             patch.object(analyzer, "_diff_strings",
                          return_value=StringDelta()):
            report = analyzer.compare(data_stub, data_stub)
        assert "network_c2" in report.behavioral.added_indicators
        assert "process_injection" in report.behavioral.removed_indicators
        assert "registry_persistence" in report.behavioral.common_indicators

    def test_verdict_near_identical(self):
        assert "near-identical" in DiffAnalyzer._verdict(95)

    def test_verdict_distinct(self):
        assert "distinct" in DiffAnalyzer._verdict(10)

    def test_verdict_moderate(self):
        assert "similar" in DiffAnalyzer._verdict(60)

    def test_diff_report_to_dict_structure(self):
        report = DiffReport(
            sha256_a="aaa", sha256_b="bbb",
            file_name_a="a.exe", file_name_b="b.exe",
            file_size_a=1000, file_size_b=2000,
            similarity_score=72.5,
            verdict="highly similar",
        )
        d = report.to_dict()
        assert "samples" in d
        assert "similarity_score" in d
        assert d["samples"]["a"]["sha256"] == "aaa"
        assert d["samples"]["b"]["size"] == 2000

    def test_header_score_full_similarity(self):
        h = HeaderDelta(
            machine_a="AMD64", machine_b="AMD64",
            subsystem_a="GUI", subsystem_b="GUI",
            is_dll_a=False, is_dll_b=False,
            characteristics_added=[], characteristics_removed=[],
        )
        score = DiffAnalyzer._score_header(h)
        assert score == 1.0

    def test_header_score_machine_changed(self):
        h = HeaderDelta(machine_a="i386", machine_b="AMD64")
        score = DiffAnalyzer._score_header(h)
        assert score < 1.0

    def test_section_score_all_unchanged(self):
        sections = [
            SectionDelta(name=".text", status="unchanged"),
            SectionDelta(name=".data", status="unchanged"),
        ]
        score = DiffAnalyzer._score_sections(sections)
        assert score == 1.0

    def test_section_score_all_added(self):
        sections = [
            SectionDelta(name=".new1", status="added"),
            SectionDelta(name=".new2", status="added"),
        ]
        score = DiffAnalyzer._score_sections(sections)
        assert score == 0.0

    def test_import_score_identical(self):
        imp = ImportDelta(
            common_dlls=["k32.dll"],
            common_imports={"k32.dll": ["CreateFile"]},
        )
        score = DiffAnalyzer._score_imports(imp)
        assert score == 1.0
