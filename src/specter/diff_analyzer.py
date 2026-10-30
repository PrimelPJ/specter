"""
Differential analysis engine for comparing two malware samples.

Produces a structured delta report covering:
  - PE header differences (architecture, timestamps, characteristics)
  - Section table changes (added, removed, resized, entropy shifts)
  - Import table delta (new/removed DLLs and API calls)
  - String delta (new, removed, and common strings with category breakdown)
  - Entropy profile comparison (per-section and overall)
  - Behavioral indicator diff
  - Composite similarity score (0–100)
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from specter.entropy import EntropyAnalyzer
from specter.pe_parser import PEParser, PEAnalysisResult
from specter.string_extractor import StringExtractor, ExtractedString, StringCategory
from specter.import_analyzer import ImportAnalyzer


# ---------------------------------------------------------------------------
# Delta data-classes
# ---------------------------------------------------------------------------

@dataclass
class SectionDelta:
    """Describes how a single section changed between two samples."""
    name: str
    status: str          # added | removed | modified | unchanged
    entropy_a: Optional[float] = None
    entropy_b: Optional[float] = None
    size_a: Optional[int] = None
    size_b: Optional[int] = None
    characteristics_a: Optional[str] = None
    characteristics_b: Optional[str] = None

    @property
    def entropy_delta(self) -> Optional[float]:
        if self.entropy_a is not None and self.entropy_b is not None:
            return self.entropy_b - self.entropy_a
        return None

    @property
    def size_delta(self) -> Optional[int]:
        if self.size_a is not None and self.size_b is not None:
            return self.size_b - self.size_a
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "entropy_a": self.entropy_a,
            "entropy_b": self.entropy_b,
            "entropy_delta": self.entropy_delta,
            "size_a": self.size_a,
            "size_b": self.size_b,
            "size_delta": self.size_delta,
            "characteristics_a": self.characteristics_a,
            "characteristics_b": self.characteristics_b,
        }


@dataclass
class ImportDelta:
    """Describes import table changes between two samples."""
    added_dlls: List[str] = field(default_factory=list)
    removed_dlls: List[str] = field(default_factory=list)
    common_dlls: List[str] = field(default_factory=list)
    added_imports: Dict[str, List[str]] = field(default_factory=dict)   # dll -> [funcs]
    removed_imports: Dict[str, List[str]] = field(default_factory=dict)
    common_imports: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def total_added(self) -> int:
        return sum(len(v) for v in self.added_imports.values())

    @property
    def total_removed(self) -> int:
        return sum(len(v) for v in self.removed_imports.values())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "added_dlls": self.added_dlls,
            "removed_dlls": self.removed_dlls,
            "common_dlls": self.common_dlls,
            "added_imports_count": self.total_added,
            "removed_imports_count": self.total_removed,
            "added_imports": self.added_imports,
            "removed_imports": self.removed_imports,
        }


@dataclass
class StringDelta:
    """String-level differences between two samples."""
    added: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    common: List[str] = field(default_factory=list)
    # category breakdown
    added_by_category: Dict[str, List[str]] = field(default_factory=dict)
    removed_by_category: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def jaccard(self) -> float:
        """Jaccard similarity on the string sets."""
        union = len(self.added) + len(self.removed) + len(self.common)
        if union == 0:
            return 1.0
        return len(self.common) / union

    def to_dict(self) -> Dict[str, Any]:
        return {
            "added_count": len(self.added),
            "removed_count": len(self.removed),
            "common_count": len(self.common),
            "jaccard_similarity": round(self.jaccard, 4),
            "added_by_category": {k: len(v) for k, v in self.added_by_category.items()},
            "removed_by_category": {k: len(v) for k, v in self.removed_by_category.items()},
            "added_samples": self.added[:20],
            "removed_samples": self.removed[:20],
        }


@dataclass
class HeaderDelta:
    """Differences in PE header fields."""
    machine_a: str = ""
    machine_b: str = ""
    subsystem_a: str = ""
    subsystem_b: str = ""
    timestamp_a: int = 0
    timestamp_b: int = 0
    entry_point_a: int = 0
    entry_point_b: int = 0
    image_base_a: int = 0
    image_base_b: int = 0
    characteristics_added: List[str] = field(default_factory=list)
    characteristics_removed: List[str] = field(default_factory=list)
    is_dll_a: bool = False
    is_dll_b: bool = False
    packer_a: List[str] = field(default_factory=list)
    packer_b: List[str] = field(default_factory=list)

    @property
    def machine_changed(self) -> bool:
        return self.machine_a != self.machine_b

    @property
    def subsystem_changed(self) -> bool:
        return self.subsystem_a != self.subsystem_b

    @property
    def is_dll_changed(self) -> bool:
        return self.is_dll_a != self.is_dll_b

    def to_dict(self) -> Dict[str, Any]:
        return {
            "machine": {"a": self.machine_a, "b": self.machine_b, "changed": self.machine_changed},
            "subsystem": {"a": self.subsystem_a, "b": self.subsystem_b, "changed": self.subsystem_changed},
            "timestamp": {"a": self.timestamp_a, "b": self.timestamp_b},
            "entry_point": {"a": hex(self.entry_point_a), "b": hex(self.entry_point_b)},
            "image_base": {"a": hex(self.image_base_a), "b": hex(self.image_base_b)},
            "is_dll": {"a": self.is_dll_a, "b": self.is_dll_b, "changed": self.is_dll_changed},
            "characteristics_added": self.characteristics_added,
            "characteristics_removed": self.characteristics_removed,
            "packer": {"a": self.packer_a, "b": self.packer_b},
        }


@dataclass
class BehavioralDelta:
    """Differences in extracted behavioral indicators."""
    added_indicators: List[str] = field(default_factory=list)
    removed_indicators: List[str] = field(default_factory=list)
    common_indicators: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "added": self.added_indicators,
            "removed": self.removed_indicators,
            "common": self.common_indicators,
        }


@dataclass
class DiffReport:
    """
    Complete differential analysis report for two PE samples.

    All sub-reports are independently queryable.  The composite
    *similarity_score* (0–100) summarises overall structural closeness.
    """

    sha256_a: str
    sha256_b: str
    file_name_a: str
    file_name_b: str
    file_size_a: int
    file_size_b: int

    header: HeaderDelta = field(default_factory=HeaderDelta)
    sections: List[SectionDelta] = field(default_factory=list)
    imports: ImportDelta = field(default_factory=ImportDelta)
    strings: StringDelta = field(default_factory=StringDelta)
    behavioral: BehavioralDelta = field(default_factory=BehavioralDelta)

    # Overall similarity score 0–100
    similarity_score: float = 0.0
    # Analyst-readable verdict
    verdict: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "samples": {
                "a": {"sha256": self.sha256_a, "file_name": self.file_name_a, "size": self.file_size_a},
                "b": {"sha256": self.sha256_b, "file_name": self.file_name_b, "size": self.file_size_b},
            },
            "similarity_score": round(self.similarity_score, 2),
            "verdict": self.verdict,
            "header": self.header.to_dict(),
            "sections": [s.to_dict() for s in self.sections],
            "imports": self.imports.to_dict(),
            "strings": self.strings.to_dict(),
            "behavioral": self.behavioral.to_dict(),
        }


# ---------------------------------------------------------------------------
# Differential analyzer
# ---------------------------------------------------------------------------

class DiffAnalyzer:
    """
    Compares two PE binary samples and produces a DiffReport.

    Usage::

        analyzer = DiffAnalyzer()
        with open("sample_a.exe", "rb") as f:
            data_a = f.read()
        with open("sample_b.exe", "rb") as f:
            data_b = f.read()
        report = analyzer.compare(data_a, data_b, name_a="v1.exe", name_b="v2.exe")
        print(report.similarity_score)
    """

    # Weights for the composite similarity score
    _WEIGHT_HEADER = 0.15
    _WEIGHT_SECTIONS = 0.25
    _WEIGHT_IMPORTS = 0.30
    _WEIGHT_STRINGS = 0.20
    _WEIGHT_BEHAVIORAL = 0.10

    def __init__(
        self,
        entropy_window: int = 256,
        min_string_len: int = 5,
    ) -> None:
        self._pe_parser = PEParser()
        self._entropy = EntropyAnalyzer(window_size=entropy_window)
        self._string_extractor = StringExtractor(min_length=min_string_len)
        self._import_analyzer = ImportAnalyzer()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def compare(
        self,
        data_a: bytes,
        data_b: bytes,
        name_a: str = "sample_a",
        name_b: str = "sample_b",
    ) -> DiffReport:
        """
        Perform full differential analysis of two PE binaries.

        Args:
            data_a: Raw bytes of the first (baseline) sample.
            data_b: Raw bytes of the second (variant) sample.
            name_a: Display name for the baseline sample.
            name_b: Display name for the variant sample.

        Returns:
            A :class:`DiffReport` with all sub-deltas populated.
        """
        import hashlib

        sha256_a = hashlib.sha256(data_a).hexdigest()
        sha256_b = hashlib.sha256(data_b).hexdigest()

        report = DiffReport(
            sha256_a=sha256_a,
            sha256_b=sha256_b,
            file_name_a=name_a,
            file_name_b=name_b,
            file_size_a=len(data_a),
            file_size_b=len(data_b),
        )

        # Parse both samples (graceful: non-PE data yields empty results)
        result_a = self._safe_parse(data_a)
        result_b = self._safe_parse(data_b)

        report.header = self._diff_headers(result_a, result_b, data_a, data_b)
        report.sections = self._diff_sections(result_a, result_b, data_a, data_b)
        report.imports = self._diff_imports(result_a, result_b)
        report.strings = self._diff_strings(data_a, data_b)
        report.behavioral = self._diff_behavioral(result_a, result_b)
        report.similarity_score = self._compute_similarity(report)
        report.verdict = self._verdict(report.similarity_score)

        return report

    # ------------------------------------------------------------------
    # Header diff
    # ------------------------------------------------------------------

    def _diff_headers(
        self,
        r_a: Optional["PEAnalysisResult"],
        r_b: Optional["PEAnalysisResult"],
        data_a: bytes,
        data_b: bytes,
    ) -> HeaderDelta:
        delta = HeaderDelta()
        if r_a is None or r_b is None:
            return delta

        h_a = r_a.header
        h_b = r_b.header
        if h_a is None or h_b is None:
            return delta

        delta.machine_a = getattr(h_a, "machine", "")
        delta.machine_b = getattr(h_b, "machine", "")
        delta.subsystem_a = getattr(h_a, "subsystem", "")
        delta.subsystem_b = getattr(h_b, "subsystem", "")
        delta.timestamp_a = getattr(h_a, "timestamp", 0)
        delta.timestamp_b = getattr(h_b, "timestamp", 0)
        delta.entry_point_a = getattr(h_a, "address_of_entry_point", 0)
        delta.entry_point_b = getattr(h_b, "address_of_entry_point", 0)
        delta.image_base_a = getattr(h_a, "image_base", 0)
        delta.image_base_b = getattr(h_b, "image_base", 0)
        delta.is_dll_a = getattr(h_a, "is_dll", False)
        delta.is_dll_b = getattr(h_b, "is_dll", False)
        delta.packer_a = getattr(r_a, "detected_packers", [])
        delta.packer_b = getattr(r_b, "detected_packers", [])

        chars_a: Set[str] = set(getattr(h_a, "characteristics", []) or [])
        chars_b: Set[str] = set(getattr(h_b, "characteristics", []) or [])
        delta.characteristics_added = sorted(chars_b - chars_a)
        delta.characteristics_removed = sorted(chars_a - chars_b)

        return delta

    # ------------------------------------------------------------------
    # Section diff
    # ------------------------------------------------------------------

    def _diff_sections(
        self,
        r_a: Optional["PEAnalysisResult"],
        r_b: Optional["PEAnalysisResult"],
        data_a: bytes,
        data_b: bytes,
    ) -> List[SectionDelta]:
        sections_a = self._extract_sections(r_a, data_a)
        sections_b = self._extract_sections(r_b, data_b)

        names_a = set(sections_a.keys())
        names_b = set(sections_b.keys())

        deltas: List[SectionDelta] = []

        for name in sorted(names_a | names_b):
            if name in names_a and name not in names_b:
                sec = sections_a[name]
                deltas.append(SectionDelta(
                    name=name, status="removed",
                    entropy_a=sec["entropy"], size_a=sec["size"],
                    characteristics_a=sec["characteristics"],
                ))
            elif name not in names_a and name in names_b:
                sec = sections_b[name]
                deltas.append(SectionDelta(
                    name=name, status="added",
                    entropy_b=sec["entropy"], size_b=sec["size"],
                    characteristics_b=sec["characteristics"],
                ))
            else:
                sec_a = sections_a[name]
                sec_b = sections_b[name]
                entropy_changed = abs((sec_a["entropy"] or 0) - (sec_b["entropy"] or 0)) > 0.1
                size_changed = sec_a["size"] != sec_b["size"]
                chars_changed = sec_a["characteristics"] != sec_b["characteristics"]
                status = "modified" if (entropy_changed or size_changed or chars_changed) else "unchanged"
                deltas.append(SectionDelta(
                    name=name, status=status,
                    entropy_a=sec_a["entropy"], entropy_b=sec_b["entropy"],
                    size_a=sec_a["size"], size_b=sec_b["size"],
                    characteristics_a=sec_a["characteristics"],
                    characteristics_b=sec_b["characteristics"],
                ))

        return deltas

    def _extract_sections(
        self,
        result: Optional["PEAnalysisResult"],
        data: bytes,
    ) -> Dict[str, Dict[str, Any]]:
        if result is None:
            return {}
        sections: Dict[str, Dict[str, Any]] = {}
        for sec in getattr(result, "sections", []) or []:
            name = getattr(sec, "name", "").strip("\x00")
            raw_offset = getattr(sec, "raw_data_offset", 0)
            raw_size = getattr(sec, "raw_data_size", 0)
            entropy: Optional[float] = None
            if raw_size > 0 and raw_offset + raw_size <= len(data):
                section_bytes = data[raw_offset: raw_offset + raw_size]
                er = self._entropy.analyze_section(name, section_bytes, raw_offset)
                entropy = er.entropy
            characteristics = getattr(sec, "characteristics_flags", None)
            if isinstance(characteristics, list):
                characteristics = "|".join(sorted(characteristics))
            elif characteristics is not None:
                characteristics = str(characteristics)
            sections[name] = {
                "entropy": entropy,
                "size": raw_size,
                "characteristics": characteristics,
            }
        return sections

    # ------------------------------------------------------------------
    # Import diff
    # ------------------------------------------------------------------

    def _diff_imports(
        self,
        r_a: Optional["PEAnalysisResult"],
        r_b: Optional["PEAnalysisResult"],
    ) -> ImportDelta:
        imports_a = self._flatten_imports(r_a)
        imports_b = self._flatten_imports(r_b)

        dlls_a = set(imports_a.keys())
        dlls_b = set(imports_b.keys())

        delta = ImportDelta(
            added_dlls=sorted(dlls_b - dlls_a),
            removed_dlls=sorted(dlls_a - dlls_b),
            common_dlls=sorted(dlls_a & dlls_b),
        )

        for dll in dlls_a | dlls_b:
            funcs_a: Set[str] = set(imports_a.get(dll, []))
            funcs_b: Set[str] = set(imports_b.get(dll, []))
            added = sorted(funcs_b - funcs_a)
            removed = sorted(funcs_a - funcs_b)
            common = sorted(funcs_a & funcs_b)
            if added:
                delta.added_imports[dll] = added
            if removed:
                delta.removed_imports[dll] = removed
            if common:
                delta.common_imports[dll] = common

        return delta

    @staticmethod
    def _flatten_imports(
        result: Optional["PEAnalysisResult"],
    ) -> Dict[str, List[str]]:
        """Return {dll_name: [function_names]} from a PEAnalysisResult."""
        if result is None:
            return {}
        imports: Dict[str, List[str]] = {}
        for entry in getattr(result, "imports", []) or []:
            dll = getattr(entry, "dll_name", "").lower()
            funcs = [
                getattr(f, "name", "") or getattr(f, "ordinal_str", "")
                for f in (getattr(entry, "functions", []) or [])
            ]
            imports[dll] = funcs
        return imports

    # ------------------------------------------------------------------
    # String diff
    # ------------------------------------------------------------------

    def _diff_strings(self, data_a: bytes, data_b: bytes) -> StringDelta:
        strings_a = self._extract_string_set(data_a)
        strings_b = self._extract_string_set(data_b)

        added_set = strings_b - strings_a
        removed_set = strings_a - strings_b
        common_set = strings_a & strings_b

        # Re-extract with categories for added/removed breakdown
        cat_a = self._extract_strings_with_categories(data_a)
        cat_b = self._extract_strings_with_categories(data_b)

        added_by_cat: Dict[str, List[str]] = {}
        removed_by_cat: Dict[str, List[str]] = {}

        for val, cat in cat_b.items():
            if val in added_set:
                added_by_cat.setdefault(cat, []).append(val)

        for val, cat in cat_a.items():
            if val in removed_set:
                removed_by_cat.setdefault(cat, []).append(val)

        return StringDelta(
            added=sorted(added_set),
            removed=sorted(removed_set),
            common=sorted(common_set),
            added_by_category=added_by_cat,
            removed_by_category=removed_by_cat,
        )

    def _extract_string_set(self, data: bytes) -> FrozenSet[str]:
        try:
            strings = self._string_extractor.extract(data)
            return frozenset(s.value for s in strings)
        except Exception:
            return frozenset()

    def _extract_strings_with_categories(self, data: bytes) -> Dict[str, str]:
        try:
            strings = self._string_extractor.extract(data)
            return {s.value: s.category.value for s in strings}
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Behavioral diff
    # ------------------------------------------------------------------

    def _diff_behavioral(
        self,
        r_a: Optional["PEAnalysisResult"],
        r_b: Optional["PEAnalysisResult"],
    ) -> BehavioralDelta:
        indicators_a: Set[str] = set(getattr(r_a, "behavioral_indicators", []) or [])
        indicators_b: Set[str] = set(getattr(r_b, "behavioral_indicators", []) or [])
        return BehavioralDelta(
            added_indicators=sorted(indicators_b - indicators_a),
            removed_indicators=sorted(indicators_a - indicators_b),
            common_indicators=sorted(indicators_a & indicators_b),
        )

    # ------------------------------------------------------------------
    # Similarity scoring
    # ------------------------------------------------------------------

    def _compute_similarity(self, report: DiffReport) -> float:
        """
        Weighted composite similarity score in [0, 100].

        Each dimension is independently scored 0–1 then combined using
        the pre-defined weight vector.
        """
        header_sim = self._score_header(report.header)
        section_sim = self._score_sections(report.sections)
        import_sim = self._score_imports(report.imports)
        string_sim = report.strings.jaccard
        behavioral_sim = self._score_behavioral(report.behavioral)

        composite = (
            self._WEIGHT_HEADER * header_sim
            + self._WEIGHT_SECTIONS * section_sim
            + self._WEIGHT_IMPORTS * import_sim
            + self._WEIGHT_STRINGS * string_sim
            + self._WEIGHT_BEHAVIORAL * behavioral_sim
        )
        return min(100.0, max(0.0, composite * 100.0))

    @staticmethod
    def _score_header(h: HeaderDelta) -> float:
        """Header similarity: 1.0 if nothing changed, penalty per difference."""
        penalty = 0.0
        if h.machine_changed:
            penalty += 0.4
        if h.subsystem_changed:
            penalty += 0.2
        if h.is_dll_changed:
            penalty += 0.2
        n_char_changes = len(h.characteristics_added) + len(h.characteristics_removed)
        penalty += min(0.2, n_char_changes * 0.05)
        return max(0.0, 1.0 - penalty)

    @staticmethod
    def _score_sections(sections: List[SectionDelta]) -> float:
        """Section similarity based on fraction of unchanged sections."""
        if not sections:
            return 1.0
        total = len(sections)
        unchanged = sum(1 for s in sections if s.status == "unchanged")
        modified = sum(1 for s in sections if s.status == "modified")
        # partial credit for modified sections
        score = (unchanged + 0.5 * modified) / total
        return min(1.0, max(0.0, score))

    @staticmethod
    def _score_imports(imp: ImportDelta) -> float:
        """Import similarity: Jaccard over the full import API set."""
        all_dlls = len(imp.added_dlls) + len(imp.removed_dlls) + len(imp.common_dlls)
        if all_dlls == 0:
            return 1.0
        dll_jaccard = len(imp.common_dlls) / all_dlls
        total_common = sum(len(v) for v in imp.common_imports.values())
        total_added = imp.total_added
        total_removed = imp.total_removed
        all_funcs = total_added + total_removed + total_common
        if all_funcs == 0:
            return dll_jaccard
        func_jaccard = total_common / all_funcs
        return 0.4 * dll_jaccard + 0.6 * func_jaccard

    @staticmethod
    def _score_behavioral(b: BehavioralDelta) -> float:
        total = len(b.added_indicators) + len(b.removed_indicators) + len(b.common_indicators)
        if total == 0:
            return 1.0
        return len(b.common_indicators) / total

    @staticmethod
    def _verdict(score: float) -> str:
        if score >= 90:
            return "near-identical: likely same malware family, minor variant"
        if score >= 70:
            return "highly similar: probable same family with functional modifications"
        if score >= 50:
            return "moderately similar: possible same campaign or shared codebase"
        if score >= 25:
            return "low similarity: different samples, possibly related toolkit"
        return "distinct: unrelated samples or completely rewritten code"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _safe_parse(self, data: bytes) -> Optional["PEAnalysisResult"]:
        """Parse a PE binary, returning None on parse errors."""
        try:
            return self._pe_parser.analyze(data)
        except Exception:
            return None
