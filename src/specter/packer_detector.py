"""
Advanced PE packer detection engine.

Extends the basic signature scanning in pe_parser.py with multi-layered
heuristic analysis:

  - Entry-point anomaly detection (EP outside .text, EP in last section)
  - Section count / name / size-ratio heuristics
  - Import table sparsity (packed files import very few functions)
  - TLS callback detection (common in protected PE files)
  - Rich header presence / absence analysis
  - Per-section entropy classification with section-mix scoring
  - Byte-frequency chi-square analysis for near-uniform distributions
  - Known packer stub patterns beyond simple string matching

Each check contributes a weighted confidence score. The final
PackerAnalysisResult records every signal that fired, the most probable
packer family, and an overall packed_confidence in [0.0, 1.0].
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from specter.pe_parser import PEFile, PEParseError, PEParser, SectionHeader

# ---------------------------------------------------------------------------
# Entropy thresholds (consistent with entropy.py)
# ---------------------------------------------------------------------------
_ENT_ENCRYPTED = 7.2
_ENT_PACKED = 6.5
_ENT_CODE = 5.0

# ---------------------------------------------------------------------------
# Known section name sets for specific packers / protectors
# ---------------------------------------------------------------------------
_PACKER_SECTION_NAMES: Dict[str, List[str]] = {
    "UPX": [".upx0", ".upx1", ".upx2", "upx0", "upx1"],
    "MPRESS": ["mpress1", "mpress2"],
    "PECompact": [".pec1", ".pec2", "pec2"],
    "ASPack": [".aspack", ".adata"],
    "Themida": [".themida", ".winlice"],
    "VMProtect": [".vmp0", ".vmp1", ".vmp2"],
    "Obsidium": [".obsidium"],
    "Armadillo": [".shrink1", ".shrink2"],
    "Enigma": [".enigma1", ".enigma2"],
    "ExeStealth": [".pdata2"],
    "FSG": [".nsp0", ".nsp1", ".nsp2"],
    "NsPack": ["nsp0", "nsp1", "nsp2"],
    "PEtite": [".petite"],
    "WinUPack": [".header", ".rsrc"],  # WinUPack uses non-standard section layout
    "Crinkler": [".crinkler"],
    "Safengine": [".sdata", ".textbss"],
    "ConfuserEx": [".confuse"],
    "Hyperion": [".hyperion"],
    "PElock": [".pelock"],
}

# Minimum legitimate imports for an unpacked PE
_MIN_LEGIT_IMPORT_COUNT = 3

# Rich header magic that appears in most MSVC-compiled PEs
_RICH_SIGNATURE = b"Rich"
_DANS_SIGNATURE = b"DanS"


@dataclass
class PackerSignal:
    """A single heuristic signal that contributes to packer confidence."""

    name: str
    description: str
    confidence_contribution: float  # 0.0–1.0 partial contribution
    packer_hint: Optional[str] = None  # specific family if known


@dataclass
class PackerAnalysisResult:
    """Full packer/protector analysis result for a parsed PE file."""

    file_sha256: str
    packed_confidence: float          # aggregate packed confidence [0, 1]
    probable_packer: Optional[str]    # best-guess family name
    signals: List[PackerSignal] = field(default_factory=list)
    section_entropy_map: Dict[str, float] = field(default_factory=dict)
    entry_point_section: Optional[str] = None
    import_count: int = 0
    has_tls: bool = False
    has_rich_header: bool = False
    pe_checksum_valid: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_sha256": self.file_sha256,
            "packed_confidence": round(self.packed_confidence, 4),
            "probable_packer": self.probable_packer,
            "signals": [
                {
                    "name": s.name,
                    "description": s.description,
                    "confidence_contribution": round(s.confidence_contribution, 4),
                    "packer_hint": s.packer_hint,
                }
                for s in self.signals
            ],
            "section_entropy_map": {
                k: round(v, 4) for k, v in self.section_entropy_map.items()
            },
            "entry_point_section": self.entry_point_section,
            "import_count": self.import_count,
            "has_tls": self.has_tls,
            "has_rich_header": self.has_rich_header,
            "pe_checksum_valid": self.pe_checksum_valid,
        }

    @property
    def is_likely_packed(self) -> bool:
        return self.packed_confidence >= 0.5

    @property
    def summary(self) -> str:
        label = self.probable_packer or "unknown packer"
        status = "likely packed" if self.is_likely_packed else "probably clean"
        return (
            f"{status} (confidence={self.packed_confidence:.2f}, "
            f"packer={label}, signals={len(self.signals)})"
        )


# ---------------------------------------------------------------------------
# Rich Header analysis
# ---------------------------------------------------------------------------

def _has_rich_header(data: bytes) -> bool:
    """
    Detect the MSVC Rich header between the DOS stub and the PE header.
    Real compilers insert this; many packers strip or corrupt it.
    """
    # Rich header lives between offset 0x40 and the PE header
    if len(data) < 0x80:
        return False
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    search_end = min(e_lfanew, len(data))
    return _RICH_SIGNATURE in data[0x40:search_end]


def _validate_pe_checksum(data: bytes, stored_checksum: int) -> bool:
    """
    Compute the PE optional-header checksum and compare against stored value.
    A mismatch is suspicious (many manual PE modifications omit recalculation).
    Returns True if checksum is 0 (not set) or matches computed.
    """
    if stored_checksum == 0:
        return True  # 0 means not checked

    # Standard PE checksum algorithm
    checksum = 0
    remainder = len(data) % 4
    padded = data + b"\x00" * (4 - remainder) if remainder else data

    for i in range(0, len(padded), 4):
        val = struct.unpack_from("<I", padded, i)[0]
        checksum += val
        if checksum > 0xFFFFFFFF:
            checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)

    # Zero out the checksum field (OptionalHeader + 0x40 from start of optional header)
    # This is an approximation; full accuracy requires knowing the exact offset.
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum += checksum >> 16
    checksum = (checksum & 0xFFFF) + len(data)
    return (checksum & 0xFFFFFFFF) == stored_checksum


# ---------------------------------------------------------------------------
# Section analysis helpers
# ---------------------------------------------------------------------------

def _section_containing_ep(
    ep_rva: int, sections: List[SectionHeader]
) -> Optional[SectionHeader]:
    """Return the section that contains the entry-point RVA."""
    for sec in sections:
        end = sec.virtual_address + max(sec.virtual_size, sec.size_of_raw_data)
        if sec.virtual_address <= ep_rva < end:
            return sec
    return None


def _is_name_suspicious(name: str) -> bool:
    """Flag section names that deviate from normal PE conventions."""
    normal_names = {
        ".text", ".data", ".rdata", ".rsrc", ".reloc",
        ".bss", ".idata", ".edata", ".tls", ".pdata",
        ".debug", ".didat", ".sxdata", "CODE", "DATA",
        ".CRT", ".gfids", ".00cfg",
    }
    return name not in normal_names and not name.startswith(".")


def _size_ratio(section: SectionHeader) -> Optional[float]:
    """
    Virtual-to-raw size ratio. A high ratio (>8x) indicates the section
    expands significantly at runtime — typical of packed code stubs.
    """
    if section.size_of_raw_data == 0:
        return None
    return section.virtual_size / section.size_of_raw_data


# ---------------------------------------------------------------------------
# Byte frequency chi-square (uniform distribution = encrypted/compressed)
# ---------------------------------------------------------------------------

def _chi_square_uniformity(data: bytes) -> float:
    """
    Chi-square distance from a perfectly uniform byte distribution.
    Lower values → more uniform → more likely encrypted/random.
    """
    if len(data) < 256:
        return float("inf")

    freq = [0] * 256
    for b in data:
        freq[b] += 1

    expected = len(data) / 256.0
    chi_sq = sum((f - expected) ** 2 / expected for f in freq)
    return chi_sq


# ---------------------------------------------------------------------------
# TLS Directory detection
# ---------------------------------------------------------------------------

def _has_tls_directory(pe: PEFile) -> bool:
    """Check if the PE has a non-empty TLS directory (data directory index 9)."""
    dirs = pe.optional_header.data_directories
    if len(dirs) < 10:
        return False
    tls_rva, tls_size = dirs[9]
    return tls_rva != 0 and tls_size > 0


# ---------------------------------------------------------------------------
# Main analysis engine
# ---------------------------------------------------------------------------

class PackerDetector:
    """
    Multi-heuristic packer/protector detection engine for PE files.

    Usage:
        detector = PackerDetector()
        with open("sample.exe", "rb") as f:
            data = f.read()
        result = detector.analyze(data)
        print(result.summary)
    """

    # Signal weights — contributions are multiplied by these before summing
    _WEIGHT_SIGNATURE = 0.90        # named packer signature found
    _WEIGHT_SECTION_NAME = 0.85     # packer-named section found
    _WEIGHT_EP_LAST_SECTION = 0.65  # entry point in last section
    _WEIGHT_EP_HIGH_ENTROPY = 0.70  # entry-point section has high entropy
    _WEIGHT_EP_NOT_CODE = 0.50      # entry point in non-.text, non-code section
    _WEIGHT_NO_IMPORTS = 0.60       # very few imports (< 3 functions)
    _WEIGHT_HIGH_ENTROPY_EXEC = 0.55  # executable section has entropy > 6.5
    _WEIGHT_ALL_SECTIONS_HIGH = 0.80  # ALL sections have elevated entropy
    _WEIGHT_SIZE_RATIO = 0.40       # large virtual/raw size ratio
    _WEIGHT_NO_RICH = 0.25          # missing Rich header (stripped by packer)
    _WEIGHT_TLS_PRESENT = 0.30      # TLS directory (common in protectors)
    _WEIGHT_FEW_SECTIONS = 0.35     # very few sections (1-2) for an executable
    _WEIGHT_CHECKSUM_INVALID = 0.30 # PE checksum mismatch

    def analyze(self, data: bytes) -> PackerAnalysisResult:
        """
        Analyze raw PE bytes and return a PackerAnalysisResult.

        Raises PEParseError if the data is not a valid PE file.
        """
        parser = PEParser()
        pe = parser.parse(data)
        return self._analyze_pe(pe, data)

    def analyze_pe(self, pe: PEFile) -> PackerAnalysisResult:
        """Analyze an already-parsed PEFile object."""
        return self._analyze_pe(pe, pe.data)

    def _analyze_pe(self, pe: PEFile, data: bytes) -> PackerAnalysisResult:
        signals: List[PackerSignal] = []
        packer_votes: Dict[str, float] = {}

        # ----------------------------------------------------------------
        # 1. Known signature matches (from pe_parser) — highest weight
        # ----------------------------------------------------------------
        for packer in pe.detected_packers:
            if packer != "Unknown/Heuristic":
                sig = PackerSignal(
                    name="known_signature",
                    description=f"Known packer signature: {packer}",
                    confidence_contribution=self._WEIGHT_SIGNATURE,
                    packer_hint=packer,
                )
                signals.append(sig)
                packer_votes[packer] = packer_votes.get(packer, 0) + self._WEIGHT_SIGNATURE

        # ----------------------------------------------------------------
        # 2. Section name analysis
        # ----------------------------------------------------------------
        section_names_lower = [s.name.lower() for s in pe.sections]
        for packer_name, known_names in _PACKER_SECTION_NAMES.items():
            for sname in known_names:
                if sname in section_names_lower:
                    sig = PackerSignal(
                        name="packer_section_name",
                        description=f"Section name '{sname}' associated with {packer_name}",
                        confidence_contribution=self._WEIGHT_SECTION_NAME,
                        packer_hint=packer_name,
                    )
                    signals.append(sig)
                    packer_votes[packer_name] = (
                        packer_votes.get(packer_name, 0) + self._WEIGHT_SECTION_NAME
                    )
                    break  # one match per packer is enough

        # ----------------------------------------------------------------
        # 3. Entry point analysis
        # ----------------------------------------------------------------
        ep_rva = pe.optional_header.address_of_entry_point
        ep_section = _section_containing_ep(ep_rva, pe.sections)
        ep_section_name = ep_section.name if ep_section else None

        if ep_section and pe.sections:
            last_section = pe.sections[-1]

            # EP in last section
            if ep_section.name == last_section.name and len(pe.sections) > 1:
                signals.append(PackerSignal(
                    name="ep_in_last_section",
                    description=(
                        f"Entry point (RVA={ep_rva:#x}) is in the last section "
                        f"'{ep_section.name}' — common in packed executables"
                    ),
                    confidence_contribution=self._WEIGHT_EP_LAST_SECTION,
                ))

            # EP section has high entropy
            if ep_section.entropy >= _ENT_PACKED:
                signals.append(PackerSignal(
                    name="ep_section_high_entropy",
                    description=(
                        f"Entry-point section '{ep_section.name}' has entropy "
                        f"{ep_section.entropy:.2f} >= {_ENT_PACKED}"
                    ),
                    confidence_contribution=self._WEIGHT_EP_HIGH_ENTROPY,
                ))

            # EP not in a named code section
            if ep_section.name.lower() not in (".text", "code", ".code"):
                if not ep_section.is_executable:
                    signals.append(PackerSignal(
                        name="ep_not_in_code_section",
                        description=(
                            f"Entry point is in non-executable section '{ep_section.name}'"
                        ),
                        confidence_contribution=self._WEIGHT_EP_NOT_CODE,
                    ))

        # ----------------------------------------------------------------
        # 4. Import table sparsity
        # ----------------------------------------------------------------
        total_imports = sum(len(imp.functions) for imp in pe.imports)
        if not pe.is_dll and total_imports < _MIN_LEGIT_IMPORT_COUNT:
            signals.append(PackerSignal(
                name="sparse_import_table",
                description=(
                    f"Only {total_imports} imported functions — packed executables "
                    f"typically import just a loader stub"
                ),
                confidence_contribution=self._WEIGHT_NO_IMPORTS,
            ))

        # ----------------------------------------------------------------
        # 5. Section entropy mix
        # ----------------------------------------------------------------
        exec_sections = [s for s in pe.sections if s.is_executable]
        section_entropy_map = {s.name: s.entropy for s in pe.sections}

        high_entropy_exec = [s for s in exec_sections if s.entropy >= _ENT_PACKED]
        for sec in high_entropy_exec:
            signals.append(PackerSignal(
                name="high_entropy_executable_section",
                description=(
                    f"Executable section '{sec.name}' has entropy {sec.entropy:.2f}"
                ),
                confidence_contribution=self._WEIGHT_HIGH_ENTROPY_EXEC,
            ))

        # All sections elevated — entire file appears compressed
        if pe.sections and all(s.entropy >= _ENT_CODE for s in pe.sections if s.size_of_raw_data > 0):
            signals.append(PackerSignal(
                name="all_sections_elevated_entropy",
                description=(
                    "All PE sections have entropy >= {:.1f} — entire file appears packed".format(
                        _ENT_CODE
                    )
                ),
                confidence_contribution=self._WEIGHT_ALL_SECTIONS_HIGH,
            ))

        # ----------------------------------------------------------------
        # 6. Virtual / raw size ratio
        # ----------------------------------------------------------------
        for sec in pe.sections:
            ratio = _size_ratio(sec)
            if ratio is not None and ratio >= 8.0:
                signals.append(PackerSignal(
                    name="high_virtual_to_raw_ratio",
                    description=(
                        f"Section '{sec.name}' virtual/raw ratio={ratio:.1f}x "
                        f"(vsize={sec.virtual_size}, rawsize={sec.size_of_raw_data})"
                    ),
                    confidence_contribution=self._WEIGHT_SIZE_RATIO,
                ))

        # ----------------------------------------------------------------
        # 7. Rich header absence
        # ----------------------------------------------------------------
        has_rich = _has_rich_header(data)
        if not has_rich and not pe.is_dll:
            signals.append(PackerSignal(
                name="no_rich_header",
                description=(
                    "No MSVC Rich header found — stripped by packer or manually crafted PE"
                ),
                confidence_contribution=self._WEIGHT_NO_RICH,
            ))

        # ----------------------------------------------------------------
        # 8. TLS directory presence
        # ----------------------------------------------------------------
        has_tls = _has_tls_directory(pe)
        if has_tls:
            signals.append(PackerSignal(
                name="tls_callbacks_present",
                description=(
                    "TLS directory present — commonly used by protectors to run "
                    "pre-entry-point code (anti-debugging, decryption)"
                ),
                confidence_contribution=self._WEIGHT_TLS_PRESENT,
            ))

        # ----------------------------------------------------------------
        # 9. Section count heuristic
        # ----------------------------------------------------------------
        if not pe.is_dll and len(pe.sections) <= 2 and total_imports > 0:
            signals.append(PackerSignal(
                name="very_few_sections",
                description=(
                    f"Only {len(pe.sections)} section(s) — legitimate executables "
                    f"typically have 3+ sections"
                ),
                confidence_contribution=self._WEIGHT_FEW_SECTIONS,
            ))

        # ----------------------------------------------------------------
        # 10. PE checksum validation
        # ----------------------------------------------------------------
        stored_checksum = pe.optional_header.checksum
        checksum_valid = _validate_pe_checksum(data, stored_checksum)
        if not checksum_valid:
            signals.append(PackerSignal(
                name="checksum_mismatch",
                description=(
                    f"Stored PE checksum {stored_checksum:#010x} does not match computed "
                    "value — file may have been modified post-compilation"
                ),
                confidence_contribution=self._WEIGHT_CHECKSUM_INVALID,
            ))

        # ----------------------------------------------------------------
        # 11. Chi-square byte uniformity on largest section
        # ----------------------------------------------------------------
        largest_exec = max(
            (s for s in exec_sections if s.size_of_raw_data > 512),
            key=lambda s: s.size_of_raw_data,
            default=None,
        )
        if largest_exec and largest_exec.pointer_to_raw_data > 0:
            end = largest_exec.pointer_to_raw_data + largest_exec.size_of_raw_data
            sec_data = data[largest_exec.pointer_to_raw_data:end]
            if sec_data:
                chi = _chi_square_uniformity(sec_data)
                # Very low chi-square (< 300 for 100KB+) indicates near-uniform distribution
                if chi < 300 and len(sec_data) > 65536:
                    signals.append(PackerSignal(
                        name="near_uniform_byte_distribution",
                        description=(
                            f"Section '{largest_exec.name}' byte frequency chi-square={chi:.1f} "
                            f"— near-uniform distribution consistent with encrypted/compressed data"
                        ),
                        confidence_contribution=0.45,
                    ))

        # ----------------------------------------------------------------
        # Aggregate confidence score
        # ----------------------------------------------------------------
        packed_confidence = self._aggregate_confidence(signals)

        # Determine probable packer family
        probable_packer: Optional[str] = None
        if packer_votes:
            probable_packer = max(packer_votes, key=lambda k: packer_votes[k])
        elif packed_confidence >= 0.5:
            probable_packer = "Unknown"

        return PackerAnalysisResult(
            file_sha256=pe.sha256,
            packed_confidence=packed_confidence,
            probable_packer=probable_packer,
            signals=signals,
            section_entropy_map=section_entropy_map,
            entry_point_section=ep_section_name,
            import_count=total_imports,
            has_tls=has_tls,
            has_rich_header=has_rich,
            pe_checksum_valid=checksum_valid,
        )

    @staticmethod
    def _aggregate_confidence(signals: List[PackerSignal]) -> float:
        """
        Combine individual signal contributions using a diminishing-returns
        formula so stacking weak signals never overwhelms strong negatives.

        Formula: 1 - product(1 - c_i) for all signal contributions c_i
        This is the probability-union model: each signal independently
        raises the probability of being packed.
        """
        if not signals:
            return 0.0

        prob_not_packed = 1.0
        for sig in signals:
            c = max(0.0, min(1.0, sig.confidence_contribution))
            prob_not_packed *= (1.0 - c)

        return round(1.0 - prob_not_packed, 6)
