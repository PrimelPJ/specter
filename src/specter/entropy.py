"""
Entropy analysis for binary file sections.
Provides Shannon entropy calculation with visualization-friendly binning
and heuristic classification of regions.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class EntropyBin:
    """A window of bytes with its computed entropy value."""
    offset: int
    size: int
    entropy: float
    classification: str  # plaintext | compressed | encrypted | code | data


@dataclass
class SectionEntropyResult:
    name: str
    offset: int
    size: int
    entropy: float
    bins: List[EntropyBin] = field(default_factory=list)
    is_packed: bool = False
    is_encrypted: bool = False
    has_low_entropy_regions: bool = False

    @property
    def classification(self) -> str:
        if self.entropy > 7.2:
            return "encrypted/compressed"
        if self.entropy > 6.5:
            return "packed"
        if self.entropy > 5.0:
            return "compiled_code"
        if self.entropy > 3.5:
            return "text_data"
        return "plaintext"


class EntropyAnalyzer:
    """
    Computes Shannon entropy across binary data with sliding window analysis.

    Uses windowed analysis to detect:
    - Encrypted/compressed regions (entropy > 7.2)
    - Packed sections (entropy 6.5-7.2)
    - Compiled code (entropy 5.0-6.5)
    - Text/data (entropy 3.5-5.0)
    - Plaintext/padding (entropy < 3.5)
    """

    # Entropy thresholds
    ENCRYPTED_THRESHOLD = 7.2
    PACKED_THRESHOLD = 6.5
    CODE_THRESHOLD = 5.0
    TEXT_THRESHOLD = 3.5

    def __init__(self, window_size: int = 256, step_size: int = 64) -> None:
        if window_size < 16:
            raise ValueError("Window size must be at least 16")
        if step_size < 1:
            raise ValueError("Step size must be at least 1")
        if step_size > window_size:
            raise ValueError("Step size cannot exceed window size")
        self.window_size = window_size
        self.step_size = step_size

    def analyze_section(
        self,
        name: str,
        data: bytes,
        file_offset: int = 0,
    ) -> SectionEntropyResult:
        """Analyze entropy of a PE section or arbitrary data region."""
        if not data:
            return SectionEntropyResult(name=name, offset=file_offset, size=0, entropy=0.0)

        overall_entropy = self.shannon_entropy(data)
        bins = self._windowed_analysis(data, file_offset)

        is_packed = overall_entropy > self.PACKED_THRESHOLD
        is_encrypted = overall_entropy > self.ENCRYPTED_THRESHOLD
        has_low = any(b.entropy < self.TEXT_THRESHOLD for b in bins)

        return SectionEntropyResult(
            name=name,
            offset=file_offset,
            size=len(data),
            entropy=overall_entropy,
            bins=bins,
            is_packed=is_packed,
            is_encrypted=is_encrypted,
            has_low_entropy_regions=has_low,
        )

    def analyze_file(
        self, data: bytes, chunk_size: int = 4096
    ) -> Tuple[float, List[EntropyBin]]:
        """Compute overall file entropy and per-chunk breakdown."""
        overall = self.shannon_entropy(data)
        bins = []
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            e = self.shannon_entropy(chunk)
            bins.append(EntropyBin(
                offset=i,
                size=len(chunk),
                entropy=e,
                classification=self._classify_entropy(e),
            ))
        return overall, bins

    def find_high_entropy_regions(
        self,
        data: bytes,
        threshold: float = 7.0,
        min_region_size: int = 256,
    ) -> List[Tuple[int, int, float]]:
        """
        Find contiguous high-entropy regions.
        Returns list of (start_offset, end_offset, avg_entropy).
        """
        regions: List[Tuple[int, int, float]] = []
        in_region = False
        region_start = 0
        region_entropies: List[float] = []

        step = max(16, self.window_size // 4)
        for i in range(0, len(data) - self.window_size + 1, step):
            window = data[i:i + self.window_size]
            e = self.shannon_entropy(window)
            if e >= threshold:
                if not in_region:
                    in_region = True
                    region_start = i
                    region_entropies = []
                region_entropies.append(e)
            else:
                if in_region:
                    region_end = i + self.window_size
                    region_size = region_end - region_start
                    if region_size >= min_region_size:
                        avg_e = sum(region_entropies) / len(region_entropies)
                        regions.append((region_start, region_end, avg_e))
                    in_region = False

        if in_region:
            region_end = len(data)
            region_size = region_end - region_start
            if region_size >= min_region_size and region_entropies:
                avg_e = sum(region_entropies) / len(region_entropies)
                regions.append((region_start, region_end, avg_e))

        return regions

    def detect_compression(self, data: bytes) -> Tuple[bool, float, str]:
        """
        Heuristic detection of compression/encryption.
        Returns (is_compressed, entropy, method_hint).
        """
        if len(data) < 64:
            return False, 0.0, "too_small"

        entropy = self.shannon_entropy(data)

        # Check magic bytes for known compression formats
        magic_map = {
            b"\x1f\x8b": "gzip",
            b"BZh": "bzip2",
            b"\xfd7zXZ\x00": "xz",
            b"PK\x03\x04": "zip",
            b"MZ": "pe_exe",
            b"\x7fELF": "elf",
            b"\xfe\xed\xfa\xcf": "macho64",
            b"\xfe\xed\xfa\xce": "macho32",
        }
        for magic, fmt in magic_map.items():
            if data.startswith(magic):
                return entropy > 6.0, entropy, fmt

        if entropy > self.ENCRYPTED_THRESHOLD:
            return True, entropy, "encrypted_or_compressed"
        if entropy > self.PACKED_THRESHOLD:
            return True, entropy, "likely_packed"

        return False, entropy, "raw_data"

    def byte_frequency_analysis(self, data: bytes) -> dict:
        """
        Analyze byte frequency distribution.
        High chi-square distance from uniform indicates encrypted data.
        """
        freq = [0] * 256
        for b in data:
            freq[b] += 1

        n = len(data)
        if n == 0:
            return {"chi_square": 0.0, "entropy": 0.0, "zero_bytes": 0, "printable_ratio": 0.0}

        expected = n / 256.0
        chi_sq = sum((f - expected) ** 2 / expected for f in freq if expected > 0)

        printable = sum(freq[i] for i in range(0x20, 0x7F))
        zero_bytes = freq[0]

        return {
            "chi_square": round(chi_sq, 2),
            "entropy": self.shannon_entropy(data),
            "zero_bytes": zero_bytes,
            "zero_ratio": round(zero_bytes / n, 4),
            "printable_ratio": round(printable / n, 4),
            "unique_bytes": sum(1 for f in freq if f > 0),
        }

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        """Compute Shannon entropy (bits per byte) of a byte sequence."""
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        entropy = 0.0
        for count in freq:
            if count:
                p = count / n
                entropy -= p * math.log2(p)
        return round(entropy, 6)

    def _windowed_analysis(
        self, data: bytes, file_offset: int
    ) -> List[EntropyBin]:
        bins = []
        for i in range(0, len(data), self.step_size):
            window = data[i:i + self.window_size]
            if len(window) < 8:
                break
            e = self.shannon_entropy(window)
            bins.append(EntropyBin(
                offset=file_offset + i,
                size=len(window),
                entropy=e,
                classification=self._classify_entropy(e),
            ))
        return bins

    def _classify_entropy(self, entropy: float) -> str:
        if entropy > self.ENCRYPTED_THRESHOLD:
            return "encrypted"
        if entropy > self.PACKED_THRESHOLD:
            return "compressed"
        if entropy > self.CODE_THRESHOLD:
            return "code"
        if entropy > self.TEXT_THRESHOLD:
            return "data"
        return "plaintext"
