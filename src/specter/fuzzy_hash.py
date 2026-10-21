"""
Fuzzy hashing module for malware similarity detection.

Implements a content-defined chunking hash (ssdeep-style) that produces a
comparable digest string, and a similarity scoring function based on
edit distance of the digest blocks.

The algorithm:
  1. Determine an initial block size from the input length so the output
     digest is roughly 64 characters per block.
  2. Make two passes: one at block_size and one at block_size*2.
  3. Each pass accumulates a rolling Adler-32 checksum; when it reaches
     a trigger value the current digest character is emitted and the
     accumulator resets.
  4. The two block digests are joined as "<bsize>:<digest1>:<digest2>".
  5. Similarity: split both digests, score each block pair with a
     normalized edit distance, combine.
"""

from __future__ import annotations

import math
import string
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

# Base64 alphabet used for digest characters
_B64 = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"
_B64_LEN = len(_B64)  # 64

# Minimum block size (bytes)
_MIN_BLOCK = 3
# Target digest length per block
_TARGET_DIGEST_LEN = 64
# Rolling hash modulus trigger
_TRIGGER_MOD = 67  # prime close to 64; determines chunk boundaries


# ---------------------------------------------------------------------------
# Rolling hash
# ---------------------------------------------------------------------------

class RollingHash:
    """
    Adler-32-style rolling accumulator used to detect chunk boundaries.

    Two accumulators (s1, s2) are maintained over a sliding window of
    length `window`. When `s1 % trigger_mod == trigger_mod - 1` a chunk
    boundary is signalled.
    """

    __slots__ = ("_s1", "_s2", "_window", "_buf", "_pos", "_trigger")

    def __init__(self, window: int = 7, trigger_mod: int = _TRIGGER_MOD) -> None:
        self._s1 = 0
        self._s2 = 0
        self._window = window
        self._buf = bytearray(window)
        self._pos = 0
        self._trigger = trigger_mod

    def reset(self) -> None:
        self._s1 = 0
        self._s2 = 0
        self._buf = bytearray(self._window)
        self._pos = 0

    def update(self, byte: int) -> None:
        outgoing = self._buf[self._pos % self._window]
        self._buf[self._pos % self._window] = byte
        self._pos += 1
        self._s1 = (self._s1 - outgoing + byte) & 0xFFFFFFFF
        self._s2 = (self._s2 - self._window * outgoing + self._s1) & 0xFFFFFFFF

    @property
    def value(self) -> int:
        return (self._s1 + self._s2 * 31) & 0xFFFFFFFF

    def is_boundary(self) -> bool:
        return self.value % self._trigger == self._trigger - 1


# ---------------------------------------------------------------------------
# Core digest computation
# ---------------------------------------------------------------------------

def _determine_block_size(data_len: int) -> int:
    """
    Choose the smallest power-of-two block size >= _MIN_BLOCK such that
    the expected digest length is at most _TARGET_DIGEST_LEN characters.
    """
    block = _MIN_BLOCK
    while block * _TARGET_DIGEST_LEN < data_len:
        block *= 2
    return max(block, _MIN_BLOCK)


def _compute_block_digest(data: bytes | bytearray, block_size: int) -> str:
    """
    Produce a digest string for `data` using the given block_size.

    A new digest character is emitted whenever the rolling hash signals a
    boundary OR when `block_size` bytes have been consumed without one,
    ensuring the digest is never empty even for small inputs.
    """
    rh = RollingHash(window=min(7, block_size))
    digest_chars: List[str] = []
    h = 0  # FNV-1a running hash for the current block
    FNV_PRIME = 0x01000193
    FNV_OFFSET = 0x811C9DC5
    byte_in_block = 0

    for byte in data:
        # FNV-1a over current block
        h = ((h ^ byte) * FNV_PRIME) & 0xFFFFFFFF
        rh.update(byte)
        byte_in_block += 1

        if rh.is_boundary() or byte_in_block >= block_size:
            digest_chars.append(_B64[h % _B64_LEN])
            h = FNV_OFFSET
            byte_in_block = 0
            rh.reset()

    # Flush any remaining bytes
    if byte_in_block > 0:
        digest_chars.append(_B64[h % _B64_LEN])

    return "".join(digest_chars) if digest_chars else _B64[0]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class FuzzyDigest:
    block_size: int
    digest1: str   # computed at block_size
    digest2: str   # computed at block_size * 2
    data_length: int

    def to_string(self) -> str:
        return f"{self.block_size}:{self.digest1}:{self.digest2}"

    @classmethod
    def from_string(cls, s: str) -> "FuzzyDigest":
        parts = s.split(":")
        if len(parts) != 3:
            raise ValueError(f"Invalid fuzzy digest string: {s!r}")
        return cls(
            block_size=int(parts[0]),
            digest1=parts[1],
            digest2=parts[2],
            data_length=0,
        )


def _edit_distance(a: str, b: str) -> int:
    """
    Wagner-Fischer dynamic programming edit distance between two strings.
    """
    if not a:
        return len(b)
    if not b:
        return len(a)
    m, n = len(a), len(b)
    # Use two-row DP to save memory
    prev = list(range(n + 1))
    curr = [0] * (n + 1)
    for i in range(1, m + 1):
        curr[0] = i
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                curr[j] = prev[j - 1]
            else:
                curr[j] = 1 + min(prev[j - 1], prev[j], curr[j - 1])
        prev, curr = curr, prev
    return prev[n]


def _block_similarity(d1: str, d2: str) -> float:
    """
    Return a 0.0–1.0 similarity score for two digest block strings
    using normalised edit distance.
    """
    if not d1 and not d2:
        return 1.0
    if not d1 or not d2:
        return 0.0
    max_len = max(len(d1), len(d2))
    ed = _edit_distance(d1, d2)
    return max(0.0, 1.0 - ed / max_len)


@dataclass
class SimilarityCluster:
    """A group of samples whose fuzzy digests are mutually similar."""

    cluster_id: int
    sample_hashes: List[str]   # SHA-256 / MD5 hashes identifying each sample
    min_similarity: float
    avg_similarity: float

    @property
    def size(self) -> int:
        return len(self.sample_hashes)


class FuzzyHasher:
    """
    Computes and compares fuzzy (ssdeep-style) hashes of binary data.

    Usage::

        hasher = FuzzyHasher()
        digest = hasher.compute(data)
        score  = hasher.compare(digest_a, digest_b)  # 0-100
    """

    def compute(self, data: bytes | bytearray) -> FuzzyDigest:
        """Compute the fuzzy digest for a blob of binary data."""
        if not data:
            return FuzzyDigest(
                block_size=_MIN_BLOCK,
                digest1=_B64[0],
                digest2=_B64[0],
                data_length=0,
            )
        block_size = _determine_block_size(len(data))
        digest1 = _compute_block_digest(data, block_size)
        digest2 = _compute_block_digest(data, block_size * 2)
        return FuzzyDigest(
            block_size=block_size,
            digest1=digest1,
            digest2=digest2,
            data_length=len(data),
        )

    def compare(self, a: str | FuzzyDigest, b: str | FuzzyDigest) -> int:
        """
        Return a similarity score in [0, 100] between two fuzzy digests.

        Scoring:
        - If block sizes are incompatible (neither pair matches) returns 0.
        - Compares digest1 blocks when sizes match, or digest2 of the
          smaller against digest1 of the larger (2x relationship).
        - Returns 0–100 integer.
        """
        if isinstance(a, str):
            a = FuzzyDigest.from_string(a)
        if isinstance(b, str):
            b = FuzzyDigest.from_string(b)

        scores: List[float] = []

        # Same block size: compare digest1 vs digest1, digest2 vs digest2
        if a.block_size == b.block_size:
            scores.append(_block_similarity(a.digest1, b.digest1))
            scores.append(_block_similarity(a.digest2, b.digest2))

        # 2x relationship: a.digest2 vs b.digest1
        if a.block_size * 2 == b.block_size:
            scores.append(_block_similarity(a.digest2, b.digest1))

        # 2x relationship: b.digest2 vs a.digest1
        if b.block_size * 2 == a.block_size:
            scores.append(_block_similarity(b.digest2, a.digest1))

        if not scores:
            return 0

        return round(max(scores) * 100)

    def cluster(
        self,
        samples: Dict[str, str | FuzzyDigest],
        threshold: int = 60,
    ) -> List[SimilarityCluster]:
        """
        Cluster samples by fuzzy similarity.

        Args:
            samples: mapping of sample_id -> fuzzy digest string or FuzzyDigest
            threshold: minimum similarity score (0-100) to link two samples

        Returns:
            List of SimilarityCluster objects, largest first.
        """
        ids = list(samples.keys())
        digests: List[FuzzyDigest] = []
        for sid in ids:
            d = samples[sid]
            if isinstance(d, str):
                d = FuzzyDigest.from_string(d)
            digests.append(d)

        # Union-Find
        parent = list(range(len(ids)))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: int, b: int) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        # Build pairwise similarity matrix and union similar samples
        pairwise: Dict[Tuple[int, int], int] = {}
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                score = self.compare(digests[i], digests[j])
                pairwise[(i, j)] = score
                if score >= threshold:
                    union(i, j)

        # Collect groups
        from collections import defaultdict
        groups: Dict[int, List[int]] = defaultdict(list)
        for i in range(len(ids)):
            groups[find(i)].append(i)

        clusters: List[SimilarityCluster] = []
        for cluster_root, members in groups.items():
            if len(members) < 2:
                continue
            # Compute avg/min similarity within cluster
            pair_scores: List[int] = []
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    mi, mj = members[i], members[j]
                    key = (min(mi, mj), max(mi, mj))
                    pair_scores.append(pairwise.get(key, self.compare(digests[mi], digests[mj])))
            clusters.append(SimilarityCluster(
                cluster_id=cluster_root,
                sample_hashes=[ids[m] for m in members],
                min_similarity=min(pair_scores) / 100.0,
                avg_similarity=sum(pair_scores) / len(pair_scores) / 100.0,
            ))

        return sorted(clusters, key=lambda c: c.size, reverse=True)


class SampleSimilarityDB:
    """
    In-memory registry mapping sample hashes to their fuzzy digests,
    enabling fast similarity lookups against a growing corpus.
    """

    def __init__(self) -> None:
        self._hasher = FuzzyHasher()
        self._store: Dict[str, FuzzyDigest] = {}  # sample_hash -> digest

    def add(self, sample_hash: str, data: bytes) -> FuzzyDigest:
        """Compute and store the fuzzy digest for a sample."""
        digest = self._hasher.compute(data)
        self._store[sample_hash] = digest
        return digest

    def add_digest(self, sample_hash: str, digest: FuzzyDigest | str) -> None:
        """Store a pre-computed digest."""
        if isinstance(digest, str):
            digest = FuzzyDigest.from_string(digest)
        self._store[sample_hash] = digest

    def find_similar(
        self,
        query: bytes | FuzzyDigest | str,
        threshold: int = 60,
        max_results: int = 20,
    ) -> List[Tuple[str, int]]:
        """
        Return (sample_hash, score) pairs for all stored digests
        that score >= threshold against `query`.
        """
        if isinstance(query, (bytes, bytearray)):
            query_digest = self._hasher.compute(query)
        elif isinstance(query, str):
            query_digest = FuzzyDigest.from_string(query)
        else:
            query_digest = query

        results: List[Tuple[str, int]] = []
        for sample_hash, stored in self._store.items():
            score = self._hasher.compare(query_digest, stored)
            if score >= threshold:
                results.append((sample_hash, score))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:max_results]

    def build_clusters(self, threshold: int = 60) -> List[SimilarityCluster]:
        """Cluster all stored samples by similarity."""
        digest_map = {k: v for k, v in self._store.items()}
        return self._hasher.cluster(digest_map, threshold=threshold)

    @property
    def count(self) -> int:
        return len(self._store)
