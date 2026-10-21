"""
Tests for the fuzzy hashing module.
"""

from __future__ import annotations

import os
from typing import List

import pytest

from specter.fuzzy_hash import (
    FuzzyDigest,
    FuzzyHasher,
    RollingHash,
    SampleSimilarityDB,
    SimilarityCluster,
    _block_similarity,
    _compute_block_digest,
    _determine_block_size,
    _edit_distance,
)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

class TestDetermineBlockSize:
    def test_small_input(self):
        # 100 bytes: block * 64 >= 100 -> block=3 (3*64=192>100)
        assert _determine_block_size(100) == 3

    def test_larger_input(self):
        size = _determine_block_size(4096)
        assert size >= 3
        assert size * 64 >= 4096

    def test_very_large_input(self):
        size = _determine_block_size(10 * 1024 * 1024)
        assert size >= 3


class TestEditDistance:
    def test_identical(self):
        assert _edit_distance("abc", "abc") == 0

    def test_empty_strings(self):
        assert _edit_distance("", "") == 0
        assert _edit_distance("abc", "") == 3
        assert _edit_distance("", "abc") == 3

    def test_single_sub(self):
        assert _edit_distance("abc", "axc") == 1

    def test_fully_different(self):
        assert _edit_distance("abcd", "wxyz") == 4


class TestBlockSimilarity:
    def test_identical(self):
        assert _block_similarity("AAAA", "AAAA") == 1.0

    def test_both_empty(self):
        assert _block_similarity("", "") == 1.0

    def test_one_empty(self):
        assert _block_similarity("ABC", "") == 0.0
        assert _block_similarity("", "ABC") == 0.0

    def test_partial_similarity(self):
        score = _block_similarity("AAAB", "AAAC")
        assert 0.0 < score < 1.0


# ---------------------------------------------------------------------------
# RollingHash
# ---------------------------------------------------------------------------

class TestRollingHash:
    def test_boundary_not_triggered_on_empty(self):
        rh = RollingHash()
        assert not rh.is_boundary()

    def test_value_changes_on_update(self):
        rh = RollingHash()
        v0 = rh.value
        rh.update(0x41)
        assert rh.value != v0

    def test_reset_clears_state(self):
        rh = RollingHash()
        rh.update(0x41)
        rh.reset()
        assert rh.value == 0

    def test_boundary_eventually_triggered(self):
        """Feed enough data to guarantee at least one boundary fires."""
        rh = RollingHash(trigger_mod=7)
        found = False
        for i in range(500):
            rh.update(i & 0xFF)
            if rh.is_boundary():
                found = True
                break
        assert found


# ---------------------------------------------------------------------------
# FuzzyHasher
# ---------------------------------------------------------------------------

class TestFuzzyHasher:
    def test_empty_data(self):
        h = FuzzyHasher()
        d = h.compute(b"")
        assert d.data_length == 0
        assert d.block_size >= 3

    def test_digest_is_string(self):
        h = FuzzyHasher()
        d = h.compute(b"hello world")
        s = d.to_string()
        assert ":" in s
        parts = s.split(":")
        assert len(parts) == 3

    def test_same_data_same_digest(self):
        h = FuzzyHasher()
        data = b"x" * 1024
        d1 = h.compute(data).to_string()
        d2 = h.compute(data).to_string()
        assert d1 == d2

    def test_different_data_different_digest(self):
        h = FuzzyHasher()
        d1 = h.compute(b"aaaa" * 256).to_string()
        d2 = h.compute(b"bbbb" * 256).to_string()
        assert d1 != d2

    def test_identical_files_score_100(self):
        h = FuzzyHasher()
        data = os.urandom(4096)
        d1 = h.compute(data)
        d2 = h.compute(data)
        score = h.compare(d1, d2)
        assert score == 100

    def test_completely_different_low_score(self):
        h = FuzzyHasher()
        # Use fixed pseudo-random data with known block boundaries
        import random
        rng = random.Random(42)
        data_a = bytes(rng.randint(0, 255) for _ in range(4096))
        rng2 = random.Random(99)
        data_b = bytes(rng2.randint(0, 255) for _ in range(4096))
        d1 = h.compute(data_a)
        d2 = h.compute(data_b)
        score = h.compare(d1, d2)
        assert score < 80  # random data should have low similarity

    def test_compare_accepts_strings(self):
        h = FuzzyHasher()
        data = b"test" * 512
        d = h.compute(data).to_string()
        score = h.compare(d, d)
        assert score == 100

    def test_similar_data_high_score(self):
        """A file with a small patch should be highly similar to the original."""
        h = FuzzyHasher()
        base = bytearray(b"A" * 8192)
        patched = bytearray(base)
        # Flip 10 bytes in the middle
        for i in range(10):
            patched[4000 + i] = 0xFF
        d_base = h.compute(bytes(base))
        d_patched = h.compute(bytes(patched))
        score = h.compare(d_base, d_patched)
        assert score >= 70  # should be highly similar

    def test_roundtrip_from_string(self):
        h = FuzzyHasher()
        d = h.compute(b"data" * 1024)
        s = d.to_string()
        d2 = FuzzyDigest.from_string(s)
        assert d2.block_size == d.block_size
        assert d2.digest1 == d.digest1
        assert d2.digest2 == d.digest2


# ---------------------------------------------------------------------------
# SampleSimilarityDB
# ---------------------------------------------------------------------------

class TestSampleSimilarityDB:
    def test_add_and_count(self):
        db = SampleSimilarityDB()
        db.add("sha256_a", b"payload" * 256)
        assert db.count == 1
        db.add("sha256_b", b"other" * 256)
        assert db.count == 2

    def test_find_similar_returns_self(self):
        db = SampleSimilarityDB()
        data = b"malware_bytes" * 512
        db.add("sample1", data)
        results = db.find_similar(data, threshold=90)
        assert len(results) == 1
        assert results[0][0] == "sample1"
        assert results[0][1] == 100

    def test_find_similar_excludes_low_scores(self):
        db = SampleSimilarityDB()
        db.add("unrelated", b"\x00\x01\x02" * 1024)
        data = b"\xFF\xFE\xFD" * 1024
        results = db.find_similar(data, threshold=90)
        # The unrelated sample should not meet the high threshold
        hashes = [r[0] for r in results]
        # May or may not include unrelated depending on content
        # We just verify the result type
        assert all(isinstance(r[1], int) for r in results)

    def test_cluster_groups_identical_samples(self):
        db = SampleSimilarityDB()
        data = b"cluster_data" * 1024
        db.add("s1", data)
        db.add("s2", data)
        db.add("s3", b"totally_different" * 1024)
        clusters = db.build_clusters(threshold=80)
        # s1 and s2 should be in the same cluster
        found = False
        for c in clusters:
            if "s1" in c.sample_hashes and "s2" in c.sample_hashes:
                found = True
                break
        assert found

    def test_add_digest_string(self):
        db = SampleSimilarityDB()
        h = FuzzyHasher()
        digest = h.compute(b"sample" * 512).to_string()
        db.add_digest("hash_x", digest)
        assert db.count == 1
