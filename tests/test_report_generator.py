"""
Tests for the analysis report generator.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List
from unittest.mock import MagicMock

import pytest

from specter.behavioral import BehaviorCategory
from specter.report_generator import AnalysisReport, ReportGenerator, RiskScorer


# ---------------------------------------------------------------------------
# Helpers — minimal mock objects so tests don’t require fully built PE/PE files
# ---------------------------------------------------------------------------

def _mock_yara_match(rule_name: str = "TestRule") -> MagicMock:
    m = MagicMock()
    m.rule_name = rule_name
    m.namespace = "default"
    m.tags = ["malware"]
    m.meta = {"author": "test"}
    m.strings = [("$s1", 0x100, b"MALWARE")]
    return m


def _mock_behavior(categories: list | None = None) -> MagicMock:
    categories = categories or [BehaviorCategory.PROCESS_INJECTION]
    indicators = []
    for cat in categories:
        ind = MagicMock()
        ind.category = cat
        ind.description = f"Detected {cat.value}"
        ind.severity = "high"
        ind.evidence = []
        indicators.append(ind)
    b = MagicMock()
    b.risk_level = "high"
    b.indicators = indicators
    b.summary = "Suspicious behavior detected."
    return b


def _mock_classification(
    family: str = "trojan",
    threat_level: str = "high",
    confidence: float = 0.9,
) -> MagicMock:
    from specter.sample_db import MalwareFamily, ThreatLevel
    c = MagicMock()
    c.family = MagicMock(value=family)
    c.threat_level = MagicMock(value=threat_level)
    c.confidence = confidence
    c.matched_rules = ["rule_a"]
    c.behavioral_indicators = ["inject"]
    c.notes = "Matches trojan family"
    return c


def _mock_network(count: int = 3) -> MagicMock:
    indicators = []
    for i in range(count):
        ind = MagicMock()
        ind.indicator_type = MagicMock(value="ipv4")
        ind.value = f"1.2.3.{i}"
        ind.context = "connect"
        ind.confidence = 0.9
        indicators.append(ind)
    n = MagicMock()
    n.total_count = count
    n.indicators = indicators
    return n


def _mock_entropy_sections(values: list) -> list:
    sections = []
    for name, entropy in values:
        s = MagicMock()
        s.section_name = name
        s.entropy = entropy
        s.size = 4096
        sections.append(s)
    return sections


def _mock_strings(count: int = 5) -> MagicMock:
    interesting = []
    for i in range(count):
        es = MagicMock()
        es.value = f"string_{i}"
        es.encoding = "ascii"
        es.offset = i * 100
        es.category = "url"
        interesting.append(es)
    s = MagicMock()
    s.total_count = count
    s.interesting = interesting
    return s


def _base_report(**kwargs) -> AnalysisReport:
    defaults = dict(
        sample_name="evil.exe",
        sample_sha256="a" * 64,
        sample_md5="b" * 32,
        sample_size=8192,
    )
    defaults.update(kwargs)
    return AnalysisReport(**defaults)


# ---------------------------------------------------------------------------
# RiskScorer
# ---------------------------------------------------------------------------

class TestRiskScorer:
    def test_zero_evidence_scores_zero(self):
        scorer = RiskScorer()
        score, breakdown = scorer.score([], None, None, None, None)
        assert score == 0
        assert all(v == 0 for v in breakdown.values())

    def test_yara_hits_add_score(self):
        scorer = RiskScorer()
        matches = [_mock_yara_match() for _ in range(4)]
        score, breakdown = scorer.score(matches, None, None, None, None)
        assert breakdown["yara"] == 20
        assert score == 20

    def test_yara_capped_at_30(self):
        scorer = RiskScorer()
        matches = [_mock_yara_match() for _ in range(20)]
        score, breakdown = scorer.score(matches, None, None, None, None)
        assert breakdown["yara"] == 30

    def test_classification_contributes(self):
        scorer = RiskScorer()
        c = _mock_classification(threat_level="critical", confidence=1.0)
        score, breakdown = scorer.score([], c, None, None, None)
        assert breakdown["classification"] == 25  # max

    def test_clean_classification_zero(self):
        scorer = RiskScorer()
        c = _mock_classification(threat_level="clean", confidence=1.0)
        score, breakdown = scorer.score([], c, None, None, None)
        assert breakdown["classification"] == 0

    def test_behavioral_injection_weighted_high(self):
        scorer = RiskScorer()
        b = _mock_behavior([BehaviorCategory.PROCESS_INJECTION])
        score, breakdown = scorer.score([], None, b, None, None)
        assert breakdown["behavioral"] == 8

    def test_network_ioc_count(self):
        scorer = RiskScorer()
        n = _mock_network(7)
        score, breakdown = scorer.score([], None, None, n, None)
        assert breakdown["network"] == 7

    def test_high_entropy_contributes(self):
        scorer = RiskScorer()
        sections = _mock_entropy_sections([".text", 7.5], [".data", 4.0])
        # entropy > 7.0 for .text only
        sections_fixed = _mock_entropy_sections(
            [(".text", 7.5), (".data", 4.0)]
        )
        score, breakdown = scorer.score([], None, None, None, sections_fixed)
        assert breakdown["entropy"] == 3  # 1 high-entropy section * 3

    def test_total_capped_at_100(self):
        scorer = RiskScorer()
        matches = [_mock_yara_match() for _ in range(20)]
        c = _mock_classification(threat_level="critical", confidence=1.0)
        b = _mock_behavior([BehaviorCategory.PROCESS_INJECTION] * 5)
        n = _mock_network(10)
        sections = _mock_entropy_sections(
            [(".text", 7.8), (".data", 7.9), (".rsrc", 7.7), (".rdata", 7.6)]
        )
        score, _ = scorer.score(matches, c, b, n, sections)
        assert score <= 100


# ---------------------------------------------------------------------------
# ReportGenerator.compute_risk
# ---------------------------------------------------------------------------

class TestComputeRisk:
    def test_populates_risk_fields(self):
        rg = ReportGenerator()
        report = _base_report(
            yara_matches=[_mock_yara_match()],
            behavior=_mock_behavior(),
        )
        rg.compute_risk(report)
        assert report.risk_score > 0
        assert "yara" in report.risk_breakdown
        assert "behavioral" in report.risk_breakdown


# ---------------------------------------------------------------------------
# ReportGenerator.to_json
# ---------------------------------------------------------------------------

class TestToJson:
    def test_schema_version_present(self):
        rg = ReportGenerator()
        report = _base_report()
        rg.compute_risk(report)
        j = rg.to_json(report)
        assert j["schema_version"] == "1.0"

    def test_sample_fields(self):
        rg = ReportGenerator()
        report = _base_report()
        j = rg.to_json(report)
        assert j["sample"]["name"] == "evil.exe"
        assert j["sample"]["sha256"] == "a" * 64

    def test_json_serialisable(self):
        rg = ReportGenerator()
        report = _base_report(
            yara_matches=[_mock_yara_match()],
            behavior=_mock_behavior(),
            classification=_mock_classification(),
            network=_mock_network(),
            strings=_mock_strings(),
        )
        rg.compute_risk(report)
        j = rg.to_json(report)
        # Should not raise
        serialised = json.dumps(j)
        assert len(serialised) > 100

    def test_risk_verdict_malicious(self):
        rg = ReportGenerator()
        report = _base_report(risk_score=85)
        j = rg.to_json(report)
        assert j["risk"]["verdict"] == "MALICIOUS"

    def test_risk_verdict_clean(self):
        rg = ReportGenerator()
        report = _base_report(risk_score=10)
        j = rg.to_json(report)
        assert j["risk"]["verdict"] == "CLEAN"

    def test_yara_matches_serialised(self):
        rg = ReportGenerator()
        report = _base_report(yara_matches=[_mock_yara_match("MalwareRule")])
        j = rg.to_json(report)
        assert len(j["yara_matches"]) == 1
        assert j["yara_matches"][0]["rule"] == "MalwareRule"

    def test_network_serialised(self):
        rg = ReportGenerator()
        report = _base_report(network=_mock_network(2))
        j = rg.to_json(report)
        assert j["network_iocs"]["total_count"] == 2
        assert len(j["network_iocs"]["indicators"]) == 2

    def test_fuzzy_hash_serialised(self):
        from specter.fuzzy_hash import FuzzyHasher
        rg = ReportGenerator()
        digest = FuzzyHasher().compute(b"test" * 512)
        report = _base_report(fuzzy_digest=digest)
        j = rg.to_json(report)
        assert j["fuzzy_hash"] is not None
        assert ":" in j["fuzzy_hash"]


# ---------------------------------------------------------------------------
# ReportGenerator.to_html
# ---------------------------------------------------------------------------

class TestToHtml:
    def test_html_contains_sample_name(self):
        rg = ReportGenerator()
        report = _base_report()
        rg.compute_risk(report)
        html_out = rg.to_html(report)
        assert "evil.exe" in html_out

    def test_html_contains_sha256(self):
        rg = ReportGenerator()
        report = _base_report()
        rg.compute_risk(report)
        html_out = rg.to_html(report)
        assert "a" * 64 in html_out

    def test_html_is_valid_doctype(self):
        rg = ReportGenerator()
        report = _base_report()
        rg.compute_risk(report)
        html_out = rg.to_html(report)
        assert html_out.startswith("<!DOCTYPE html>")

    def test_html_contains_yara_section_when_matches(self):
        rg = ReportGenerator()
        report = _base_report(yara_matches=[_mock_yara_match("MyRule")])
        rg.compute_risk(report)
        html_out = rg.to_html(report)
        assert "YARA Matches" in html_out
        assert "MyRule" in html_out

    def test_html_contains_network_section(self):
        rg = ReportGenerator()
        report = _base_report(network=_mock_network(3))
        rg.compute_risk(report)
        html_out = rg.to_html(report)
        assert "Network Indicators" in html_out

    def test_html_no_yara_section_when_no_matches(self):
        rg = ReportGenerator()
        report = _base_report(yara_matches=[])
        rg.compute_risk(report)
        html_out = rg.to_html(report)
        assert "YARA Matches" not in html_out

    def test_html_escapes_special_chars(self):
        rg = ReportGenerator()
        report = _base_report(sample_name="<evil> & \"test\"")
        rg.compute_risk(report)
        html_out = rg.to_html(report)
        assert "<evil>" not in html_out
        assert "&lt;evil&gt;" in html_out

    def test_html_fuzzy_hash_section(self):
        from specter.fuzzy_hash import FuzzyHasher
        rg = ReportGenerator()
        digest = FuzzyHasher().compute(b"sample" * 512)
        report = _base_report(fuzzy_digest=digest)
        rg.compute_risk(report)
        html_out = rg.to_html(report)
        assert "Fuzzy Hash" in html_out
