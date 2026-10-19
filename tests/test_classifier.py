"""Tests for the SampleClassifier."""

from unittest.mock import MagicMock

import pytest

from specter.behavioral import BehaviorCategory, BehaviorReport, BehaviorIndicator
from specter.classifier import (
    ClassificationFeatures,
    ClassificationResult,
    MalwareClass,
    SampleClassifier,
)
from specter.yara_engine import YaraMatch

HASH = "b" * 64


def make_features(
    file_hash: str = HASH,
    max_section_entropy: float = 5.0,
    import_count: int = 50,
    has_packed_sections: bool = False,
    url_count: int = 0,
    ip_count: int = 0,
    has_overlay: bool = False,
    is_dll: bool = False,
) -> ClassificationFeatures:
    return ClassificationFeatures(
        file_hash=file_hash,
        file_size=1024 * 100,
        section_count=4,
        import_count=import_count,
        export_count=0,
        average_section_entropy=max_section_entropy * 0.8,
        max_section_entropy=max_section_entropy,
        has_packed_sections=has_packed_sections,
        is_dll=is_dll,
        url_string_count=url_count,
        ip_string_count=ip_count,
        has_overlay=has_overlay,
    )


def make_yara_match(rule_name: str, tags=None) -> YaraMatch:
    return YaraMatch(
        rule_name=rule_name,
        namespace="test",
        tags=tags or [],
        meta={},
        strings=[],
        file_hash=HASH,
    )


def make_behavior_report(
    categories=None,
    techniques=None,
    severity: int = 3,
    families=None,
    is_packed: bool = False,
) -> BehaviorReport:
    report = BehaviorReport(
        sample_hash=HASH,
        is_packed=is_packed,
        overall_severity=severity,
        malware_families=families or [],
    )
    for cat in (categories or []):
        report.categories.add(cat)
    for tech in (techniques or []):
        report.mitre_techniques.add(tech)
    return report


class TestClassifierClean:
    def setup_method(self):
        self.clf = SampleClassifier()

    def test_no_signal_returns_clean(self):
        features = make_features()
        result = self.clf.classify(features)
        assert result.malware_class == MalwareClass.CLEAN
        assert result.confidence >= 0.9
        assert not result.is_malicious

    def test_verdict_clean(self):
        result = self.clf.classify(make_features())
        assert result.verdict == "CLEAN"


class TestClassifierYara:
    def setup_method(self):
        self.clf = SampleClassifier()

    def test_yara_ransomware_tag(self):
        features = make_features()
        match = make_yara_match("WannaCry_Generic", tags=["ransomware"])
        result = self.clf.classify(features, yara_matches=[match])
        assert result.malware_class == MalwareClass.RANSOMWARE
        assert result.confidence >= 0.8
        assert result.is_malicious

    def test_yara_rat_tag(self):
        features = make_features()
        match = make_yara_match("NjRAT_v0_7", tags=["rat"])
        result = self.clf.classify(features, yara_matches=[match])
        assert result.malware_class == MalwareClass.RAT

    def test_yara_no_family_tag_suspicious(self):
        features = make_features()
        match = make_yara_match("Generic_Suspicious_String", tags=["malware"])
        result = self.clf.classify(features, yara_matches=[match])
        assert result.is_malicious
        assert result.confidence >= 0.5

    def test_yara_hit_name_in_result(self):
        features = make_features()
        match = make_yara_match("Mirai_Loader", tags=["loader"])
        result = self.clf.classify(features, yara_matches=[match])
        assert "Mirai_Loader" in result.yara_hits


class TestClassifierBehavior:
    def setup_method(self):
        self.clf = SampleClassifier()

    def test_ransomware_via_behavior(self):
        features = make_features()
        behavior = make_behavior_report(
            categories=[BehaviorCategory.EXECUTION],
            techniques=["T1486"],
            severity=5,
        )
        result = self.clf.classify(features, behavior_report=behavior)
        assert result.malware_class == MalwareClass.RANSOMWARE
        assert result.is_malicious

    def test_rat_via_behavior(self):
        features = make_features()
        behavior = make_behavior_report(
            categories=[
                BehaviorCategory.INJECTION,
                BehaviorCategory.NETWORK,
                BehaviorCategory.PERSISTENCE,
            ],
            severity=4,
        )
        result = self.clf.classify(features, behavior_report=behavior)
        assert result.malware_class in (MalwareClass.RAT, MalwareClass.BACKDOOR)

    def test_infostealer_via_behavior(self):
        features = make_features()
        behavior = make_behavior_report(
            categories=[
                BehaviorCategory.CREDENTIAL_ACCESS,
                BehaviorCategory.INJECTION,
            ],
            severity=5,
        )
        result = self.clf.classify(features, behavior_report=behavior)
        assert result.malware_class == MalwareClass.INFOSTEALER

    def test_keylogger_via_behavior(self):
        features = make_features()
        behavior = make_behavior_report(
            categories=[BehaviorCategory.COLLECTION, BehaviorCategory.NETWORK],
            techniques=["T1056"],
            severity=4,
        )
        result = self.clf.classify(features, behavior_report=behavior)
        assert result.malware_class == MalwareClass.KEYLOGGER

    def test_severity_inherited_from_behavior(self):
        features = make_features()
        behavior = make_behavior_report(severity=5)
        behavior.categories.add(BehaviorCategory.INJECTION)
        result = self.clf.classify(features, behavior_report=behavior)
        assert result.severity == 5


class TestClassifierStatic:
    def setup_method(self):
        self.clf = SampleClassifier()

    def test_high_entropy_triggers_packer(self):
        features = make_features(max_section_entropy=7.5, import_count=3)
        result = self.clf.classify(features)
        assert result.is_malicious or result.confidence > 0.3
        assert any("entropy" in r.lower() for r in result.reasoning)

    def test_few_imports_suspicious(self):
        features = make_features(import_count=2, is_dll=False)
        result = self.clf.classify(features)
        assert any("import" in r.lower() for r in result.reasoning)

    def test_overlay_flagged(self):
        features = make_features(has_overlay=True)
        result = self.clf.classify(features)
        assert any("overlay" in r.lower() for r in result.reasoning)

    def test_many_urls_flagged(self):
        features = make_features(url_count=10)
        result = self.clf.classify(features)
        assert any("url" in r.lower() or "URL" in r for r in result.reasoning)

    def test_many_ips_flagged(self):
        features = make_features(ip_count=5)
        result = self.clf.classify(features)
        assert any("ip" in r.lower() or "IP" in r for r in result.reasoning)


class TestClassificationResult:
    def test_verdict_malicious_high_confidence(self):
        result = ClassificationResult(
            file_hash=HASH,
            malware_class=MalwareClass.TROJAN,
            confidence=0.9,
            severity=4,
            yara_hits=[],
            mitre_techniques=[],
            malware_families=[],
            features=make_features(),
        )
        assert "MALICIOUS" in result.verdict

    def test_verdict_suspicious_medium_confidence(self):
        result = ClassificationResult(
            file_hash=HASH,
            malware_class=MalwareClass.SUSPICIOUS,
            confidence=0.6,
            severity=2,
            yara_hits=[],
            mitre_techniques=[],
            malware_families=[],
            features=make_features(),
        )
        assert "SUSPICIOUS" in result.verdict

    def test_to_dict_keys(self):
        clf = SampleClassifier()
        result = clf.classify(make_features())
        d = result.to_dict()
        expected_keys = {
            "file_hash", "verdict", "malware_class", "confidence",
            "severity", "yara_hits", "mitre_techniques", "malware_families", "reasoning"
        }
        assert expected_keys <= set(d.keys())
