"""
Malware sample classifier.
Combines PE static features, entropy, YARA matches, and behavioral indicators
to produce a classification verdict with confidence scoring.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from specter.behavioral import BehaviorCategory, BehaviorReport
from specter.yara_engine import YaraMatch

logger = logging.getLogger(__name__)


class MalwareClass(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    RANSOMWARE = "ransomware"
    TROJAN = "trojan"
    WORM = "worm"
    ROOTKIT = "rootkit"
    INFOSTEALER = "infostealer"
    RAT = "rat"
    BACKDOOR = "backdoor"
    DROPPER = "dropper"
    DOWNLOADER = "downloader"
    LOADER = "loader"
    KEYLOGGER = "keylogger"
    ADWARE = "adware"
    UNKNOWN = "unknown"


@dataclass
class ClassificationFeatures:
    """Normalized feature vector for classification."""
    file_hash: str
    file_size: int = 0
    section_count: int = 0
    import_count: int = 0
    export_count: int = 0
    average_section_entropy: float = 0.0
    max_section_entropy: float = 0.0
    has_packed_sections: bool = False      # section entropy > 7.0
    is_dll: bool = False
    has_tls: bool = False
    has_resources: bool = False
    has_overlay: bool = False
    string_count: int = 0
    url_string_count: int = 0
    ip_string_count: int = 0
    yara_matches: List[str] = field(default_factory=list)
    behavior_categories: Set[BehaviorCategory] = field(default_factory=set)
    behavior_severity: int = 0
    mitre_techniques: Set[str] = field(default_factory=set)
    malware_family_hints: List[str] = field(default_factory=list)


@dataclass
class ClassificationResult:
    file_hash: str
    malware_class: MalwareClass
    confidence: float               # 0.0–1.0
    severity: int                   # 1–5
    yara_hits: List[str]
    mitre_techniques: List[str]
    malware_families: List[str]
    features: ClassificationFeatures
    reasoning: List[str] = field(default_factory=list)

    @property
    def is_malicious(self) -> bool:
        return self.malware_class not in (MalwareClass.CLEAN, MalwareClass.UNKNOWN)

    @property
    def verdict(self) -> str:
        if self.malware_class == MalwareClass.CLEAN:
            return "CLEAN"
        if self.confidence >= 0.8:
            return f"MALICIOUS ({self.malware_class.value.upper()})"
        if self.confidence >= 0.5:
            return f"SUSPICIOUS ({self.malware_class.value.upper()})"
        return "UNKNOWN"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_hash": self.file_hash,
            "verdict": self.verdict,
            "malware_class": self.malware_class.value,
            "confidence": round(self.confidence, 3),
            "severity": self.severity,
            "yara_hits": self.yara_hits,
            "mitre_techniques": sorted(self.mitre_techniques),
            "malware_families": self.malware_families,
            "reasoning": self.reasoning,
        }


class SampleClassifier:
    """
    Rule-based + score-based classifier.

    Scoring algorithm:
    1. Hard rules:  YARA family-specific matches  → high-confidence classification
    2. Behavior:    category/severity scores       → class inference
    3. Static:      entropy, section anomalies     → packer/dropper signals
    4. Soft rules:  technique combinations         → family disambiguation
    """

    # Entropy thresholds
    HIGH_ENTROPY = 7.0
    SUSPICIOUS_ENTROPY = 6.0

    # YARA tag → malware class mapping
    YARA_CLASS_MAP: Dict[str, MalwareClass] = {
        "ransomware": MalwareClass.RANSOMWARE,
        "rat": MalwareClass.RAT,
        "backdoor": MalwareClass.BACKDOOR,
        "infostealer": MalwareClass.INFOSTEALER,
        "keylogger": MalwareClass.KEYLOGGER,
        "rootkit": MalwareClass.ROOTKIT,
        "worm": MalwareClass.WORM,
        "trojan": MalwareClass.TROJAN,
        "dropper": MalwareClass.DROPPER,
        "downloader": MalwareClass.DOWNLOADER,
        "loader": MalwareClass.LOADER,
        "adware": MalwareClass.ADWARE,
    }

    def classify(
        self,
        features: ClassificationFeatures,
        yara_matches: Optional[List[YaraMatch]] = None,
        behavior_report: Optional[BehaviorReport] = None,
    ) -> ClassificationResult:
        """Run classification pipeline and return result."""
        score = 0.0
        max_score = 0.0
        reasoning: List[str] = []
        malware_class = MalwareClass.UNKNOWN
        severity = 1
        yara_families: List[str] = []

        # ----------------------------------------------------------------
        # Stage 1: Hard YARA-based classification
        if yara_matches:
            for match in yara_matches:
                for tag in match.tags:
                    tag_lower = tag.lower()
                    if tag_lower in self.YARA_CLASS_MAP:
                        malware_class = self.YARA_CLASS_MAP[tag_lower]
                        score = 0.9
                        max_score = 1.0
                        reasoning.append(
                            f"YARA rule '{match.rule_name}' matched with tag '{tag}'"
                        )
                        if tag_lower not in yara_families:
                            yara_families.append(tag_lower)

            # Generic malware YARA match without family tag still suspicious
            if yara_matches and malware_class == MalwareClass.UNKNOWN:
                score = max(score, 0.6)
                max_score = max(max_score, 1.0)
                malware_class = MalwareClass.SUSPICIOUS
                reasoning.append(
                    f"{len(yara_matches)} YARA rule(s) matched without specific family tag"
                )

        # ----------------------------------------------------------------
        # Stage 2: Behavioral scoring
        if behavior_report:
            bscore, breasoning = self._score_behavior(behavior_report)
            score = max(score, bscore / 10.0)
            max_score = max(max_score, 1.0)
            reasoning.extend(breasoning)
            severity = max(severity, behavior_report.overall_severity)

            # Behavior-inferred class (only if YARA didn't already set one)
            if malware_class in (MalwareClass.UNKNOWN, MalwareClass.SUSPICIOUS):
                inferred = self._infer_class_from_behavior(behavior_report)
                if inferred != MalwareClass.UNKNOWN:
                    malware_class = inferred
                    reasoning.append(
                        f"Behavioral indicators suggest class: {inferred.value}"
                    )

        # ----------------------------------------------------------------
        # Stage 3: Static / entropy signals
        static_score, static_reasoning = self._score_static(features)
        score = max(score, static_score / 10.0)
        max_score = max(max_score, 1.0)
        reasoning.extend(static_reasoning)

        # ----------------------------------------------------------------
        # Stage 4: Finalize
        confidence = min(1.0, score)

        # Ensure malware class is set if we have any signal
        if malware_class == MalwareClass.UNKNOWN and score > 0.3:
            malware_class = MalwareClass.SUSPICIOUS

        # Clean if nothing triggered
        if score == 0.0:
            malware_class = MalwareClass.CLEAN
            confidence = 0.95
            reasoning.append("No malicious indicators detected")

        yara_hit_names = [m.rule_name for m in (yara_matches or [])]
        combined_families = list(
            {*yara_families, *(behavior_report.malware_families if behavior_report else [])}
        )

        return ClassificationResult(
            file_hash=features.file_hash,
            malware_class=malware_class,
            confidence=confidence,
            severity=severity,
            yara_hits=yara_hit_names,
            mitre_techniques=sorted(
                behavior_report.mitre_techniques if behavior_report else set()
            ),
            malware_families=combined_families,
            features=features,
            reasoning=reasoning,
        )

    # ------------------------------------------------------------------
    # Scoring helpers

    def _score_behavior(self, report: BehaviorReport) -> Tuple[float, List[str]]:
        """Convert behavior report into a 0-10 score."""
        score = 0.0
        reasoning: List[str] = []
        cats = report.categories

        category_weights = {
            BehaviorCategory.INJECTION: 2.5,
            BehaviorCategory.CREDENTIAL_ACCESS: 2.5,
            BehaviorCategory.ANTI_ANALYSIS: 2.0,
            BehaviorCategory.PERSISTENCE: 1.5,
            BehaviorCategory.PRIVILEGE_ESCALATION: 2.0,
            BehaviorCategory.NETWORK: 1.0,
            BehaviorCategory.COLLECTION: 1.5,
            BehaviorCategory.LATERAL_MOVEMENT: 2.0,
            BehaviorCategory.EXFILTRATION: 2.5,
            BehaviorCategory.EXECUTION: 1.0,
            BehaviorCategory.DEFENSE_EVASION: 1.5,
        }

        for cat, weight in category_weights.items():
            if cat in cats:
                score += weight
                reasoning.append(f"Behavior: {cat.value} ({weight:.1f}pts)")

        # Severity multiplier
        if report.overall_severity >= 4:
            score *= 1.3
            reasoning.append("High-severity behavioral indicators present")

        if report.is_packed:
            score += 1.0
            reasoning.append("Sample appears packed (entropy or packer signatures)")

        return min(10.0, score), reasoning

    def _score_static(self, features: ClassificationFeatures) -> Tuple[float, List[str]]:
        """Score static features; returns 0-10."""
        score = 0.0
        reasoning: List[str] = []

        if features.max_section_entropy >= self.HIGH_ENTROPY:
            score += 3.0
            reasoning.append(
                f"High section entropy ({features.max_section_entropy:.2f}) indicates packing"
            )
        elif features.max_section_entropy >= self.SUSPICIOUS_ENTROPY:
            score += 1.5
            reasoning.append(
                f"Elevated section entropy ({features.max_section_entropy:.2f})"
            )

        if features.has_packed_sections:
            score += 1.0
            reasoning.append("Multiple high-entropy sections detected")

        if features.url_string_count > 5:
            score += 1.0
            reasoning.append(f"{features.url_string_count} hardcoded URLs found")

        if features.ip_string_count > 3:
            score += 1.5
            reasoning.append(f"{features.ip_string_count} hardcoded IP addresses found")

        if features.import_count < 5 and not features.is_dll:
            score += 2.0
            reasoning.append(
                "Very few imports — consistent with packed/loader binary"
            )

        if features.has_overlay:
            score += 1.0
            reasoning.append("File has overlay data after PE sections")

        return min(10.0, score), reasoning

    @staticmethod
    def _infer_class_from_behavior(report: BehaviorReport) -> MalwareClass:
        cats = report.categories
        techs = report.mitre_techniques

        if "T1486" in techs:
            return MalwareClass.RANSOMWARE
        if BehaviorCategory.CREDENTIAL_ACCESS in cats and BehaviorCategory.INJECTION in cats:
            return MalwareClass.INFOSTEALER
        if BehaviorCategory.COLLECTION in cats and "T1056" in techs:
            return MalwareClass.KEYLOGGER
        if BehaviorCategory.INJECTION in cats and BehaviorCategory.NETWORK in cats:
            return MalwareClass.RAT
        if BehaviorCategory.INJECTION in cats and BehaviorCategory.PERSISTENCE in cats:
            return MalwareClass.BACKDOOR
        if BehaviorCategory.LATERAL_MOVEMENT in cats:
            return MalwareClass.WORM
        if BehaviorCategory.NETWORK in cats and BehaviorCategory.PERSISTENCE not in cats:
            return MalwareClass.DOWNLOADER
        if BehaviorCategory.INJECTION in cats:
            return MalwareClass.LOADER
        return MalwareClass.UNKNOWN


def build_features_from_pe(
    file_hash: str,
    pe_result: Any,
    yara_matches: Optional[List[YaraMatch]] = None,
    strings: Optional[List[bytes]] = None,
) -> ClassificationFeatures:
    """
    Build a ClassificationFeatures from a PEAnalysisResult object.
    Handles missing attributes gracefully.
    """
    import re as _re

    url_pattern = _re.compile(rb"https?://", _re.IGNORECASE)
    ip_pattern = _re.compile(rb"(?:\d{1,3}\.){3}\d{1,3}")

    url_count = 0
    ip_count = 0
    if strings:
        for s in strings:
            if url_pattern.search(s):
                url_count += 1
            if ip_pattern.search(s):
                ip_count += 1

    sections = getattr(pe_result, "sections", [])
    entropies = [getattr(s, "entropy", 0.0) for s in sections]
    avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
    max_entropy = max(entropies) if entropies else 0.0

    imports = getattr(pe_result, "imports", {})
    import_count = sum(len(v) for v in imports.values()) if imports else 0
    exports = getattr(pe_result, "exports", [])
    characteristics = getattr(pe_result, "characteristics", [])
    data_dirs = getattr(pe_result, "data_directories", {})

    return ClassificationFeatures(
        file_hash=file_hash,
        file_size=getattr(pe_result, "file_size", 0),
        section_count=len(sections),
        import_count=import_count,
        export_count=len(exports),
        average_section_entropy=avg_entropy,
        max_section_entropy=max_entropy,
        has_packed_sections=sum(1 for e in entropies if e > 7.0) > 1,
        is_dll="DLL" in characteristics,
        has_tls="TLS" in data_dirs,
        has_resources="RESOURCE_TABLE" in data_dirs,
        has_overlay=getattr(pe_result, "overlay_size", 0) > 0,
        string_count=len(strings) if strings else 0,
        url_string_count=url_count,
        ip_string_count=ip_count,
        yara_matches=[m.rule_name for m in (yara_matches or [])],
    )
