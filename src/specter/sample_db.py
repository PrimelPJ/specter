"""
Malware sample database with classification and family clustering.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class MalwareFamily(str, Enum):
    UNKNOWN = "unknown"
    TROJAN = "trojan"
    RANSOMWARE = "ransomware"
    BACKDOOR = "backdoor"
    BOTNET = "botnet"
    DROPPER = "dropper"
    DOWNLOADER = "downloader"
    ROOTKIT = "rootkit"
    WORM = "worm"
    SPYWARE = "spyware"
    ADWARE = "adware"
    BANKER = "banker"
    RAT = "rat"
    CRYPTOMINER = "cryptominer"
    FILELESS = "fileless"


class ThreatLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    CLEAN = "clean"


@dataclass
class ClassificationResult:
    family: MalwareFamily
    threat_level: ThreatLevel
    confidence: float  # 0.0 - 1.0
    matched_rules: List[str]
    behavioral_indicators: List[str]
    notes: str = ""


@dataclass
class MalwareSample:
    """Complete record for a submitted malware sample."""
    md5: str
    sha1: str
    sha256: str
    file_size: int
    file_name: str = ""
    file_type: str = ""
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    submission_count: int = 1

    # PE-specific fields
    imphash: str = ""
    compile_timestamp: str = ""
    packer: List[str] = field(default_factory=list)
    section_entropy: Dict[str, float] = field(default_factory=dict)
    imports: List[str] = field(default_factory=list)  # DLL names
    is_64bit: bool = False
    is_dll: bool = False

    # Classification
    family: MalwareFamily = MalwareFamily.UNKNOWN
    threat_level: ThreatLevel = ThreatLevel.MEDIUM
    classification_confidence: float = 0.0
    matched_yara_rules: List[str] = field(default_factory=list)
    behavioral_indicators: List[str] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)
    mitre_techniques: List[str] = field(default_factory=list)

    # Analysis metadata
    analyst_notes: str = ""
    is_false_positive: bool = False
    related_samples: List[str] = field(default_factory=list)  # SHA256 hashes

    def __post_init__(self) -> None:
        if not self._validate_hash(self.md5, 32):
            raise ValueError(f"Invalid MD5: {self.md5}")
        if not self._validate_hash(self.sha1, 40):
            raise ValueError(f"Invalid SHA1: {self.sha1}")
        if not self._validate_hash(self.sha256, 64):
            raise ValueError(f"Invalid SHA256: {self.sha256}")

    @staticmethod
    def _validate_hash(h: str, length: int) -> bool:
        return len(h) == length and all(c in "0123456789abcdefABCDEF" for c in h)

    @property
    def is_known_malware(self) -> bool:
        return self.family != MalwareFamily.UNKNOWN and not self.is_false_positive

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sha256": self.sha256,
            "sha1": self.sha1,
            "md5": self.md5,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "file_type": self.file_type,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "submission_count": self.submission_count,
            "imphash": self.imphash,
            "compile_timestamp": self.compile_timestamp,
            "packer": self.packer,
            "is_64bit": self.is_64bit,
            "is_dll": self.is_dll,
            "family": self.family.value,
            "threat_level": self.threat_level.value,
            "classification_confidence": self.classification_confidence,
            "matched_yara_rules": self.matched_yara_rules,
            "behavioral_indicators": self.behavioral_indicators,
            "tags": list(self.tags),
            "mitre_techniques": self.mitre_techniques,
            "section_entropy": self.section_entropy,
        }


class SampleDatabase:
    """
    In-memory malware sample database with family clustering
    and imphash-based similarity grouping.
    """

    def __init__(self) -> None:
        self._by_sha256: Dict[str, MalwareSample] = {}
        self._by_md5: Dict[str, str] = {}   # md5 -> sha256
        self._by_sha1: Dict[str, str] = {}  # sha1 -> sha256
        self._by_imphash: Dict[str, List[str]] = {}  # imphash -> list of sha256
        self._by_family: Dict[MalwareFamily, List[str]] = {f: [] for f in MalwareFamily}
        self._rule_index: Dict[str, List[str]] = {}  # rule_name -> list of sha256

    def add_sample(self, sample: MalwareSample) -> bool:
        """Add or update a sample. Returns True if new, False if updated."""
        sha256 = sample.sha256.lower()
        is_new = sha256 not in self._by_sha256

        if not is_new:
            existing = self._by_sha256[sha256]
            existing.submission_count += 1
            existing.last_seen = datetime.now(timezone.utc)
            existing.tags.update(sample.tags)
            for rule in sample.matched_yara_rules:
                if rule not in existing.matched_yara_rules:
                    existing.matched_yara_rules.append(rule)
            return False

        self._by_sha256[sha256] = sample
        self._by_md5[sample.md5.lower()] = sha256
        self._by_sha1[sample.sha1.lower()] = sha256

        if sample.imphash:
            self._by_imphash.setdefault(sample.imphash, []).append(sha256)

        self._by_family[sample.family].append(sha256)

        for rule in sample.matched_yara_rules:
            self._rule_index.setdefault(rule, []).append(sha256)

        return True

    def get_by_sha256(self, sha256: str) -> Optional[MalwareSample]:
        return self._by_sha256.get(sha256.lower())

    def get_by_md5(self, md5: str) -> Optional[MalwareSample]:
        sha256 = self._by_md5.get(md5.lower())
        return self._by_sha256.get(sha256) if sha256 else None

    def get_by_sha1(self, sha1: str) -> Optional[MalwareSample]:
        sha256 = self._by_sha1.get(sha1.lower())
        return self._by_sha256.get(sha256) if sha256 else None

    def get_similar_by_imphash(self, imphash: str, exclude_sha256: str = "") -> List[MalwareSample]:
        """Return samples with the same import hash (same malware family indicator)."""
        sha256_list = self._by_imphash.get(imphash, [])
        return [
            self._by_sha256[h]
            for h in sha256_list
            if h != exclude_sha256.lower() and h in self._by_sha256
        ]

    def get_by_family(self, family: MalwareFamily) -> List[MalwareSample]:
        return [
            self._by_sha256[h]
            for h in self._by_family.get(family, [])
            if h in self._by_sha256
        ]

    def get_by_rule(self, rule_name: str) -> List[MalwareSample]:
        return [
            self._by_sha256[h]
            for h in self._rule_index.get(rule_name, [])
            if h in self._by_sha256
        ]

    def classify_sample(
        self,
        pe_data: Dict[str, Any],
        yara_matches: List[str],
    ) -> ClassificationResult:
        """
        Classify a sample based on PE attributes and YARA matches.
        Returns a ClassificationResult with family, threat level, and indicators.
        """
        behavioral_indicators = []
        family_scores: Dict[MalwareFamily, float] = {f: 0.0 for f in MalwareFamily}

        # YARA-based classification
        for rule in yara_matches:
            rule_lower = rule.lower()
            for family, keywords in _FAMILY_KEYWORDS.items():
                if any(kw in rule_lower for kw in keywords):
                    family_scores[family] += 2.0

        # Import-based heuristics
        imports = [imp.lower() for imp in pe_data.get("imports", [])]
        for dll in imports:
            if "wininet" in dll or "urlmon" in dll:
                behavioral_indicators.append("network_capability")
                family_scores[MalwareFamily.DOWNLOADER] += 1.0
                family_scores[MalwareFamily.RAT] += 0.5
            if "crypt32" in dll or "advapi32" in dll:
                behavioral_indicators.append("crypto_usage")
                family_scores[MalwareFamily.RANSOMWARE] += 1.0
                family_scores[MalwareFamily.BANKER] += 0.5
            if "ws2_32" in dll:
                behavioral_indicators.append("socket_communication")
                family_scores[MalwareFamily.BACKDOOR] += 1.0
                family_scores[MalwareFamily.BOTNET] += 1.0

        # Packer detection
        packers = pe_data.get("detected_packers", [])
        if packers:
            behavioral_indicators.append(f"packed:{packers[0]}")
            for f in (MalwareFamily.DROPPER, MalwareFamily.RANSOMWARE, MalwareFamily.BACKDOOR):
                family_scores[f] += 0.5

        # Section entropy analysis
        sections = pe_data.get("sections", [])
        for sec in sections:
            if sec.get("entropy", 0) > 7.2:
                behavioral_indicators.append(f"high_entropy_section:{sec['name']}")
                family_scores[MalwareFamily.RANSOMWARE] += 0.5
            if sec.get("is_suspicious"):
                behavioral_indicators.append(f"rwx_section:{sec['name']}")
                family_scores[MalwareFamily.ROOTKIT] += 1.0
                family_scores[MalwareFamily.BACKDOOR] += 0.5

        # Risk indicators from PE
        for indicator in pe_data.get("risk_indicators", []):
            if "overlay" in indicator.lower():
                behavioral_indicators.append("suspicious_overlay")
                family_scores[MalwareFamily.DROPPER] += 1.0

        # Determine best family
        best_family = MalwareFamily.UNKNOWN
        best_score = 0.0
        for family, score in family_scores.items():
            if family == MalwareFamily.UNKNOWN:
                continue
            if score > best_score:
                best_score = score
                best_family = family

        # Threat level based on family and indicators
        threat_level = self._score_threat_level(
            best_family, behavioral_indicators, yara_matches
        )

        confidence = min(1.0, best_score / 4.0) if best_score > 0 else 0.0

        return ClassificationResult(
            family=best_family,
            threat_level=threat_level,
            confidence=round(confidence, 2),
            matched_rules=yara_matches,
            behavioral_indicators=behavioral_indicators,
        )

    def stats(self) -> Dict[str, Any]:
        total = len(self._by_sha256)
        by_family = {
            f.value: len(samples)
            for f, samples in self._by_family.items()
            if samples
        }
        return {
            "total_samples": total,
            "by_family": by_family,
            "unique_imphashes": len(self._by_imphash),
            "yara_rule_hits": {
                rule: len(hits)
                for rule, hits in self._rule_index.items()
            },
        }

    def export_json(self) -> str:
        return json.dumps(
            [s.to_dict() for s in self._by_sha256.values()],
            indent=2,
        )

    @staticmethod
    def _score_threat_level(
        family: MalwareFamily,
        indicators: List[str],
        rules: List[str],
    ) -> ThreatLevel:
        critical_families = {
            MalwareFamily.RANSOMWARE, MalwareFamily.ROOTKIT,
            MalwareFamily.BACKDOOR, MalwareFamily.BOTNET,
        }
        high_families = {
            MalwareFamily.RAT, MalwareFamily.BANKER, MalwareFamily.TROJAN,
            MalwareFamily.DROPPER, MalwareFamily.WORM,
        }

        if family in critical_families:
            return ThreatLevel.CRITICAL
        if family in high_families:
            return ThreatLevel.HIGH
        if family != MalwareFamily.UNKNOWN:
            return ThreatLevel.MEDIUM

        # Fallback to indicators
        if len(indicators) >= 3 or len(rules) >= 2:
            return ThreatLevel.HIGH
        if indicators or rules:
            return ThreatLevel.MEDIUM

        return ThreatLevel.LOW


_FAMILY_KEYWORDS: Dict[MalwareFamily, List[str]] = {
    MalwareFamily.RANSOMWARE: ["ransom", "encrypt", "locker", "crypt", "bitcoin", "walletlock"],
    MalwareFamily.BACKDOOR: ["backdoor", "shell", "reverse", "bind_shell", "cmd_exec"],
    MalwareFamily.BOTNET: ["botnet", "c2", "command_control", "irc_bot", "dga"],
    MalwareFamily.RAT: ["rat", "remote_access", "keylog", "screenshot", "remote_shell"],
    MalwareFamily.DROPPER: ["dropper", "stage", "download_exec", "inject"],
    MalwareFamily.DOWNLOADER: ["downloader", "urldownload", "fetch", "wget_style"],
    MalwareFamily.ROOTKIT: ["rootkit", "hook_ssdt", "kernel", "driver_hide", "dkom"],
    MalwareFamily.BANKER: ["banker", "zeus", "formgrab", "credential_steal"],
    MalwareFamily.SPYWARE: ["spyware", "keylogger", "clipper", "screen_capture"],
    MalwareFamily.WORM: ["worm", "spreader", "network_propagate", "smb_spread"],
    MalwareFamily.CRYPTOMINER: ["miner", "monero", "xmr", "cpu_mine", "stratum"],
    MalwareFamily.TROJAN: ["trojan", "generic", "generic_malware", "suspect"],
}
