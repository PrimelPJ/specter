"""
Specter - Static Malware Analysis Sandbox
"""

from specter.pe_parser import PEParser, PEParseError, PEFile
from specter.entropy import EntropyAnalyzer, SectionEntropyResult
from specter.yara_engine import YaraEngine, YaraRule, YaraMatch
from specter.sample_db import SampleDatabase, MalwareSample, ClassificationResult
from specter.behavioral import BehavioralAnalyzer, BehaviorReport, BehaviorCategory
from specter.classifier import SampleClassifier, ClassificationFeatures, MalwareClass
from specter.network_extractor import NetworkExtractor, NetworkIndicator, NetworkExtractionResult
from specter.string_extractor import StringExtractor, ExtractedString, StringExtractionResult
from specter.fuzzy_hash import (
    FuzzyHasher,
    FuzzyDigest,
    SampleSimilarityDB,
    SimilarityCluster,
    RollingHash,
)
from specter.report_generator import (
    ReportGenerator,
    AnalysisReport,
    RiskScorer,
)

__all__ = [
    "PEParser",
    "PEParseError",
    "PEFile",
    "EntropyAnalyzer",
    "SectionEntropyResult",
    "YaraEngine",
    "YaraRule",
    "YaraMatch",
    "SampleDatabase",
    "MalwareSample",
    "ClassificationResult",
    "BehavioralAnalyzer",
    "BehaviorReport",
    "BehaviorCategory",
    "SampleClassifier",
    "ClassificationFeatures",
    "MalwareClass",
    "NetworkExtractor",
    "NetworkIndicator",
    "NetworkExtractionResult",
    "StringExtractor",
    "ExtractedString",
    "StringExtractionResult",
    "FuzzyHasher",
    "FuzzyDigest",
    "SampleSimilarityDB",
    "SimilarityCluster",
    "RollingHash",
    "ReportGenerator",
    "AnalysisReport",
    "RiskScorer",
]

__version__ = "0.1.0"
