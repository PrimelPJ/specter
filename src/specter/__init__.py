"""
Specter - Static Malware Analysis Sandbox
"""

from specter.pe_parser import PEParser, PEParseError, PEFile
from specter.entropy import EntropyAnalyzer, SectionEntropyResult
from specter.yara_engine import YaraEngine, YaraRule, YaraMatch
from specter.sample_db import SampleDatabase, MalwareSample, ClassificationResult

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
]

__version__ = "0.1.0"
