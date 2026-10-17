# Specter

Static malware analysis sandbox with PE parsing, YARA-style rule engine, and entropy analysis.

## Overview

Specter provides comprehensive static analysis of PE (Portable Executable) files without executing them. It combines deep binary parsing with a built-in signature engine to classify malware samples and extract behavioral indicators.

## Features

- **PE Parser**: Full DOS/COFF/Optional header parsing, section table analysis, import/export table extraction
- **Entropy Analysis**: Shannon entropy per-section and windowed analysis, DGA detection, packer identification
- **YARA-style Engine**: Pure-Python rule engine with text/hex/regex patterns, wildcards, XOR encoding detection
- **Packer Detection**: UPX, MPRESS, ASPack, Themida, VMProtect, and heuristic entropy-based detection
- **String Extraction**: Regex-based extraction of URLs, file paths, registry keys, Windows API calls
- **Import Analysis**: DLL import table parsing with suspicious API detection
- **Sample Database**: In-memory sample store with imphash clustering and family classification
- **Built-in Rules**: 10+ YARA rules covering ransomware, RATs, backdoors, process injection, anti-VM

## MITRE ATT&CK Coverage

| Technique | ID | Detection |
|-----------|-----|-----------|
| Data Encrypted for Impact | T1486 | Ransomware patterns |
| Command and Scripting Interpreter | T1059 | Shell invocation strings |
| Ingress Tool Transfer | T1105 | Downloader API patterns |
| Input Capture | T1056.001 | Keylogger hook APIs |
| Process Injection | T1055 | VirtualAllocEx/WriteProcessMemory chains |
| Boot/Logon Autostart | T1547.001 | Run key registry writes |
| Resource Hijacking | T1496 | Cryptominer pool strings |
| Virtualization/Sandbox Evasion | T1497 | Anti-VM checks |

## Installation

```bash
pip install -r requirements.txt
pip install -e .
```

## Quick Start

```python
from specter import PEParser, YaraEngine, EntropyAnalyzer, SampleDatabase

# Parse a PE file
parser = PEParser()
with open("sample.exe", "rb") as f:
    data = f.read()

pe = parser.parse(data)
print(f"SHA256: {pe.sha256}")
print(f"Imphash: {pe.imphash}")
print(f"Packers: {pe.detected_packers}")
print(f"Risk indicators: {pe.risk_indicators}")

# Entropy analysis
analyzer = EntropyAnalyzer()
for section in pe.sections:
    result = analyzer.analyze_section(
        section.name,
        data[section.pointer_to_raw_data:section.pointer_to_raw_data + section.size_of_raw_data]
    )
    print(f"  {section.name}: entropy={result.entropy:.2f} ({result.classification})")

# YARA scanning
engine = YaraEngine()
engine.load_rules_text(open("rules/malware_signatures.yar").read())
matches = engine.scan(data, file_hash=pe.sha256)
for m in matches:
    print(f"Rule matched: {m.rule_name} (tags: {m.tags})")

# Sample database
db = SampleDatabase()
from specter import MalwareSample, MalwareFamily
sample = MalwareSample(
    md5=pe.md5, sha1=pe.sha1, sha256=pe.sha256,
    file_size=pe.file_size,
    imphash=pe.imphash,
    packer=pe.detected_packers,
)
result = db.classify_sample(pe.to_dict(), [m.rule_name for m in matches])
print(f"Family: {result.family.value}, Threat: {result.threat_level.value}")
```

## Project Structure

```
specter/
├── src/specter/
│   ├── pe_parser.py      # PE file binary parser
│   ├── entropy.py        # Entropy analysis engine
│   ├── yara_engine.py    # YARA-style rule engine
│   └── sample_db.py      # Sample database and classification
├── rules/
│   └── malware_signatures.yar  # Built-in detection rules
└── tests/
    ├── test_entropy.py
    └── test_yara_engine.py
```

## Running Tests

```bash
PYTHONPATH=src pytest tests/ -v
```

## License

MIT License - Copyright (c) 2026 Primel Jayawardana
