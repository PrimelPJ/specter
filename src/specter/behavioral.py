"""
Behavioral indicator extractor for PE files.
Analyzes import tables and strings to infer behavioral capabilities,
network activity, persistence mechanisms, and evasion techniques.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


class BehaviorCategory(str, Enum):
    NETWORK = "network"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    EXECUTION = "execution"
    INJECTION = "injection"
    ANTI_ANALYSIS = "anti_analysis"
    FILE_SYSTEM = "file_system"
    REGISTRY = "registry"
    PROCESS = "process"
    CRYPTO = "crypto"


@dataclass
class BehaviorIndicator:
    """A single behavioral indicator with MITRE ATT&CK mapping."""
    name: str
    category: BehaviorCategory
    description: str
    severity: int                   # 1 (low) – 5 (critical)
    mitre_technique: str            # e.g. "T1055"
    mitre_subtechnique: str = ""    # e.g. "T1055.001"
    evidence: List[str] = field(default_factory=list)  # matched API calls / strings


@dataclass
class BehaviorReport:
    """Aggregated behavioral analysis for a sample."""
    sample_hash: str
    indicators: List[BehaviorIndicator] = field(default_factory=list)
    categories: Set[BehaviorCategory] = field(default_factory=set)
    mitre_techniques: Set[str] = field(default_factory=set)
    overall_severity: int = 0       # 1-5
    malware_families: List[str] = field(default_factory=list)
    is_packed: bool = False
    has_network_activity: bool = False
    has_persistence: bool = False
    has_anti_analysis: bool = False

    def add_indicator(self, indicator: BehaviorIndicator) -> None:
        self.indicators.append(indicator)
        self.categories.add(indicator.category)
        self.mitre_techniques.add(indicator.mitre_technique)
        if indicator.mitre_subtechnique:
            self.mitre_techniques.add(indicator.mitre_subtechnique)
        self.overall_severity = max(self.overall_severity, indicator.severity)

    @property
    def severity_label(self) -> str:
        labels = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL", 5: "CRITICAL"}
        return labels.get(self.overall_severity, "UNKNOWN")

    @property
    def indicator_count(self) -> int:
        return len(self.indicators)

    def summary(self) -> Dict:
        return {
            "sample_hash": self.sample_hash,
            "severity": self.severity_label,
            "indicator_count": self.indicator_count,
            "categories": [c.value for c in self.categories],
            "mitre_techniques": sorted(self.mitre_techniques),
            "malware_families": self.malware_families,
            "flags": {
                "network_activity": self.has_network_activity,
                "persistence": self.has_persistence,
                "anti_analysis": self.has_anti_analysis,
                "packed": self.is_packed,
            },
        }


# ---------------------------------------------------------------------------
# Import-based behavioral signatures
# Each entry: (set of API names, BehaviorCategory, name, description, severity, technique, sub)

_IMPORT_SIGNATURES: List[Tuple] = [
    # Network — T1071
    (
        {"WSAStartup", "WSAConnect", "connect", "send", "recv", "InternetOpenA",
         "InternetOpenW", "InternetConnectA", "InternetConnectW", "HttpOpenRequestA",
         "WinHttpOpen", "WinHttpConnect", "URLDownloadToFileA", "URLDownloadToFileW"},
        BehaviorCategory.NETWORK, "Network Communication",
        "Sample establishes network connections or performs HTTP requests.",
        3, "T1071", "T1071.001",
    ),
    # DNS resolution — T1071.004
    (
        {"DnsQuery_A", "DnsQuery_W", "getaddrinfo", "gethostbyname"},
        BehaviorCategory.NETWORK, "DNS Resolution",
        "Sample performs DNS lookups, potentially for C2 or DGA activity.",
        2, "T1071", "T1071.004",
    ),
    # Process injection — T1055
    (
        {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
         "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
         "SetThreadContext", "ResumeThread"},
        BehaviorCategory.INJECTION, "Process Injection",
        "Sample injects code into remote processes.",
        5, "T1055", "T1055.001",
    ),
    # DLL injection — T1055.001
    (
        {"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
         "LdrLoadDll", "NtMapViewOfSection"},
        BehaviorCategory.INJECTION, "DLL Load",
        "Sample loads DLLs dynamically, potentially for injection or evasion.",
        2, "T1055", "T1055.001",
    ),
    # Process hollowing — T1055.012
    (
        {"NtUnmapViewOfSection", "ZwUnmapViewOfSection"},
        BehaviorCategory.INJECTION, "Process Hollowing",
        "Sample unmaps executable sections, consistent with process hollowing.",
        5, "T1055", "T1055.012",
    ),
    # Persistence — Registry — T1547.001
    (
        {"RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
         "RegOpenKeyExA", "RegOpenKeyExW"},
        BehaviorCategory.PERSISTENCE, "Registry Persistence",
        "Sample modifies registry keys, potentially for persistence or configuration.",
        4, "T1547", "T1547.001",
    ),
    # Scheduled tasks — T1053
    (
        {"ITaskScheduler", "TaskScheduler", "CreateService", "OpenSCManager",
         "StartServiceCtrlDispatcher"},
        BehaviorCategory.PERSISTENCE, "Scheduled Task / Service",
        "Sample creates scheduled tasks or services for persistence.",
        4, "T1053", "T1053.005",
    ),
    # Defense evasion — process/thread manipulation — T1055
    (
        {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
         "OutputDebugStringA"},
        BehaviorCategory.ANTI_ANALYSIS, "Debugger Detection",
        "Sample checks for attached debuggers to evade analysis.",
        4, "T1622", "",
    ),
    # Anti-VM — T1497
    (
        {"GetTickCount", "timeGetTime", "QueryPerformanceCounter"},
        BehaviorCategory.ANTI_ANALYSIS, "Timing Check",
        "Sample uses timing APIs that may detect sandbox/VM slowdowns.",
        2, "T1497", "T1497.001",
    ),
    # Credential access — T1003
    (
        {"LsaOpenPolicy", "SamOpenDomain", "SamEnumerateUsersInDomain",
         "NtlmCredentialHandle", "CredEnumerateA", "CredReadA",
         "CryptUnprotectData"},
        BehaviorCategory.CREDENTIAL_ACCESS, "Credential Dumping",
        "Sample accesses credential stores or LSA secrets.",
        5, "T1003", "",
    ),
    # Keylogging — T1056.001
    (
        {"SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
         "GetKeyState", "GetKeyboardState"},
        BehaviorCategory.COLLECTION, "Keylogging",
        "Sample installs keyboard hooks or polls key state for keylogging.",
        5, "T1056", "T1056.001",
    ),
    # Screenshot — T1113
    (
        {"BitBlt", "GetDC", "CreateCompatibleDC", "SelectObject",
         "PrintWindow"},
        BehaviorCategory.COLLECTION, "Screen Capture",
        "Sample captures screen content.",
        3, "T1113", "",
    ),
    # File encryption — T1486
    (
        {"CryptEncrypt", "BCryptEncrypt", "CryptCreateHash"},
        BehaviorCategory.EXECUTION, "Cryptographic Operations",
        "Sample performs cryptographic operations; ransomware encrypts files.",
        3, "T1486", "",
    ),
    # Lateral movement — T1021
    (
        {"WNetAddConnection2A", "WNetAddConnection2W", "WNetOpenEnumA",
         "CreateFileMapping"},
        BehaviorCategory.LATERAL_MOVEMENT, "Network Share Access",
        "Sample accesses network shares, potentially for lateral movement.",
        3, "T1021", "T1021.002",
    ),
    # Discovery — T1082
    (
        {"GetSystemInfo", "GetComputerNameA", "GetComputerNameW",
         "GetUserNameA", "GetUserNameW", "NetUserEnum", "NetShareEnum"},
        BehaviorCategory.DISCOVERY, "System Discovery",
        "Sample enumerates system and user information.",
        2, "T1082", "",
    ),
    # Privilege escalation — T1134
    (
        {"AdjustTokenPrivileges", "LookupPrivilegeValueA", "OpenProcessToken",
         "ImpersonateLoggedOnUser", "DuplicateTokenEx"},
        BehaviorCategory.PRIVILEGE_ESCALATION, "Token Manipulation",
        "Sample manipulates access tokens to escalate privileges.",
        4, "T1134", "",
    ),
]

# ---------------------------------------------------------------------------
# String-based behavioral signatures (regex patterns)
# Each: (pattern, category, name, description, severity, technique, sub)

_STRING_SIGNATURES: List[Tuple] = [
    (
        re.compile(rb"(?:HKEY_LOCAL_MACHINE|HKLM|HKCU|HKEY_CURRENT_USER)", re.IGNORECASE),
        BehaviorCategory.REGISTRY, "Registry Reference",
        "Sample references registry hive paths.",
        1, "T1012", "",
    ),
    (
        re.compile(rb"\\(?:run|runonce|winlogon|explorer)\b", re.IGNORECASE),
        BehaviorCategory.PERSISTENCE, "Autorun Registry Key",
        "Sample references common autorun registry keys.",
        4, "T1547", "T1547.001",
    ),
    (
        re.compile(rb"cmd(?:\.exe)?|powershell(?:\.exe)?", re.IGNORECASE),
        BehaviorCategory.EXECUTION, "Command Interpreter",
        "Sample references cmd.exe or PowerShell for command execution.",
        3, "T1059", "T1059.001",
    ),
    (
        re.compile(rb"(?:svchost|lsass|explorer|csrss)\.exe", re.IGNORECASE),
        BehaviorCategory.INJECTION, "System Process Reference",
        "Sample references system processes commonly targeted for injection.",
        3, "T1055", "",
    ),
    (
        re.compile(rb"https?://[^\x00\s]{8,}", re.IGNORECASE),
        BehaviorCategory.NETWORK, "Hardcoded URL",
        "Sample contains hardcoded HTTP/HTTPS URLs.",
        3, "T1071", "T1071.001",
    ),
    (
        re.compile(rb"(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}"),
        BehaviorCategory.NETWORK, "Hardcoded IP:Port",
        "Sample contains hardcoded IP:port combination, likely C2 address.",
        4, "T1071", "",
    ),
    (
        re.compile(rb"(?:ransom|encrypt|decrypt|bitcoin|wallet|\.onion)", re.IGNORECASE),
        BehaviorCategory.EXECUTION, "Ransomware Indicators",
        "Sample contains ransomware-related strings.",
        5, "T1486", "",
    ),
    (
        re.compile(rb"(?:mimikatz|sekurlsa|lsadump|wce\.exe)", re.IGNORECASE),
        BehaviorCategory.CREDENTIAL_ACCESS, "Credential Tool Reference",
        "Sample references known credential dumping tool names.",
        5, "T1003", "",
    ),
    (
        re.compile(rb"(?:tor2web|torrc|\.onion)", re.IGNORECASE),
        BehaviorCategory.NETWORK, "Tor Network Indicators",
        "Sample references Tor network infrastructure.",
        4, "T1090", "T1090.003",
    ),
    (
        re.compile(rb"(?:vboxservice|vmtoolsd|vmwaretray|vbox|virtualbox)", re.IGNORECASE),
        BehaviorCategory.ANTI_ANALYSIS, "VM Detection String",
        "Sample checks for virtualization artifacts.",
        3, "T1497", "T1497.001",
    ),
    (
        re.compile(rb"SeDebugPrivilege", re.IGNORECASE),
        BehaviorCategory.PRIVILEGE_ESCALATION, "Debug Privilege Request",
        "Sample requests SeDebugPrivilege for process access.",
        4, "T1134", "",
    ),
    (
        re.compile(rb"(?:\\Device\\Afd|RawSocket)", re.IGNORECASE),
        BehaviorCategory.NETWORK, "Raw Socket Reference",
        "Sample references raw sockets for packet crafting.",
        3, "T1095", "",
    ),
]


class BehavioralAnalyzer:
    """
    Analyzes extracted PE features for behavioral indicators.

    Inputs:
      - imports: Dict[str, List[str]]  (dll_name -> [function_names])
      - strings: List[bytes]            (extracted ASCII/Unicode strings)
      - is_packed: bool
    """

    def analyze(
        self,
        sample_hash: str,
        imports: Dict[str, List[str]],
        strings: List[bytes],
        is_packed: bool = False,
    ) -> BehaviorReport:
        report = BehaviorReport(sample_hash=sample_hash, is_packed=is_packed)

        # Flatten all imported function names to a set for O(1) lookup
        all_imports: Set[str] = set()
        for funcs in imports.values():
            all_imports.update(funcs)

        # Check import-based signatures
        for api_set, category, name, desc, sev, tech, sub in _IMPORT_SIGNATURES:
            matched = api_set & all_imports
            if matched:
                indicator = BehaviorIndicator(
                    name=name,
                    category=category,
                    description=desc,
                    severity=sev,
                    mitre_technique=tech,
                    mitre_subtechnique=sub,
                    evidence=sorted(matched),
                )
                report.add_indicator(indicator)

        # Check string-based signatures
        for pattern, category, name, desc, sev, tech, sub in _STRING_SIGNATURES:
            matches: List[str] = []
            for s in strings:
                m = pattern.search(s)
                if m:
                    matches.append(s[:64].decode("latin-1", errors="replace"))
            if matches:
                indicator = BehaviorIndicator(
                    name=name,
                    category=category,
                    description=desc,
                    severity=sev,
                    mitre_technique=tech,
                    mitre_subtechnique=sub,
                    evidence=matches[:5],
                )
                report.add_indicator(indicator)

        # Set top-level flags
        report.has_network_activity = BehaviorCategory.NETWORK in report.categories
        report.has_persistence = BehaviorCategory.PERSISTENCE in report.categories
        report.has_anti_analysis = BehaviorCategory.ANTI_ANALYSIS in report.categories

        # Heuristic malware family hints
        report.malware_families = self._classify_family(report)

        return report

    @staticmethod
    def _classify_family(report: BehaviorReport) -> List[str]:
        """Rough malware family guesses based on category combination."""
        families: List[str] = []
        cats = report.categories

        if BehaviorCategory.EXECUTION in cats and "T1486" in report.mitre_techniques:
            families.append("ransomware")

        has_inject = BehaviorCategory.INJECTION in cats
        has_network = BehaviorCategory.NETWORK in cats
        has_persist = BehaviorCategory.PERSISTENCE in cats
        has_cred = BehaviorCategory.CREDENTIAL_ACCESS in cats
        has_collect = BehaviorCategory.COLLECTION in cats

        if has_inject and has_network and has_persist and not families:
            families.append("rat")

        if has_cred and has_inject and not families:
            families.append("infostealer")

        if has_collect and has_network and "T1056" in report.mitre_techniques and not families:
            families.append("keylogger")

        if has_network and not has_inject and not has_persist and not families:
            families.append("downloader")

        if has_inject and not has_network and not families:
            families.append("loader")

        return families
