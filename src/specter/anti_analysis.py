"""
Anti-analysis and sandbox evasion detection for PE binaries.

Detects a wide range of techniques malware uses to resist static/dynamic
analysis: anti-debugging API calls, VM/hypervisor fingerprinting, timing
attacks, environment enumeration, process injection guards, anti-dump
techniques, and known sandbox-evasion patterns.

All detection is purely static (string and import table analysis) so it
works without executing the sample.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


class AntiAnalysisTechnique(str, Enum):
    # --- Anti-debugging ---
    ISDEBUGGERPRESENT = "IsDebuggerPresent"
    CHECKREMOTEDEBUGGERPRESENT = "CheckRemoteDebuggerPresent"
    NTQUERYINFORMATIONPROCESS = "NtQueryInformationProcess"
    DEBUGACTIVEPROCESS = "DebugActiveProcess"
    NTSETINFORMATIONTHREAD = "NtSetInformationThread"
    OUTPUTDEBUGSTRING = "OutputDebugString"
    CLOSEHANDLE_INVALID = "CloseHandle_InvalidHandle"
    HEAP_FLAG_CHECK = "HeapFlagCheck"
    INT3_PATCH = "SoftwareBreakpointPatch"
    HARDWARE_BREAKPOINT = "HardwareBreakpointCheck"
    DR_REGISTER_CHECK = "DebugRegisterCheck"
    PARENT_PROCESS_CHECK = "ParentProcessCheck"
    RAISEEXCEPTION_ANTIDEBUG = "RaiseException_AntiDebug"
    # --- Timing attacks ---
    RDTSC_TIMING = "RDTSC_Timing"
    GETTICKCOUNT_TIMING = "GetTickCount_Timing"
    TIMEGETTIME_TIMING = "timeGetTime_Timing"
    QUERYPERFORMANCECOUNTER = "QueryPerformanceCounter_Timing"
    SLEEP_EVASION = "SleepEvasion"
    WFSO_SLEEP = "WaitForSingleObject_Sleep"
    # --- VM / hypervisor detection ---
    CPUID_HYPERVISOR = "CPUID_HypervisorCheck"
    VMWARE_IO_PORT = "VMware_IOPort"
    VMWARE_REGISTRY = "VMware_Registry"
    VMWARE_PROCESS = "VMware_Process"
    VMWARE_MAC_ADDRESS = "VMware_MACAddress"
    VIRTUALBOX_REGISTRY = "VirtualBox_Registry"
    VIRTUALBOX_PROCESS = "VirtualBox_Process"
    VIRTUALBOX_DEVICE = "VirtualBox_Device"
    HYPERV_ARTIFACT = "HyperV_Artifact"
    QEMU_ARTIFACT = "QEMU_Artifact"
    VBOX_SHARED_FOLDER = "VirtualBox_SharedFolder"
    # --- Environment / user detection ---
    GETCOMPUTERNAME = "GetComputerName_EnvCheck"
    GETUSERNAME = "GetUserName_EnvCheck"
    GETMODULEFILENAME = "GetModuleFilename_EnvCheck"
    GETSYSTEMINFO = "GetSystemInfo_EnvCheck"
    GETSYSTEMMETRICS = "GetSystemMetrics_EnvCheck"
    GETVOLUMEINFO = "GetVolumeInfo_EnvCheck"
    SCREEN_RESOLUTION_CHECK = "ScreenResolutionCheck"
    MOUSE_MOVEMENT_CHECK = "MouseMovementCheck"
    # --- Sandbox-specific artifacts ---
    CUCKOO_PIPE = "Cuckoo_Pipe"
    SBIEDLL = "SandboxieDLL"
    WINE_ARTIFACT = "Wine_Artifact"
    ANUBIS_ARTIFACT = "Anubis_Artifact"
    THREATEXPERT_ARTIFACT = "ThreatExpert_Artifact"
    JOEBOX_ARTIFACT = "JoeBox_Artifact"
    KNOWN_SANDBOX_USERNAME = "KnownSandboxUsername"
    KNOWN_SANDBOX_HOSTNAME = "KnownSandboxHostname"
    # --- Anti-dump / memory protection ---
    NTUNMAPVIEWOFSECTION = "NtUnmapViewOfSection_AntiDump"
    VIRTUALPROTECT_EXEC = "VirtualProtect_SelfModify"
    RTLZEROMEMORY_CLEANUP = "RtlZeroMemory_PayloadCleanup"
    HEAP_WALK_DETECTION = "HeapWalk_AntiDump"
    # --- Code integrity / self-check ---
    CRC_SELF_CHECK = "CRC_SelfCheck"
    HASH_SELF_CHECK = "Hash_SelfCheck"


class EvasionSeverity(str, Enum):
    LOW = "low"           # informational, common in legitimate software
    MEDIUM = "medium"     # suspicious, uncommon outside malware
    HIGH = "high"         # strong evasion indicator
    CRITICAL = "critical" # almost exclusively used for evasion


@dataclass
class EvasionFinding:
    technique: AntiAnalysisTechnique
    severity: EvasionSeverity
    description: str
    mitre_technique: str       # ATT&CK technique ID
    mitre_subtechnique: str    # ATT&CK sub-technique ID (empty if none)
    evidence: List[str] = field(default_factory=list)  # matching strings / imports
    confidence: float = 1.0    # 0.0 – 1.0


@dataclass
class EvasionReport:
    sample_id: str
    findings: List[EvasionFinding] = field(default_factory=list)
    techniques: Set[AntiAnalysisTechnique] = field(default_factory=set)
    categories_detected: Set[str] = field(default_factory=set)
    overall_severity: EvasionSeverity = EvasionSeverity.LOW
    evasion_score: int = 0      # 0 – 100
    is_vm_aware: bool = False
    is_debugger_aware: bool = False
    is_timing_aware: bool = False
    is_sandbox_aware: bool = False
    is_environment_aware: bool = False

    def add_finding(self, finding: EvasionFinding) -> None:
        self.findings.append(finding)
        self.techniques.add(finding.technique)
        category = finding.technique.value.split("_")[0]
        self.categories_detected.add(category)

        sev_order = {
            EvasionSeverity.LOW: 1,
            EvasionSeverity.MEDIUM: 2,
            EvasionSeverity.HIGH: 3,
            EvasionSeverity.CRITICAL: 4,
        }
        if sev_order[finding.severity] > sev_order[self.overall_severity]:
            self.overall_severity = finding.severity

    def compute_score(self) -> None:
        """
        Compute a 0-100 evasion score from finding severities.
        Weights: critical=20, high=10, medium=5, low=2 — capped at 100.
        """
        weights = {
            EvasionSeverity.LOW: 2,
            EvasionSeverity.MEDIUM: 5,
            EvasionSeverity.HIGH: 10,
            EvasionSeverity.CRITICAL: 20,
        }
        total = sum(weights[f.severity] for f in self.findings)
        self.evasion_score = min(100, total)

        # Convenience flags
        vm_techs = {
            AntiAnalysisTechnique.CPUID_HYPERVISOR,
            AntiAnalysisTechnique.VMWARE_IO_PORT,
            AntiAnalysisTechnique.VMWARE_REGISTRY,
            AntiAnalysisTechnique.VMWARE_PROCESS,
            AntiAnalysisTechnique.VMWARE_MAC_ADDRESS,
            AntiAnalysisTechnique.VIRTUALBOX_REGISTRY,
            AntiAnalysisTechnique.VIRTUALBOX_PROCESS,
            AntiAnalysisTechnique.VIRTUALBOX_DEVICE,
            AntiAnalysisTechnique.HYPERV_ARTIFACT,
            AntiAnalysisTechnique.QEMU_ARTIFACT,
            AntiAnalysisTechnique.VBOX_SHARED_FOLDER,
        }
        dbg_techs = {
            AntiAnalysisTechnique.ISDEBUGGERPRESENT,
            AntiAnalysisTechnique.CHECKREMOTEDEBUGGERPRESENT,
            AntiAnalysisTechnique.NTQUERYINFORMATIONPROCESS,
            AntiAnalysisTechnique.NTSETINFORMATIONTHREAD,
            AntiAnalysisTechnique.DR_REGISTER_CHECK,
            AntiAnalysisTechnique.PARENT_PROCESS_CHECK,
        }
        timing_techs = {
            AntiAnalysisTechnique.RDTSC_TIMING,
            AntiAnalysisTechnique.GETTICKCOUNT_TIMING,
            AntiAnalysisTechnique.TIMEGETTIME_TIMING,
            AntiAnalysisTechnique.QUERYPERFORMANCECOUNTER,
            AntiAnalysisTechnique.SLEEP_EVASION,
            AntiAnalysisTechnique.WFSO_SLEEP,
        }
        sandbox_techs = {
            AntiAnalysisTechnique.CUCKOO_PIPE,
            AntiAnalysisTechnique.SBIEDLL,
            AntiAnalysisTechnique.WINE_ARTIFACT,
            AntiAnalysisTechnique.KNOWN_SANDBOX_USERNAME,
            AntiAnalysisTechnique.KNOWN_SANDBOX_HOSTNAME,
        }
        env_techs = {
            AntiAnalysisTechnique.GETCOMPUTERNAME,
            AntiAnalysisTechnique.GETUSERNAME,
            AntiAnalysisTechnique.SCREEN_RESOLUTION_CHECK,
            AntiAnalysisTechnique.MOUSE_MOVEMENT_CHECK,
        }
        self.is_vm_aware = bool(self.techniques & vm_techs)
        self.is_debugger_aware = bool(self.techniques & dbg_techs)
        self.is_timing_aware = bool(self.techniques & timing_techs)
        self.is_sandbox_aware = bool(self.techniques & sandbox_techs)
        self.is_environment_aware = bool(self.techniques & env_techs)

    def to_dict(self) -> Dict:
        return {
            "sample_id": self.sample_id,
            "evasion_score": self.evasion_score,
            "overall_severity": self.overall_severity.value,
            "finding_count": len(self.findings),
            "is_vm_aware": self.is_vm_aware,
            "is_debugger_aware": self.is_debugger_aware,
            "is_timing_aware": self.is_timing_aware,
            "is_sandbox_aware": self.is_sandbox_aware,
            "is_environment_aware": self.is_environment_aware,
            "techniques": sorted(t.value for t in self.techniques),
            "findings": [
                {
                    "technique": f.technique.value,
                    "severity": f.severity.value,
                    "description": f.description,
                    "mitre": f.mitre_technique
                    + (f".{f.mitre_subtechnique}" if f.mitre_subtechnique else ""),
                    "evidence": f.evidence,
                    "confidence": f.confidence,
                }
                for f in self.findings
            ],
        }


# ---------------------------------------------------------------------------
# Detection rule tables
# ---------------------------------------------------------------------------

# (import_name, technique, severity, mitre_tech, mitre_sub, description)
_IMPORT_RULES: List[Tuple[str, AntiAnalysisTechnique, EvasionSeverity, str, str, str]] = [
    # Anti-debugging
    ("IsDebuggerPresent", AntiAnalysisTechnique.ISDEBUGGERPRESENT, EvasionSeverity.HIGH,
     "T1622", "", "Calls IsDebuggerPresent to detect attached debuggers"),
    ("CheckRemoteDebuggerPresent", AntiAnalysisTechnique.CHECKREMOTEDEBUGGERPRESENT, EvasionSeverity.HIGH,
     "T1622", "", "Checks for remote debugger process"),
    ("NtQueryInformationProcess", AntiAnalysisTechnique.NTQUERYINFORMATIONPROCESS, EvasionSeverity.HIGH,
     "T1622", "", "Queries process debug port via NtQueryInformationProcess"),
    ("DebugActiveProcess", AntiAnalysisTechnique.DEBUGACTIVEPROCESS, EvasionSeverity.MEDIUM,
     "T1622", "", "Attaches own debugger to block external debuggers"),
    ("NtSetInformationThread", AntiAnalysisTechnique.NTSETINFORMATIONTHREAD, EvasionSeverity.HIGH,
     "T1622", "", "Hides thread from debugger via ThreadHideFromDebugger"),
    ("OutputDebugStringA", AntiAnalysisTechnique.OUTPUTDEBUGSTRING, EvasionSeverity.MEDIUM,
     "T1622", "", "OutputDebugString timing trick to detect debugger"),
    ("OutputDebugStringW", AntiAnalysisTechnique.OUTPUTDEBUGSTRING, EvasionSeverity.MEDIUM,
     "T1622", "", "OutputDebugString timing trick to detect debugger"),
    ("RaiseException", AntiAnalysisTechnique.RAISEEXCEPTION_ANTIDEBUG, EvasionSeverity.MEDIUM,
     "T1622", "", "Exception-based debugger detection via single-step trap"),
    # Timing
    ("GetTickCount", AntiAnalysisTechnique.GETTICKCOUNT_TIMING, EvasionSeverity.LOW,
     "T1497", "003", "GetTickCount timing check to detect analysis slowdown"),
    ("GetTickCount64", AntiAnalysisTechnique.GETTICKCOUNT_TIMING, EvasionSeverity.LOW,
     "T1497", "003", "GetTickCount64 timing check"),
    ("timeGetTime", AntiAnalysisTechnique.TIMEGETTIME_TIMING, EvasionSeverity.LOW,
     "T1497", "003", "timeGetTime-based timing measurement"),
    ("QueryPerformanceCounter", AntiAnalysisTechnique.QUERYPERFORMANCECOUNTER, EvasionSeverity.LOW,
     "T1497", "003", "High-resolution timer used for timing-based detection"),
    ("NtDelayExecution", AntiAnalysisTechnique.SLEEP_EVASION, EvasionSeverity.MEDIUM,
     "T1497", "003", "NtDelayExecution sleep for sandbox timeout evasion"),
    # Memory / anti-dump
    ("NtUnmapViewOfSection", AntiAnalysisTechnique.NTUNMAPVIEWOFSECTION, EvasionSeverity.HIGH,
     "T1055", "001", "Unmaps sections to hinder memory dumping"),
    ("VirtualProtect", AntiAnalysisTechnique.VIRTUALPROTECT_EXEC, EvasionSeverity.MEDIUM,
     "T1055", "", "VirtualProtect used for runtime code modification"),
    ("RtlZeroMemory", AntiAnalysisTechnique.RTLZEROMEMORY_CLEANUP, EvasionSeverity.MEDIUM,
     "T1070", "009", "Zeroes payload buffers to defeat post-execution analysis"),
    ("HeapWalk", AntiAnalysisTechnique.HEAP_WALK_DETECTION, EvasionSeverity.MEDIUM,
     "T1622", "", "HeapWalk used to inspect heap flags set by debuggers"),
    # Environment checks
    ("GetComputerNameA", AntiAnalysisTechnique.GETCOMPUTERNAME, EvasionSeverity.LOW,
     "T1497", "001", "Retrieves hostname for sandbox hostname check"),
    ("GetComputerNameW", AntiAnalysisTechnique.GETCOMPUTERNAME, EvasionSeverity.LOW,
     "T1497", "001", "Retrieves hostname for sandbox hostname check"),
    ("GetUserNameA", AntiAnalysisTechnique.GETUSERNAME, EvasionSeverity.LOW,
     "T1497", "001", "Retrieves username for sandbox username check"),
    ("GetUserNameW", AntiAnalysisTechnique.GETUSERNAME, EvasionSeverity.LOW,
     "T1497", "001", "Retrieves username for sandbox username check"),
    ("GetSystemInfo", AntiAnalysisTechnique.GETSYSTEMINFO, EvasionSeverity.LOW,
     "T1497", "001", "Checks number of processors to detect single-CPU sandboxes"),
    ("GetSystemMetrics", AntiAnalysisTechnique.GETSYSTEMMETRICS, EvasionSeverity.LOW,
     "T1497", "001", "Checks screen resolution or display metrics"),
    ("GetVolumeInformationA", AntiAnalysisTechnique.GETVOLUMEINFO, EvasionSeverity.LOW,
     "T1497", "001", "Checks disk serial number to fingerprint environment"),
    ("GetVolumeInformationW", AntiAnalysisTechnique.GETVOLUMEINFO, EvasionSeverity.LOW,
     "T1497", "001", "Checks disk serial number to fingerprint environment"),
    ("GetModuleFileNameA", AntiAnalysisTechnique.GETMODULEFILENAME, EvasionSeverity.LOW,
     "T1497", "001", "Checks executable path for sandbox-typical filenames"),
    ("GetModuleFileNameW", AntiAnalysisTechnique.GETMODULEFILENAME, EvasionSeverity.LOW,
     "T1497", "001", "Checks executable path for sandbox-typical filenames"),
]

# Strings (case-insensitive) that indicate specific evasion techniques
# (pattern, technique, severity, mitre_tech, mitre_sub, description, confidence)
_STRING_RULES: List[Tuple[str, AntiAnalysisTechnique, EvasionSeverity, str, str, str, float]] = [
    # VMware artifacts
    (r"vmware", AntiAnalysisTechnique.VMWARE_REGISTRY, EvasionSeverity.CRITICAL,
     "T1497", "001", "VMware registry key or string reference", 0.9),
    (r"VMwareService", AntiAnalysisTechnique.VMWARE_PROCESS, EvasionSeverity.CRITICAL,
     "T1497", "001", "VMware service process name", 0.95),
    (r"VMwareTray", AntiAnalysisTechnique.VMWARE_PROCESS, EvasionSeverity.CRITICAL,
     "T1497", "001", "VMware tray process name", 0.95),
    (r"vmci\.sys", AntiAnalysisTechnique.VMWARE_DEVICE, EvasionSeverity.CRITICAL,
     "T1497", "001", "VMware VMCI device driver reference", 0.95),
    (r"VBOX_MSR_|VBoxGuest|VBoxMouse|VBoxSF", AntiAnalysisTechnique.VIRTUALBOX_DEVICE, EvasionSeverity.CRITICAL,
     "T1497", "001", "VirtualBox device or driver reference", 0.95),
    (r"VBoxService\.exe|VBoxTray\.exe", AntiAnalysisTechnique.VIRTUALBOX_PROCESS, EvasionSeverity.CRITICAL,
     "T1497", "001", "VirtualBox process name", 0.95),
    (r"SOFTWARE\\Oracle\\VirtualBox|HARDWARE\\ACPI\\DSDT\\VBOX_", AntiAnalysisTechnique.VIRTUALBOX_REGISTRY, EvasionSeverity.HIGH,
     "T1497", "001", "VirtualBox registry key", 0.9),
    (r"\\VBoxMiniRdrDN", AntiAnalysisTechnique.VBOX_SHARED_FOLDER, EvasionSeverity.HIGH,
     "T1497", "001", "VirtualBox shared folder network provider path", 0.9),
    (r"KVMKVMKVM|TCGTCGTCGTCG", AntiAnalysisTechnique.QEMU_ARTIFACT, EvasionSeverity.CRITICAL,
     "T1497", "001", "QEMU/KVM CPUID hypervisor string", 1.0),
    (r"Microsoft Hv|HvHvHvHv", AntiAnalysisTechnique.HYPERV_ARTIFACT, EvasionSeverity.HIGH,
     "T1497", "001", "Hyper-V hypervisor CPUID leaf string", 0.9),
    # Sandbox artifact strings
    (r"\\\\.\\pipe\\cuckoo", AntiAnalysisTechnique.CUCKOO_PIPE, EvasionSeverity.CRITICAL,
     "T1497", "001", "Cuckoo sandbox named pipe path", 1.0),
    (r"SbieDll\.dll|SandboxieRpcSs", AntiAnalysisTechnique.SBIEDLL, EvasionSeverity.CRITICAL,
     "T1497", "001", "Sandboxie DLL name", 1.0),
    (r"wine_get_unix_file_name|ntdll\.dll\.so", AntiAnalysisTechnique.WINE_ARTIFACT, EvasionSeverity.HIGH,
     "T1497", "001", "Wine Unix shim function name", 1.0),
    (r"\banalysis\b", AntiAnalysisTechnique.ANUBIS_ARTIFACT, EvasionSeverity.MEDIUM,
     "T1497", "001", "Generic sandbox artifact path component", 0.5),
    (r"currentuser|currentUser", AntiAnalysisTechnique.KNOWN_SANDBOX_USERNAME, EvasionSeverity.MEDIUM,
     "T1497", "001", "Common sandbox default username", 0.6),
    (r"\b(sandbox|maltest|virus|malware|sample)\b", AntiAnalysisTechnique.KNOWN_SANDBOX_USERNAME, EvasionSeverity.HIGH,
     "T1497", "001", "Typical sandbox username or hostname checked", 0.8),
    (r"\b(cuckoo|vmware|vbox|virtualbox|qemu)\b", AntiAnalysisTechnique.KNOWN_SANDBOX_HOSTNAME, EvasionSeverity.CRITICAL,
     "T1497", "001", "VM or sandbox name checked as hostname", 0.9),
    # Mouse / display checks
    (r"GetCursorPos", AntiAnalysisTechnique.MOUSE_MOVEMENT_CHECK, EvasionSeverity.MEDIUM,
     "T1497", "001", "Checks cursor position for human interaction detection", 0.85),
    (r"SM_CXSCREEN|SM_CYSCREEN", AntiAnalysisTechnique.SCREEN_RESOLUTION_CHECK, EvasionSeverity.MEDIUM,
     "T1497", "001", "Checks screen resolution to detect sandbox display", 0.85),
    # RDTSC (appears as inline asm string pattern)
    (r"\x0f\x31", AntiAnalysisTechnique.RDTSC_TIMING, EvasionSeverity.HIGH,
     "T1497", "003", "RDTSC instruction byte pattern (timing check)", 0.75),
    # CRC/hash self-check patterns
    (r"CRC32|crc32", AntiAnalysisTechnique.CRC_SELF_CHECK, EvasionSeverity.MEDIUM,
     "T1542", "001", "CRC32 routine used for integrity self-verification", 0.6),
]

# Regex patterns compiled once at module load
_COMPILED_STRING_RULES: List[Tuple[re.Pattern, AntiAnalysisTechnique, EvasionSeverity, str, str, str, float]] = [
    (re.compile(pattern, re.IGNORECASE | re.MULTILINE), tech, sev, mt, ms, desc, conf)
    for pattern, tech, sev, mt, ms, desc, conf in _STRING_RULES
]


class AntiAnalysisDetector:
    """
    Detects anti-analysis and sandbox evasion techniques in PE files.

    Takes the extracted import list and decoded strings from an existing
    PE parse result and returns an :class:`EvasionReport`.

    Usage::

        from specter.pe_parser import PEParser
        from specter.string_extractor import StringExtractor
        from specter.anti_analysis import AntiAnalysisDetector

        pe = PEParser().parse(data)
        strings = StringExtractor().extract(data)
        detector = AntiAnalysisDetector()
        report = detector.analyze(
            sample_id=pe.sha256,
            imports=[imp.name for imp in pe.imports],
            strings=strings,
            raw_data=data,
        )
    """

    def analyze(
        self,
        sample_id: str,
        imports: List[str],
        strings: List[str],
        raw_data: Optional[bytes] = None,
    ) -> EvasionReport:
        """
        Run all detection passes and return a consolidated :class:`EvasionReport`.

        :param sample_id: Unique identifier for the sample (e.g. SHA-256).
        :param imports:   List of imported function names from the PE's IAT.
        :param strings:   List of decoded printable strings from the binary.
        :param raw_data:  Raw binary bytes (optional; enables byte-pattern checks).
        """
        report = EvasionReport(sample_id=sample_id)

        self._check_imports(report, imports)
        self._check_strings(report, strings)
        if raw_data:
            self._check_raw_bytes(report, raw_data)
        self._check_combined(report, imports, strings)

        report.compute_score()
        return report

    # ------------------------------------------------------------------
    # Detection passes
    # ------------------------------------------------------------------

    def _check_imports(self, report: EvasionReport, imports: List[str]) -> None:
        import_set: Set[str] = {imp.split("!")[-1] for imp in imports}
        seen: Set[AntiAnalysisTechnique] = set()
        for import_name, tech, sev, mt, ms, desc in _IMPORT_RULES:
            if tech in seen:
                continue
            for imp in import_set:
                if imp == import_name or imp.rstrip("AW") == import_name.rstrip("AW"):
                    finding = EvasionFinding(
                        technique=tech,
                        severity=sev,
                        description=desc,
                        mitre_technique=mt,
                        mitre_subtechnique=ms,
                        evidence=[imp],
                    )
                    report.add_finding(finding)
                    seen.add(tech)
                    break

    def _check_strings(self, report: EvasionReport, strings: List[str]) -> None:
        combined = "\n".join(strings)
        seen: Set[AntiAnalysisTechnique] = set()
        for pattern, tech, sev, mt, ms, desc, conf in _COMPILED_STRING_RULES:
            if tech in seen:
                continue
            matches = pattern.findall(combined)
            if matches:
                # Deduplicate match evidence, keep at most 5 examples
                unique_matches = list(dict.fromkeys(str(m) for m in matches))[:5]
                finding = EvasionFinding(
                    technique=tech,
                    severity=sev,
                    description=desc,
                    mitre_technique=mt,
                    mitre_subtechnique=ms,
                    evidence=unique_matches,
                    confidence=conf,
                )
                report.add_finding(finding)
                seen.add(tech)

    def _check_raw_bytes(self, report: EvasionReport, data: bytes) -> None:
        """
        Byte-level checks that operate on raw binary content (e.g. RDTSC opcodes,
        INT3 sled detection, CPUID byte patterns).
        """
        # RDTSC opcode: 0F 31
        if b"\x0f\x31" in data and AntiAnalysisTechnique.RDTSC_TIMING not in report.techniques:
            report.add_finding(EvasionFinding(
                technique=AntiAnalysisTechnique.RDTSC_TIMING,
                severity=EvasionSeverity.HIGH,
                description="RDTSC opcode found: high-precision timing used for sandbox evasion",
                mitre_technique="T1497",
                mitre_subtechnique="003",
                evidence=["0F 31"],
            ))

        # CPUID opcode: 0F A2
        if b"\x0f\xa2" in data and AntiAnalysisTechnique.CPUID_HYPERVISOR not in report.techniques:
            # CPUID alone is ambiguous; flag as low confidence
            report.add_finding(EvasionFinding(
                technique=AntiAnalysisTechnique.CPUID_HYPERVISOR,
                severity=EvasionSeverity.MEDIUM,
                description="CPUID opcode found: may query hypervisor presence bit (EAX=1, ECX bit 31)",
                mitre_technique="T1497",
                mitre_subtechnique="001",
                evidence=["0F A2"],
                confidence=0.6,
            ))

        # INT3 sled: 5+ consecutive 0xCC bytes = likely anti-disassembly / trap
        if re.search(b"\xcc{5,}", data) and AntiAnalysisTechnique.INT3_PATCH not in report.techniques:
            report.add_finding(EvasionFinding(
                technique=AntiAnalysisTechnique.INT3_PATCH,
                severity=EvasionSeverity.HIGH,
                description="INT3 sled detected: software breakpoint trap or anti-disassembly padding",
                mitre_technique="T1622",
                mitre_subtechnique="",
                evidence=["0xCC * 5+"],
            ))

    def _check_combined(
        self, report: EvasionReport, imports: List[str], strings: List[str]
    ) -> None:
        """
        Cross-indicator heuristics that require evidence from multiple sources.
        """
        has_sleep = any("Sleep" in imp for imp in imports)
        has_wfso = any("WaitForSingleObject" in imp for imp in imports)
        # WaitForSingleObject with a hard-coded large timeout is a common sandbox
        # evasion alternative to Sleep() which sandboxes may accelerate.
        if has_wfso and AntiAnalysisTechnique.WFSO_SLEEP not in report.techniques:
            report.add_finding(EvasionFinding(
                technique=AntiAnalysisTechnique.WFSO_SLEEP,
                severity=EvasionSeverity.MEDIUM,
                description="WaitForSingleObject imported: may be used for sleep-based sandbox evasion",
                mitre_technique="T1497",
                mitre_subtechnique="003",
                evidence=["WaitForSingleObject"],
                confidence=0.5,
            ))

        # Parent process check: CreateToolhelp32Snapshot + Process32First/Next
        # used to enumerate and verify parent is explorer.exe
        snap = any("CreateToolhelp32Snapshot" in imp for imp in imports)
        proc_iter = any(
            "Process32" in imp for imp in imports
        )
        if snap and proc_iter and AntiAnalysisTechnique.PARENT_PROCESS_CHECK not in report.techniques:
            report.add_finding(EvasionFinding(
                technique=AntiAnalysisTechnique.PARENT_PROCESS_CHECK,
                severity=EvasionSeverity.HIGH,
                description="Process enumeration via Toolhelp32: likely parent-process anti-analysis check",
                mitre_technique="T1622",
                mitre_subtechnique="",
                evidence=["CreateToolhelp32Snapshot", "Process32First/Next"],
                confidence=0.75,
            ))

        # Heap flag check: GetProcessHeap + (HeapQueryInformation or HeapWalk)
        heap_get = any("GetProcessHeap" in imp for imp in imports)
        heap_query = any("HeapQueryInformation" in imp or "HeapWalk" in imp for imp in imports)
        if heap_get and heap_query and AntiAnalysisTechnique.HEAP_FLAG_CHECK not in report.techniques:
            report.add_finding(EvasionFinding(
                technique=AntiAnalysisTechnique.HEAP_FLAG_CHECK,
                severity=EvasionSeverity.HIGH,
                description="GetProcessHeap + HeapQueryInformation/Walk: checks heap flags set by debuggers",
                mitre_technique="T1622",
                mitre_subtechnique="",
                evidence=["GetProcessHeap", "HeapQueryInformation"],
                confidence=0.8,
            ))
