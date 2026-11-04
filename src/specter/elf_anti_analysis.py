"""
ELF anti-analysis and sandbox evasion detection for Linux binaries.

Detects Linux/ELF-specific techniques malware uses to resist debugging,
dynamic analysis, and sandbox environments:

- ptrace-based anti-debugging (PTRACE_TRACEME trick, /proc/TracerPid checks)
- /proc/self filesystem inspection (status, maps, cmdline, exe)
- LD_PRELOAD / LD_AUDIT injection detection and self-checks
- prctl(PR_SET_DUMPABLE) to disable core dumps and ptrace attachment
- Signal handler manipulation for anti-disassembly / anti-debugging
- Timing attacks (clock_gettime, gettimeofday differential checks)
- Environment variable scanning for sandbox artifacts
- Known sandbox/analysis framework artifacts (Cuckoo, DRAKVUF, Any.run)
- Process / parent process enumeration via /proc
- Hypervisor and container detection (DMI, cgroup, /proc/cpuinfo strings)

All detection is purely static — string and symbol table analysis — so it
operates without executing the sample.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Technique enumeration
# ---------------------------------------------------------------------------

class ELFAntiTechnique(str, Enum):
    # --- ptrace anti-debugging ---
    PTRACE_TRACEME         = "ptrace_TRACEME_self_debug"
    PROC_TRACER_PID        = "proc_self_status_TracerPid"
    PROC_EXE_PATH          = "proc_self_exe_path_check"
    PROC_CMDLINE           = "proc_self_cmdline_check"
    PROC_MAPS_INSPECTOR    = "proc_self_maps_inspection"

    # --- prctl anti-attach ---
    PRCTL_SET_DUMPABLE     = "prctl_PR_SET_DUMPABLE_0"
    PRCTL_SET_PTRACER      = "prctl_PR_SET_PTRACER"

    # --- signal manipulation ---
    SIGNAL_SIGTRAP         = "signal_SIGTRAP_handler"
    SIGNAL_SIGILL          = "signal_SIGILL_handler"
    SIGACTION_CHAIN        = "sigaction_anti_debug_chain"

    # --- timing attacks ---
    CLOCK_GETTIME_DELTA    = "clock_gettime_timing_delta"
    GETTIMEOFDAY_DELTA     = "gettimeofday_timing_delta"
    RDTSC_INLINE           = "rdtsc_inline_asm"
    CLOCK_NANOSLEEP        = "clock_nanosleep_sandbox_evasion"

    # --- LD_PRELOAD / dynamic linker tricks ---
    LDPRELOAD_CHECK        = "LD_PRELOAD_env_check"
    LDAUDIT_CHECK          = "LD_AUDIT_env_check"
    DLOPEN_SELF_CHECK      = "dlopen_self_integrity_check"
    PLT_HOOK_DETECT        = "PLT_hook_detection"

    # --- /proc filesystem enumeration ---
    PROC_NET_TCP           = "proc_net_tcp_scan"
    PROC_CPUINFO_SCAN      = "proc_cpuinfo_hypervisor_flag"
    PROC_VERSION_SCAN      = "proc_version_string_check"
    PROC_UPTIME_CHECK      = "proc_uptime_low_value"

    # --- environment variable scanning ---
    ENV_SANDBOX_DETECT     = "env_var_sandbox_artifact"
    ENV_ANALYSIS_DETECT    = "env_var_analysis_tool_artifact"

    # --- container / VM detection ---
    CGROUP_CONTAINER       = "cgroup_container_check"
    DOCKER_ENV_FILE        = "docker_env_file_check"
    DMI_HYPERVISOR         = "dmi_hypervisor_string"
    CPUINFO_HYPERVISOR     = "cpuinfo_hypervisor_flag"
    VIRT_WHAT              = "virt_what_command_exec"

    # --- known sandbox artifacts ---
    CUCKOO_AGENT           = "cuckoo_agent_artifact"
    DRAKVUF_ARTIFACT       = "drakvuf_artifact"
    ANYRUN_ARTIFACT        = "anyrun_artifact"
    SANDBOX_HOSTNAME       = "known_sandbox_hostname"
    SANDBOX_USERNAME       = "known_sandbox_username"
    SANDBOX_PATH_ARTIFACT  = "sandbox_path_artifact"

    # --- anti-dump / memory self-protection ---
    MPROTECT_EXEC          = "mprotect_PROT_EXEC_self"
    MADVISE_DONTFORK       = "madvise_MADV_DONTFORK"
    MEMFD_SECRET           = "memfd_secret_payload"
    PROC_MEM_INJECT        = "proc_mem_self_inject"

    # --- code integrity ---
    SELF_CRC_CHECK         = "self_crc_integrity_check"
    ELF_HASH_VERIFY        = "elf_section_hash_verify"


class ELFEvasionSeverity(str, Enum):
    LOW      = "low"      # common in legitimate software
    MEDIUM   = "medium"   # suspicious, uncommon outside malware
    HIGH     = "high"     # strong evasion indicator
    CRITICAL = "critical" # almost exclusively used for evasion


@dataclass
class ELFEvasionFinding:
    technique: ELFAntiTechnique
    severity: ELFEvasionSeverity
    description: str
    mitre_technique: str        # ATT&CK technique ID
    mitre_subtechnique: str     # ATT&CK sub-technique (empty if none)
    evidence: List[str] = field(default_factory=list)
    confidence: float = 1.0     # 0.0 – 1.0


@dataclass
class ELFEvasionReport:
    sample_id: str
    findings: List[ELFEvasionFinding] = field(default_factory=list)
    techniques: Set[ELFAntiTechnique] = field(default_factory=set)
    overall_severity: ELFEvasionSeverity = ELFEvasionSeverity.LOW
    evasion_score: int = 0       # 0 – 100

    # Convenience flags
    is_ptrace_aware: bool = False
    is_vm_aware: bool = False
    is_timing_aware: bool = False
    is_sandbox_aware: bool = False
    is_env_aware: bool = False
    is_preload_aware: bool = False

    def add_finding(self, finding: ELFEvasionFinding) -> None:
        if finding.technique in self.techniques:
            return  # deduplicate
        self.findings.append(finding)
        self.techniques.add(finding.technique)

        order = {
            ELFEvasionSeverity.LOW: 1,
            ELFEvasionSeverity.MEDIUM: 2,
            ELFEvasionSeverity.HIGH: 3,
            ELFEvasionSeverity.CRITICAL: 4,
        }
        if order[finding.severity] > order[self.overall_severity]:
            self.overall_severity = finding.severity

    def compute_score(self) -> None:
        weights = {
            ELFEvasionSeverity.LOW: 2,
            ELFEvasionSeverity.MEDIUM: 5,
            ELFEvasionSeverity.HIGH: 10,
            ELFEvasionSeverity.CRITICAL: 20,
        }
        self.evasion_score = min(100, sum(weights[f.severity] for f in self.findings))

        ptrace_techs = {
            ELFAntiTechnique.PTRACE_TRACEME,
            ELFAntiTechnique.PROC_TRACER_PID,
            ELFAntiTechnique.PRCTL_SET_DUMPABLE,
            ELFAntiTechnique.PRCTL_SET_PTRACER,
            ELFAntiTechnique.SIGNAL_SIGTRAP,
        }
        vm_techs = {
            ELFAntiTechnique.DMI_HYPERVISOR,
            ELFAntiTechnique.CPUINFO_HYPERVISOR,
            ELFAntiTechnique.CGROUP_CONTAINER,
            ELFAntiTechnique.DOCKER_ENV_FILE,
            ELFAntiTechnique.PROC_CPUINFO_SCAN,
        }
        timing_techs = {
            ELFAntiTechnique.CLOCK_GETTIME_DELTA,
            ELFAntiTechnique.GETTIMEOFDAY_DELTA,
            ELFAntiTechnique.RDTSC_INLINE,
            ELFAntiTechnique.CLOCK_NANOSLEEP,
        }
        sandbox_techs = {
            ELFAntiTechnique.CUCKOO_AGENT,
            ELFAntiTechnique.DRAKVUF_ARTIFACT,
            ELFAntiTechnique.ANYRUN_ARTIFACT,
            ELFAntiTechnique.SANDBOX_HOSTNAME,
            ELFAntiTechnique.SANDBOX_USERNAME,
            ELFAntiTechnique.SANDBOX_PATH_ARTIFACT,
        }
        env_techs = {
            ELFAntiTechnique.ENV_SANDBOX_DETECT,
            ELFAntiTechnique.ENV_ANALYSIS_DETECT,
            ELFAntiTechnique.LDPRELOAD_CHECK,
            ELFAntiTechnique.LDAUDIT_CHECK,
        }
        preload_techs = {
            ELFAntiTechnique.LDPRELOAD_CHECK,
            ELFAntiTechnique.LDAUDIT_CHECK,
            ELFAntiTechnique.DLOPEN_SELF_CHECK,
            ELFAntiTechnique.PLT_HOOK_DETECT,
        }

        self.is_ptrace_aware   = bool(self.techniques & ptrace_techs)
        self.is_vm_aware       = bool(self.techniques & vm_techs)
        self.is_timing_aware   = bool(self.techniques & timing_techs)
        self.is_sandbox_aware  = bool(self.techniques & sandbox_techs)
        self.is_env_aware      = bool(self.techniques & env_techs)
        self.is_preload_aware  = bool(self.techniques & preload_techs)

    def to_dict(self) -> Dict:
        return {
            "sample_id": self.sample_id,
            "evasion_score": self.evasion_score,
            "overall_severity": self.overall_severity.value,
            "finding_count": len(self.findings),
            "is_ptrace_aware": self.is_ptrace_aware,
            "is_vm_aware": self.is_vm_aware,
            "is_timing_aware": self.is_timing_aware,
            "is_sandbox_aware": self.is_sandbox_aware,
            "is_env_aware": self.is_env_aware,
            "is_preload_aware": self.is_preload_aware,
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

# Symbol (function name) rules: (symbol, technique, severity, mitre_tech, mitre_sub, description)
_SYMBOL_RULES: List[Tuple[
    str, ELFAntiTechnique, ELFEvasionSeverity, str, str, str
]] = [
    # ptrace
    ("ptrace",         ELFAntiTechnique.PTRACE_TRACEME, ELFEvasionSeverity.HIGH,
     "T1622", "", "ptrace() imported; likely used for PTRACE_TRACEME self-debugging trick"),
    ("prctl",          ELFAntiTechnique.PRCTL_SET_DUMPABLE, ELFEvasionSeverity.HIGH,
     "T1622", "", "prctl() may set PR_SET_DUMPABLE=0 to block ptrace attachment"),
    # signal manipulation
    ("signal",         ELFAntiTechnique.SIGNAL_SIGTRAP, ELFEvasionSeverity.MEDIUM,
     "T1622", "", "signal() used to intercept SIGTRAP or SIGILL for anti-debug"),
    ("sigaction",      ELFAntiTechnique.SIGACTION_CHAIN, ELFEvasionSeverity.MEDIUM,
     "T1622", "", "sigaction() signal handler chain for anti-disassembly / anti-debug"),
    # timing
    ("clock_gettime",  ELFAntiTechnique.CLOCK_GETTIME_DELTA, ELFEvasionSeverity.LOW,
     "T1497", "003", "clock_gettime() used for high-resolution timing delta check"),
    ("gettimeofday",   ELFAntiTechnique.GETTIMEOFDAY_DELTA, ELFEvasionSeverity.LOW,
     "T1497", "003", "gettimeofday() timing measurement for sandbox slowdown detection"),
    ("clock_nanosleep",ELFAntiTechnique.CLOCK_NANOSLEEP, ELFEvasionSeverity.MEDIUM,
     "T1497", "003", "clock_nanosleep() for sandbox timeout evasion"),
    # dynamic linker
    ("dlopen",         ELFAntiTechnique.DLOPEN_SELF_CHECK, ELFEvasionSeverity.MEDIUM,
     "T1574", "006", "dlopen() self-inspection or PLT hook detection"),
    ("dlsym",          ELFAntiTechnique.PLT_HOOK_DETECT, ELFEvasionSeverity.MEDIUM,
     "T1574", "006", "dlsym() for runtime PLT/GOT hook detection"),
    # memory self-protection
    ("mprotect",       ELFAntiTechnique.MPROTECT_EXEC, ELFEvasionSeverity.MEDIUM,
     "T1055", "009", "mprotect(PROT_EXEC) for runtime code modification"),
    ("madvise",        ELFAntiTechnique.MADVISE_DONTFORK, ELFEvasionSeverity.LOW,
     "T1055", "", "madvise(MADV_DONTFORK) to prevent memory region inheritance on fork"),
    ("memfd_create",   ELFAntiTechnique.MEMFD_SECRET, ELFEvasionSeverity.HIGH,
     "T1055", "009", "memfd_create() for anonymous in-memory payload execution"),
    # integrity
    ("crc32",          ELFAntiTechnique.SELF_CRC_CHECK, ELFEvasionSeverity.MEDIUM,
     "T1542", "001", "CRC32 routine present; may verify own code integrity"),
]

# String pattern rules (case-insensitive unless specified):
# (pattern, technique, severity, mitre_tech, mitre_sub, description, confidence)
_STRING_RULES: List[Tuple[str, ELFAntiTechnique, ELFEvasionSeverity, str, str, str, float]] = [
    # /proc anti-debugging
    (r"/proc/self/status",       ELFAntiTechnique.PROC_TRACER_PID,     ELFEvasionSeverity.HIGH,
     "T1622", "", "/proc/self/status read; likely checking TracerPid for debugger", 0.9),
    (r"TracerPid",               ELFAntiTechnique.PROC_TRACER_PID,     ELFEvasionSeverity.CRITICAL,
     "T1622", "", "TracerPid field parsed directly from /proc/self/status", 1.0),
    (r"/proc/self/exe",          ELFAntiTechnique.PROC_EXE_PATH,       ELFEvasionSeverity.MEDIUM,
     "T1497", "001", "/proc/self/exe read to check if running from expected path", 0.7),
    (r"/proc/self/cmdline",      ELFAntiTechnique.PROC_CMDLINE,        ELFEvasionSeverity.MEDIUM,
     "T1497", "001", "/proc/self/cmdline inspected for debugger arguments", 0.7),
    (r"/proc/self/maps",         ELFAntiTechnique.PROC_MAPS_INSPECTOR, ELFEvasionSeverity.HIGH,
     "T1622", "", "/proc/self/maps scanned for injected libraries or hooking frameworks", 0.85),
    (r"/proc/net/tcp",           ELFAntiTechnique.PROC_NET_TCP,        ELFEvasionSeverity.MEDIUM,
     "T1497", "001", "/proc/net/tcp scanned for analysis-tool listening ports", 0.7),
    (r"/proc/uptime",            ELFAntiTechnique.PROC_UPTIME_CHECK,   ELFEvasionSeverity.MEDIUM,
     "T1497", "001", "/proc/uptime read; sandbox detection via low uptime value", 0.65),
    (r"/proc/cpuinfo",           ELFAntiTechnique.PROC_CPUINFO_SCAN,   ELFEvasionSeverity.MEDIUM,
     "T1497", "001", "/proc/cpuinfo scanned for hypervisor flag or CPU count", 0.7),
    (r"/proc/version",           ELFAntiTechnique.PROC_VERSION_SCAN,   ELFEvasionSeverity.LOW,
     "T1497", "001", "/proc/version read to fingerprint kernel for sandbox detection", 0.5),

    # LD_PRELOAD / dynamic linker
    (r"LD_PRELOAD",              ELFAntiTechnique.LDPRELOAD_CHECK,     ELFEvasionSeverity.HIGH,
     "T1574", "006", "LD_PRELOAD env var checked; may detect hooking frameworks", 0.9),
    (r"LD_AUDIT",                ELFAntiTechnique.LDAUDIT_CHECK,       ELFEvasionSeverity.HIGH,
     "T1574", "006", "LD_AUDIT env var checked; detects audit-based monitoring", 0.9),

    # prctl PR_SET_PTRACER
    (r"PR_SET_PTRACER",          ELFAntiTechnique.PRCTL_SET_PTRACER,   ELFEvasionSeverity.HIGH,
     "T1622", "", "PR_SET_PTRACER used to restrict which process can attach via ptrace", 0.95),

    # container / VM detection strings
    (r"\.dockerenv|/\.dockerenv", ELFAntiTechnique.DOCKER_ENV_FILE,   ELFEvasionSeverity.MEDIUM,
     "T1497", "001", "/.dockerenv file checked to detect Docker container", 0.85),
    (r"/sys/fs/cgroup",          ELFAntiTechnique.CGROUP_CONTAINER,    ELFEvasionSeverity.MEDIUM,
     "T1497", "001", "cgroup filesystem inspected for container fingerprinting", 0.75),
    (r"hypervisor|vmx|svm|kvm",  ELFAntiTechnique.CPUINFO_HYPERVISOR, ELFEvasionSeverity.HIGH,
     "T1497", "001", "Hypervisor-related string from /proc/cpuinfo flags", 0.85),
    (r"/sys/class/dmi/id/",      ELFAntiTechnique.DMI_HYPERVISOR,      ELFEvasionSeverity.HIGH,
     "T1497", "001", "DMI sysfs path read to detect hypervisor vendor string", 0.9),
    (r"virt-what",               ELFAntiTechnique.VIRT_WHAT,           ELFEvasionSeverity.HIGH,
     "T1497", "001", "virt-what command executed to identify virtualisation type", 0.85),

    # sandbox artifact strings
    (r"cuckoo",                  ELFAntiTechnique.CUCKOO_AGENT,        ELFEvasionSeverity.CRITICAL,
     "T1497", "001", "Cuckoo sandbox string reference", 1.0),
    (r"drakvuf",                 ELFAntiTechnique.DRAKVUF_ARTIFACT,    ELFEvasionSeverity.CRITICAL,
     "T1497", "001", "DRAKVUF dynamic analysis platform string", 1.0),
    (r"any\.run|anyrun",         ELFAntiTechnique.ANYRUN_ARTIFACT,     ELFEvasionSeverity.CRITICAL,
     "T1497", "001", "Any.Run online sandbox artifact string", 1.0),
    (r"\b(sandbox|maltest|malware|sample|virus)\b",
                                 ELFAntiTechnique.SANDBOX_USERNAME,    ELFEvasionSeverity.HIGH,
     "T1497", "001", "Typical sandbox username or hostname string checked", 0.8),
    (r"/home/user/|/home/analyst/|/home/sandbox/",
                                 ELFAntiTechnique.SANDBOX_PATH_ARTIFACT, ELFEvasionSeverity.HIGH,
     "T1497", "001", "Known sandbox home directory path referenced", 0.85),
    (r"\b(analysis|analysispc|WIN7-SANDBOX|MALWARE-PC)\b",
                                 ELFAntiTechnique.SANDBOX_HOSTNAME,    ELFEvasionSeverity.HIGH,
     "T1497", "001", "Known sandbox hostname string", 0.85),

    # environment variable scanning
    (r"ANALYSIS_|CUCKOO_|MALWARE_",
                                 ELFAntiTechnique.ENV_SANDBOX_DETECT,  ELFEvasionSeverity.HIGH,
     "T1497", "001", "Sandbox-specific environment variable names checked", 0.9),
    (r"FRIDA_|FRIDA_AGENT|_FRIDA",
                                 ELFAntiTechnique.ENV_ANALYSIS_DETECT, ELFEvasionSeverity.CRITICAL,
     "T1497", "001", "Frida dynamic instrumentation environment variable checked", 1.0),
    (r"INJECT_DYLIB|_DYLIB_INSERT",
                                 ELFAntiTechnique.ENV_ANALYSIS_DETECT, ELFEvasionSeverity.CRITICAL,
     "T1497", "001", "DYLIB injection environment variable checked", 1.0),

    # memfd / anonymous execution
    (r"memfd:|\[memfd\]",        ELFAntiTechnique.MEMFD_SECRET,        ELFEvasionSeverity.HIGH,
     "T1055", "009", "memfd anonymous file descriptor name referenced for in-memory execution", 0.9),

    # /proc/self/mem injection
    (r"/proc/self/mem",          ELFAntiTechnique.PROC_MEM_INJECT,     ELFEvasionSeverity.CRITICAL,
     "T1055", "009", "/proc/self/mem write used for self-injection without mprotect", 1.0),
]

# Compile all regex patterns at module load time
_COMPILED_STRING_RULES: List[Tuple[
    re.Pattern, ELFAntiTechnique, ELFEvasionSeverity, str, str, str, float
]] = [
    (re.compile(pattern, re.IGNORECASE | re.MULTILINE), tech, sev, mt, ms, desc, conf)
    for pattern, tech, sev, mt, ms, desc, conf in _STRING_RULES
]


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class ELFAntiAnalysisDetector:
    """
    Detects anti-analysis techniques in ELF binaries using static analysis.

    Accepts the imported/exported symbol list and decoded printable strings
    from an ELF parse result, plus optional raw bytes for opcode-level checks.

    Usage::

        from specter.elf_parser import ELFParser
        from specter.string_extractor import StringExtractor
        from specter.elf_anti_analysis import ELFAntiAnalysisDetector

        result = ELFParser().parse(data)
        strings = StringExtractor().extract(data)
        detector = ELFAntiAnalysisDetector()
        report = detector.analyze(
            sample_id=result.sha256,
            symbols=result.imported_symbols + result.exported_symbols,
            strings=strings,
            raw_data=data,
        )
        print(report.to_dict())
    """

    def analyze(
        self,
        sample_id: str,
        symbols: List[str],
        strings: List[str],
        raw_data: Optional[bytes] = None,
    ) -> ELFEvasionReport:
        """
        Run all detection passes and return a consolidated :class:`ELFEvasionReport`.

        :param sample_id: Unique identifier (e.g. SHA-256 of the binary).
        :param symbols:   Imported/exported symbol names from the ELF dynamic symbol table.
        :param strings:   Decoded printable strings extracted from the binary.
        :param raw_data:  Raw binary bytes (optional; enables opcode-level checks).
        """
        report = ELFEvasionReport(sample_id=sample_id)

        self._check_symbols(report, symbols)
        self._check_strings(report, strings)
        if raw_data:
            self._check_raw_bytes(report, raw_data)
        self._check_combined(report, symbols, strings)

        report.compute_score()
        return report

    # ------------------------------------------------------------------
    # Detection passes
    # ------------------------------------------------------------------

    def _check_symbols(self, report: ELFEvasionReport, symbols: List[str]) -> None:
        """Check dynamic symbol table against known anti-analysis APIs."""
        symbol_set: Set[str] = set(symbols)
        for sym_name, tech, sev, mt, ms, desc in _SYMBOL_RULES:
            if tech in report.techniques:
                continue
            # Match exact symbol name or stripped version prefix
            if sym_name in symbol_set or any(s == sym_name for s in symbol_set):
                report.add_finding(ELFEvasionFinding(
                    technique=tech,
                    severity=sev,
                    description=desc,
                    mitre_technique=mt,
                    mitre_subtechnique=ms,
                    evidence=[sym_name],
                ))

    def _check_strings(self, report: ELFEvasionReport, strings: List[str]) -> None:
        """Scan decoded strings against pattern rules."""
        combined = "\n".join(strings)
        for pattern, tech, sev, mt, ms, desc, conf in _COMPILED_STRING_RULES:
            if tech in report.techniques:
                continue
            matches = pattern.findall(combined)
            if matches:
                unique = list(dict.fromkeys(str(m) for m in matches))[:5]
                report.add_finding(ELFEvasionFinding(
                    technique=tech,
                    severity=sev,
                    description=desc,
                    mitre_technique=mt,
                    mitre_subtechnique=ms,
                    evidence=unique,
                    confidence=conf,
                ))

    def _check_raw_bytes(self, report: ELFEvasionReport, data: bytes) -> None:
        """Byte-level opcode and pattern checks."""
        # RDTSC: 0F 31 — high-precision timing, used for sandbox slowdown detection
        if (b"\x0f\x31" in data
                and ELFAntiTechnique.RDTSC_INLINE not in report.techniques):
            report.add_finding(ELFEvasionFinding(
                technique=ELFAntiTechnique.RDTSC_INLINE,
                severity=ELFEvasionSeverity.HIGH,
                description="RDTSC opcode (0F 31) in ELF: high-precision timing for sandbox detection",
                mitre_technique="T1497",
                mitre_subtechnique="003",
                evidence=["0F 31"],
            ))

        # CPUID: 0F A2 — hypervisor presence bit
        if (b"\x0f\xa2" in data
                and ELFAntiTechnique.CPUINFO_HYPERVISOR not in report.techniques):
            report.add_finding(ELFEvasionFinding(
                technique=ELFAntiTechnique.CPUINFO_HYPERVISOR,
                severity=ELFEvasionSeverity.MEDIUM,
                description="CPUID opcode (0F A2): may query hypervisor presence bit",
                mitre_technique="T1497",
                mitre_subtechnique="001",
                evidence=["0F A2"],
                confidence=0.6,
            ))

        # INT3 sled: 5+ consecutive 0xCC bytes = anti-disassembly padding
        if re.search(b"\xcc{5,}", data):
            report.add_finding(ELFEvasionFinding(
                technique=ELFAntiTechnique.SIGNAL_SIGTRAP,
                severity=ELFEvasionSeverity.HIGH,
                description="INT3 sled (0xCC * 5+): anti-disassembly padding or trap chain",
                mitre_technique="T1622",
                mitre_subtechnique="",
                evidence=["0xCC * 5+"],
            ))

    def _check_combined(
        self,
        report: ELFEvasionReport,
        symbols: List[str],
        strings: List[str],
    ) -> None:
        """
        Multi-indicator heuristics that require evidence from multiple sources.
        """
        sym_set = set(symbols)
        all_strings = "\n".join(strings).lower()

        # ptrace + fork: PTRACE_TRACEME self-debugging
        # ptrace is already flagged above; boost confidence if fork is also present
        has_fork = "fork" in sym_set or "__libc_fork" in sym_set
        has_ptrace = "ptrace" in sym_set
        if (has_ptrace and has_fork
                and ELFAntiTechnique.PTRACE_TRACEME in report.techniques):
            # Upgrade existing finding severity context note (re-add won't duplicate)
            for f in report.findings:
                if f.technique == ELFAntiTechnique.PTRACE_TRACEME:
                    if "fork" not in f.evidence:
                        f.evidence.append("fork (confirms PTRACE_TRACEME pattern)")
                    break

        # clock_gettime + nanosleep: classic sleep-based sandbox evasion combo
        has_clock = "clock_gettime" in sym_set or "gettimeofday" in sym_set
        has_sleep = "nanosleep" in sym_set or "usleep" in sym_set or "sleep" in sym_set
        if (has_clock and has_sleep
                and ELFAntiTechnique.CLOCK_NANOSLEEP not in report.techniques):
            report.add_finding(ELFEvasionFinding(
                technique=ELFAntiTechnique.CLOCK_NANOSLEEP,
                severity=ELFEvasionSeverity.MEDIUM,
                description="clock_gettime/gettimeofday + sleep combination: "
                            "timing-based sandbox evasion",
                mitre_technique="T1497",
                mitre_subtechnique="003",
                evidence=list(
                    {s for s in sym_set if s in
                     {"clock_gettime", "gettimeofday", "nanosleep", "usleep", "sleep"}}
                ),
                confidence=0.7,
            ))

        # getenv + sandbox keyword strings: environment variable scanning
        has_getenv = "getenv" in sym_set or "secure_getenv" in sym_set
        sandbox_env_keywords = {"ld_preload", "ld_audit", "cuckoo", "frida", "analysis_"}
        env_hits = [kw for kw in sandbox_env_keywords if kw in all_strings]
        if (has_getenv and env_hits
                and ELFAntiTechnique.ENV_SANDBOX_DETECT not in report.techniques):
            report.add_finding(ELFEvasionFinding(
                technique=ELFAntiTechnique.ENV_SANDBOX_DETECT,
                severity=ELFEvasionSeverity.HIGH,
                description="getenv() with sandbox-specific variable names: "
                            "scanning environment for analysis tool artifacts",
                mitre_technique="T1497",
                mitre_subtechnique="001",
                evidence=["getenv"] + env_hits,
                confidence=0.85,
            ))

        # open + /proc/self/status or TracerPid string: direct TracerPid check
        has_open = "open" in sym_set or "fopen" in sym_set
        tracer_check = "tracerpid" in all_strings or "/proc/self/status" in all_strings
        if (has_open and tracer_check
                and ELFAntiTechnique.PROC_TRACER_PID not in report.techniques):
            report.add_finding(ELFEvasionFinding(
                technique=ELFAntiTechnique.PROC_TRACER_PID,
                severity=ELFEvasionSeverity.CRITICAL,
                description="open()/fopen() + TracerPid: reads /proc/self/status to detect debugger",
                mitre_technique="T1622",
                mitre_subtechnique="",
                evidence=["open/fopen", "/proc/self/status"],
                confidence=0.95,
            ))
