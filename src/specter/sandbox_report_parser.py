"""
Sandbox dynamic analysis report parser.
Ingests Cuckoo / CAPE / any.run compatible JSON reports and extracts
behavioral indicators: process trees, API call sequences, network activity,
file system and registry operations, dropped files, and MITRE ATT&CK mappings.
Integrates output with the existing BehaviorReport and sample database models.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from specter.behavioral import BehaviorCategory, BehaviorIndicator, BehaviorReport


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class SandboxFormat(str, Enum):
    CUCKOO   = "cuckoo"    # Cuckoo Sandbox / CAPE
    ANY_RUN  = "any_run"   # any.run JSON export
    HYBRID   = "hybrid"    # Hybrid Analysis (Falcon Sandbox)
    TRIAGE   = "triage"    # Hatching Triage
    AUTO     = "auto"      # Auto-detect


class ProcessStatus(str, Enum):
    CREATED    = "created"
    TERMINATED = "terminated"
    INJECTED   = "injected"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ProcessNode:
    """A node in the process tree."""
    pid: int
    ppid: int
    name: str
    command_line: str
    image_path: str
    status: ProcessStatus = ProcessStatus.CREATED
    children: List["ProcessNode"] = field(default_factory=list)
    api_calls: List["APICall"] = field(default_factory=list)
    injected: bool = False
    hollowed: bool = False

    def flat_children(self) -> List["ProcessNode"]:
        result = list(self.children)
        for child in self.children:
            result.extend(child.flat_children())
        return result


@dataclass
class APICall:
    """A single captured API / syscall."""
    api_name: str
    category: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    return_value: Any = None
    timestamp: float = 0.0
    status: bool = True     # True = success

    @property
    def key_arg(self) -> str:
        """Return the most meaningful argument string for display."""
        for key in ("filename", "filepath", "path", "regkey", "key", "url",
                    "ip", "hostname", "service_name", "classname", "buffer"):
            if key in self.arguments:
                val = self.arguments[key]
                if isinstance(val, str):
                    return val
        return ""


@dataclass
class NetworkConnection:
    """A captured network connection."""
    protocol: str        # tcp, udp, dns, http, https
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    dst_host: str = ""
    url: str = ""
    method: str = ""
    user_agent: str = ""
    request_body: str = ""
    response_code: int = 0
    is_c2_candidate: bool = False


@dataclass
class DNSQuery:
    request: str
    response: List[str] = field(default_factory=list)


@dataclass
class FileOperation:
    """A file system operation observed during execution."""
    operation: str   # create, read, write, delete, copy, rename, modify
    path: str
    new_path: str = ""      # for rename/copy
    size: int = 0
    md5: str = ""
    sha256: str = ""
    is_dropped: bool = False


@dataclass
class RegistryOperation:
    """A Windows registry operation."""
    operation: str   # read, write, delete, create_key
    key: str
    value_name: str = ""
    data: str = ""
    data_type: str = ""


@dataclass
class DroppedFile:
    """A file dropped / written during execution."""
    path: str
    md5: str = ""
    sha256: str = ""
    size: int = 0
    file_type: str = ""
    yara_matches: List[str] = field(default_factory=list)
    is_malicious: bool = False


@dataclass
class MutexEvent:
    operation: str  # create, open
    name: str


@dataclass
class SandboxReport:
    """Parsed and normalized sandbox analysis report."""
    sample_sha256: str
    sample_md5: str = ""
    sample_name: str = ""
    format: SandboxFormat = SandboxFormat.AUTO
    analysis_id: str = ""
    analysis_time: Optional[datetime] = None
    score: int = 0                    # 0-100 maliciousness score
    verdict: str = ""                 # malicious / suspicious / clean

    processes: List[ProcessNode] = field(default_factory=list)
    network_connections: List[NetworkConnection] = field(default_factory=list)
    dns_queries: List[DNSQuery] = field(default_factory=list)
    file_operations: List[FileOperation] = field(default_factory=list)
    registry_operations: List[RegistryOperation] = field(default_factory=list)
    dropped_files: List[DroppedFile] = field(default_factory=list)
    mutexes: List[MutexEvent] = field(default_factory=list)

    behavior_report: Optional[BehaviorReport] = None
    mitre_techniques: Set[str] = field(default_factory=set)
    tags: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def all_processes(self) -> List[ProcessNode]:
        result = list(self.processes)
        for p in self.processes:
            result.extend(p.flat_children())
        return result

    @property
    def unique_c2_candidates(self) -> List[str]:
        candidates = []
        for conn in self.network_connections:
            if conn.is_c2_candidate:
                addr = conn.dst_host or conn.dst_ip
                if addr not in candidates:
                    candidates.append(addr)
        return candidates

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_sha256": self.sample_sha256,
            "sample_md5": self.sample_md5,
            "sample_name": self.sample_name,
            "analysis_id": self.analysis_id,
            "score": self.score,
            "verdict": self.verdict,
            "format": self.format.value,
            "tags": self.tags,
            "mitre_techniques": sorted(self.mitre_techniques),
            "process_count": len(self.all_processes),
            "network_connections": len(self.network_connections),
            "dns_queries": len(self.dns_queries),
            "dropped_files": [
                {"path": f.path, "sha256": f.sha256, "type": f.file_type,
                 "malicious": f.is_malicious}
                for f in self.dropped_files
            ],
            "c2_candidates": self.unique_c2_candidates,
            "behavior_indicators": (
                [
                    {
                        "name": ind.name,
                        "category": ind.category.value,
                        "severity": ind.severity,
                        "technique": ind.mitre_technique,
                        "evidence": ind.evidence[:5],
                    }
                    for ind in self.behavior_report.indicators
                ]
                if self.behavior_report else []
            ),
        }


# ---------------------------------------------------------------------------
# MITRE ATT&CK technique mappings
# ---------------------------------------------------------------------------

# API-call patterns → (technique_id, sub_technique, name, category, severity)
_API_MITRE_MAP: List[Tuple[str, str, str, BehaviorCategory, int]] = [
    # Process injection
    ("VirtualAllocEx",      "T1055",     "Process Injection",         BehaviorCategory.INJECTION, 4),
    ("WriteProcessMemory",  "T1055",     "Process Injection",         BehaviorCategory.INJECTION, 4),
    ("CreateRemoteThread",  "T1055.001", "Remote Thread Injection",   BehaviorCategory.INJECTION, 5),
    ("NtCreateThreadEx",    "T1055.001", "Remote Thread Injection",   BehaviorCategory.INJECTION, 5),
    ("SetWindowsHookEx",    "T1056.001", "Keylogging via Hook",       BehaviorCategory.COLLECTION, 4),
    # Process hollowing
    ("ZwUnmapViewOfSection","T1055.012", "Process Hollowing",         BehaviorCategory.INJECTION, 5),
    ("NtUnmapViewOfSection","T1055.012", "Process Hollowing",         BehaviorCategory.INJECTION, 5),
    # Persistence
    ("RegSetValueEx",       "T1547.001", "Registry Run Keys",         BehaviorCategory.PERSISTENCE, 3),
    ("CreateService",       "T1543.003", "Windows Service Creation",  BehaviorCategory.PERSISTENCE, 4),
    ("NtSetValueKey",       "T1547.001", "Registry Run Keys",         BehaviorCategory.PERSISTENCE, 3),
    # Defense evasion
    ("IsDebuggerPresent",   "T1622",     "Debugger Evasion",          BehaviorCategory.ANTI_ANALYSIS, 3),
    ("CheckRemoteDebuggerPresent", "T1622", "Debugger Evasion",       BehaviorCategory.ANTI_ANALYSIS, 3),
    ("NtQueryInformationProcess", "T1622", "Debugger Evasion",        BehaviorCategory.ANTI_ANALYSIS, 3),
    ("GetTickCount",        "T1497.003", "Time-Based Evasion",        BehaviorCategory.ANTI_ANALYSIS, 2),
    ("Sleep",               "T1497.003", "Time-Based Evasion",        BehaviorCategory.ANTI_ANALYSIS, 2),
    ("GetSystemTime",       "T1497.003", "Time-Based Evasion",        BehaviorCategory.ANTI_ANALYSIS, 1),
    # Credential access
    ("LsaQueryInformationPolicy", "T1003", "Credential Dumping",      BehaviorCategory.CREDENTIAL_ACCESS, 5),
    ("SamOpenDatabase",     "T1003.002", "SAM Credential Dumping",    BehaviorCategory.CREDENTIAL_ACCESS, 5),
    ("CryptProtectData",    "T1555",     "Credentials from Password Stores", BehaviorCategory.CREDENTIAL_ACCESS, 4),
    # Network
    ("InternetConnectA",    "T1071.001", "Web Protocol C2",           BehaviorCategory.NETWORK, 3),
    ("InternetConnectW",    "T1071.001", "Web Protocol C2",           BehaviorCategory.NETWORK, 3),
    ("WSAConnect",          "T1095",     "Non-Application Layer C2",  BehaviorCategory.NETWORK, 3),
    ("HttpSendRequest",     "T1071.001", "Web Protocol C2",           BehaviorCategory.NETWORK, 2),
    ("URLDownloadToFileA",  "T1105",     "Ingress Tool Transfer",     BehaviorCategory.NETWORK, 3),
    ("URLDownloadToFileW",  "T1105",     "Ingress Tool Transfer",     BehaviorCategory.NETWORK, 3),
    # Execution
    ("ShellExecuteEx",      "T1059",     "Command Interpreter",       BehaviorCategory.EXECUTION, 3),
    ("WinExec",             "T1059",     "Command Execution",         BehaviorCategory.EXECUTION, 3),
    ("CreateProcessA",      "T1106",     "Native API Process Creation",BehaviorCategory.EXECUTION, 2),
    ("CreateProcessW",      "T1106",     "Native API Process Creation",BehaviorCategory.EXECUTION, 2),
    # Collection
    ("GetClipboardData",    "T1115",     "Clipboard Data",            BehaviorCategory.COLLECTION, 3),
    ("BitBlt",              "T1113",     "Screen Capture",            BehaviorCategory.COLLECTION, 3),
    # Discovery
    ("GetSystemInfo",       "T1082",     "System Information Discovery", BehaviorCategory.DISCOVERY, 1),
    ("EnumProcesses",       "T1057",     "Process Discovery",         BehaviorCategory.DISCOVERY, 2),
    ("NetUserEnum",         "T1087.001", "Local Account Discovery",   BehaviorCategory.DISCOVERY, 3),
    ("RegOpenKeyEx",        "T1012",     "Registry Query",            BehaviorCategory.DISCOVERY, 1),
    # Privilege escalation
    ("AdjustTokenPrivileges", "T1134",   "Access Token Manipulation", BehaviorCategory.PRIVILEGE_ESCALATION, 4),
    ("ImpersonateLoggedOnUser", "T1134.001", "Token Impersonation",   BehaviorCategory.PRIVILEGE_ESCALATION, 5),
]

# Build lookup dict
_API_MITRE_LOOKUP: Dict[str, Tuple[str, str, str, BehaviorCategory, int]] = {
    entry[0]: entry[1:] for entry in _API_MITRE_MAP
}

# Registry key patterns → MITRE technique
_REGISTRY_MITRE_MAP: List[Tuple[re.Pattern, str, str, BehaviorCategory, int]] = [
    (re.compile(r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", re.I),
     "T1547.001", "Registry Run Key Persistence", BehaviorCategory.PERSISTENCE, 4),
    (re.compile(r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", re.I),
     "T1547.001", "Registry Run Key Persistence", BehaviorCategory.PERSISTENCE, 4),
    (re.compile(r"HKLM\\SYSTEM\\CurrentControlSet\\Services", re.I),
     "T1543.003", "Windows Service Registry Key", BehaviorCategory.PERSISTENCE, 3),
    (re.compile(r"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", re.I),
     "T1546.012", "Image File Execution Options Debugger", BehaviorCategory.DEFENSE_EVASION, 5),
    (re.compile(r"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot", re.I),
     "T1562.001", "Safe Mode Boot Modification", BehaviorCategory.DEFENSE_EVASION, 5),
]

# Network indicators
_C2_PORT_HEURISTICS: Set[int] = {4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 443, 80, 8080}
_SUSPICIOUS_UA_PATTERNS = re.compile(
    r"(curl|wget|python|go-http|libwww|WinHTTP|PowerShell)", re.I
)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class SandboxParseError(Exception):
    pass


class SandboxReportParser:
    """
    Parses dynamic analysis sandbox JSON reports into a normalized SandboxReport.

    Supported formats: Cuckoo/CAPE, any.run, Hybrid Analysis, Hatching Triage.
    Format auto-detection is performed when format=SandboxFormat.AUTO.

    Usage::

        with open("report.json") as f:
            data = json.load(f)
        parser = SandboxReportParser(data)
        report = parser.parse()
    """

    def __init__(
        self,
        raw: Dict[str, Any],
        fmt: SandboxFormat = SandboxFormat.AUTO,
    ) -> None:
        self._raw = raw
        self._fmt = fmt

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self) -> SandboxReport:
        fmt = self._detect_format() if self._fmt == SandboxFormat.AUTO else self._fmt

        if fmt == SandboxFormat.CUCKOO:
            report = self._parse_cuckoo()
        elif fmt == SandboxFormat.ANY_RUN:
            report = self._parse_any_run()
        elif fmt == SandboxFormat.HYBRID:
            report = self._parse_hybrid()
        elif fmt == SandboxFormat.TRIAGE:
            report = self._parse_triage()
        else:
            raise SandboxParseError(f"Unknown sandbox format: {fmt}")

        report.format = fmt
        self._map_mitre_techniques(report)
        self._detect_c2_candidates(report)
        report.behavior_report = self._build_behavior_report(report)
        return report

    # ------------------------------------------------------------------
    # Format detection
    # ------------------------------------------------------------------

    def _detect_format(self) -> SandboxFormat:
        raw = self._raw
        # Cuckoo/CAPE: has "info" key with "version", "category" under "info"
        if "info" in raw and isinstance(raw.get("info"), dict):
            info = raw["info"]
            if "version" in info or "category" in info:
                return SandboxFormat.CUCKOO
        # any.run: has "analysis" key with "content" sub-key
        if "analysis" in raw and isinstance(raw.get("analysis"), dict):
            if "content" in raw["analysis"] or "verdict" in raw["analysis"]:
                return SandboxFormat.ANY_RUN
        # Hybrid Analysis: has "hybrid-analysis" or "threatscore"
        if "threatscore" in raw or "hybrid-analysis" in raw:
            return SandboxFormat.HYBRID
        # Hatching Triage: has "sample" and "signatures" and "targets"
        if "sample" in raw and "targets" in raw:
            return SandboxFormat.TRIAGE
        # Default to cuckoo-like
        return SandboxFormat.CUCKOO

    # ------------------------------------------------------------------
    # Cuckoo / CAPE parser
    # ------------------------------------------------------------------

    def _parse_cuckoo(self) -> SandboxReport:
        raw = self._raw
        info = raw.get("info", {})
        target = raw.get("target", {})
        file_info = target.get("file", {})

        report = SandboxReport(
            sample_sha256=file_info.get("sha256", ""),
            sample_md5=file_info.get("md5", ""),
            sample_name=file_info.get("name", ""),
            analysis_id=str(info.get("id", "")),
            score=raw.get("malscore", 0),
            verdict=self._cuckoo_verdict(raw.get("malscore", 0)),
        )

        # Process tree
        process_tree = raw.get("processtree", [])
        for proc_raw in process_tree:
            report.processes.append(self._parse_cuckoo_process(proc_raw))

        # API calls (flattened from processes)
        for proc_raw in raw.get("behavior", {}).get("processes", []):
            proc_node = self._find_process(report.processes, proc_raw.get("pid", -1))
            for call in proc_raw.get("calls", []):
                api_call = APICall(
                    api_name=call.get("api", ""),
                    category=call.get("category", ""),
                    arguments=call.get("arguments", {}),
                    return_value=call.get("return", None),
                    timestamp=call.get("timestamp", 0.0),
                    status=call.get("status", True),
                )
                if proc_node:
                    proc_node.api_calls.append(api_call)

        # Network
        network = raw.get("network", {})
        for conn in network.get("tcp", []) + network.get("udp", []):
            report.network_connections.append(NetworkConnection(
                protocol="tcp" if conn in network.get("tcp", []) else "udp",
                src_ip=conn.get("src", ""),
                src_port=conn.get("sport", 0),
                dst_ip=conn.get("dst", ""),
                dst_port=conn.get("dport", 0),
            ))

        for dns in network.get("dns", []):
            report.dns_queries.append(DNSQuery(
                request=dns.get("request", ""),
                response=[a.get("data", "") for a in dns.get("answers", [])],
            ))

        for http in network.get("http", []):
            report.network_connections.append(NetworkConnection(
                protocol="http",
                src_ip="", src_port=0,
                dst_ip=http.get("host", ""),
                dst_port=http.get("port", 80),
                dst_host=http.get("host", ""),
                url=http.get("uri", ""),
                method=http.get("method", "GET"),
                user_agent=http.get("user-agent", ""),
                response_code=http.get("status", 0),
            ))

        # File operations
        behavior = raw.get("behavior", {})
        for fop in behavior.get("summary", {}).get("files", []):
            if isinstance(fop, str):
                report.file_operations.append(FileOperation(operation="access", path=fop))
            elif isinstance(fop, dict):
                report.file_operations.append(FileOperation(
                    operation=fop.get("type", "access"),
                    path=fop.get("path", ""),
                ))

        # Registry
        for rop in behavior.get("summary", {}).get("keys", []):
            if isinstance(rop, str):
                report.registry_operations.append(RegistryOperation(
                    operation="access", key=rop,
                ))
            elif isinstance(rop, dict):
                report.registry_operations.append(RegistryOperation(
                    operation=rop.get("type", "access"),
                    key=rop.get("path", ""),
                    value_name=rop.get("value", ""),
                ))

        # Dropped files
        for dropped in raw.get("dropped", []):
            report.dropped_files.append(DroppedFile(
                path=dropped.get("path", ""),
                md5=dropped.get("md5", ""),
                sha256=dropped.get("sha256", ""),
                size=dropped.get("size", 0),
                file_type=dropped.get("type", ""),
                yara_matches=[y.get("name", "") for y in dropped.get("yara", [])],
                is_malicious=bool(dropped.get("yara", [])),
            ))

        # Mutexes
        for mutex in behavior.get("summary", {}).get("mutexes", []):
            if isinstance(mutex, str):
                report.mutexes.append(MutexEvent(operation="create", name=mutex))

        # Tags from signatures
        for sig in raw.get("signatures", []):
            name = sig.get("name", "")
            if name:
                report.tags.append(name)

        return report

    def _parse_cuckoo_process(self, raw: Dict[str, Any]) -> ProcessNode:
        node = ProcessNode(
            pid=raw.get("pid", 0),
            ppid=raw.get("ppid", 0),
            name=raw.get("process_name", raw.get("name", "")),
            command_line=raw.get("command_line", ""),
            image_path=raw.get("module_path", raw.get("path", "")),
        )
        for child in raw.get("children", []):
            node.children.append(self._parse_cuckoo_process(child))
        return node

    @staticmethod
    def _cuckoo_verdict(score: int) -> str:
        if score >= 7:
            return "malicious"
        if score >= 3:
            return "suspicious"
        return "clean"

    # ------------------------------------------------------------------
    # any.run parser
    # ------------------------------------------------------------------

    def _parse_any_run(self) -> SandboxReport:
        raw = self._raw
        analysis = raw.get("analysis", {})
        content = analysis.get("content", {})
        verdict_data = analysis.get("verdict", {})
        file_info = content.get("mainObject", {}).get("hashes", {})

        report = SandboxReport(
            sample_sha256=file_info.get("sha256", ""),
            sample_md5=file_info.get("md5", ""),
            sample_name=content.get("mainObject", {}).get("name", ""),
            analysis_id=str(analysis.get("taskid", "")),
            score=verdict_data.get("score", 0),
            verdict=verdict_data.get("verdict", ""),
        )

        # Processes
        for proc in content.get("processes", []):
            node = ProcessNode(
                pid=proc.get("pid", 0),
                ppid=proc.get("ppid", 0),
                name=proc.get("image", ""),
                command_line=proc.get("cmd", ""),
                image_path=proc.get("image", ""),
                injected=proc.get("injected", False),
            )
            report.processes.append(node)

        # Network
        for conn in content.get("network", {}).get("connections", []):
            report.network_connections.append(NetworkConnection(
                protocol=conn.get("protocol", "tcp").lower(),
                src_ip=conn.get("src", ""),
                src_port=conn.get("srcPort", 0),
                dst_ip=conn.get("dst", ""),
                dst_port=conn.get("dstPort", 0),
                dst_host=conn.get("dstHost", ""),
            ))

        for dns in content.get("network", {}).get("dnsRequests", []):
            report.dns_queries.append(DNSQuery(
                request=dns.get("domain", ""),
                response=dns.get("ips", []),
            ))

        for req in content.get("network", {}).get("httpRequests", []):
            report.network_connections.append(NetworkConnection(
                protocol="http",
                src_ip="", src_port=0,
                dst_ip="",
                dst_port=req.get("port", 80),
                dst_host=req.get("domain", ""),
                url=req.get("url", ""),
                method=req.get("method", "GET"),
                user_agent=req.get("userAgent", ""),
                response_code=req.get("statusCode", 0),
            ))

        # Files
        for fop in content.get("fileActivity", []):
            report.file_operations.append(FileOperation(
                operation=fop.get("type", "access").lower(),
                path=fop.get("path", ""),
            ))

        # Registry
        for rop in content.get("registryActivity", []):
            report.registry_operations.append(RegistryOperation(
                operation=rop.get("type", "access").lower(),
                key=rop.get("key", ""),
                value_name=rop.get("value", ""),
                data=str(rop.get("data", "")),
            ))

        # Dropped files
        for dropped in content.get("dropped", []):
            report.dropped_files.append(DroppedFile(
                path=dropped.get("path", ""),
                md5=dropped.get("md5", ""),
                sha256=dropped.get("sha256", ""),
                file_type=dropped.get("type", ""),
            ))

        return report

    # ------------------------------------------------------------------
    # Hybrid Analysis parser
    # ------------------------------------------------------------------

    def _parse_hybrid(self) -> SandboxReport:
        raw = self._raw
        report = SandboxReport(
            sample_sha256=raw.get("sha256", ""),
            sample_md5=raw.get("md5", ""),
            sample_name=raw.get("submit_name", ""),
            analysis_id=str(raw.get("job_id", "")),
            score=raw.get("threatscore", 0),
            verdict=raw.get("verdict", ""),
        )

        for proc in raw.get("processes", []):
            node = ProcessNode(
                pid=proc.get("pid", 0),
                ppid=proc.get("parentpid", 0),
                name=proc.get("name", ""),
                command_line=proc.get("commandline", ""),
                image_path=proc.get("path", ""),
            )
            for call in proc.get("calls", []):
                node.api_calls.append(APICall(
                    api_name=call.get("name", ""),
                    category=call.get("type", ""),
                    arguments={a.get("name", ""): a.get("value", "")
                               for a in call.get("parameters", [])},
                    return_value=call.get("returnValue", None),
                ))
            report.processes.append(node)

        for conn in raw.get("network", {}).get("domains", []):
            report.dns_queries.append(DNSQuery(
                request=conn.get("address", ""),
                response=[conn.get("ip", "")],
            ))

        for req in raw.get("network", {}).get("requests", []):
            report.network_connections.append(NetworkConnection(
                protocol=req.get("protocol", "tcp").lower(),
                src_ip="", src_port=0,
                dst_ip=req.get("ip_address", ""),
                dst_port=req.get("destination_port", 0),
                dst_host=req.get("host", ""),
                url=req.get("url", ""),
                method=req.get("method", ""),
                response_code=req.get("response_code", 0),
            ))

        for reg in raw.get("mitre_attcks", []):
            tid = reg.get("technique", {}).get("id", "")
            if tid:
                report.mitre_techniques.add(tid)

        return report

    # ------------------------------------------------------------------
    # Triage (Hatching) parser
    # ------------------------------------------------------------------

    def _parse_triage(self) -> SandboxReport:
        raw = self._raw
        sample = raw.get("sample", {})
        report = SandboxReport(
            sample_sha256=sample.get("sha256", ""),
            sample_md5=sample.get("md5", ""),
            sample_name=sample.get("target", ""),
            analysis_id=str(raw.get("id", "")),
            score=raw.get("score", 0),
            verdict="malicious" if raw.get("score", 0) >= 7 else "clean",
        )

        for target in raw.get("targets", []):
            for proc in target.get("processes", []):
                node = ProcessNode(
                    pid=proc.get("pid", 0),
                    ppid=proc.get("ppid", 0),
                    name=proc.get("name", ""),
                    command_line=" ".join(proc.get("args", [])),
                    image_path=proc.get("path", ""),
                )
                report.processes.append(node)

            for sig in target.get("signatures", []):
                report.tags.append(sig.get("name", ""))
                for ioc in sig.get("iocs", []):
                    path = ioc.get("path", "")
                    if path.startswith("HKLM") or path.startswith("HKCU"):
                        report.registry_operations.append(
                            RegistryOperation(operation="write", key=path)
                        )
                    else:
                        report.file_operations.append(
                            FileOperation(operation="write", path=path)
                        )

        for conn in raw.get("network", {}).get("connections", []):
            report.network_connections.append(NetworkConnection(
                protocol=conn.get("proto", "tcp"),
                src_ip=conn.get("src_ip", ""),
                src_port=conn.get("src_port", 0),
                dst_ip=conn.get("dst_ip", ""),
                dst_port=conn.get("dst_port", 0),
            ))

        return report

    # ------------------------------------------------------------------
    # Post-processing: MITRE mapping
    # ------------------------------------------------------------------

    def _map_mitre_techniques(self, report: SandboxReport) -> None:
        for proc in report.all_processes:
            for api_call in proc.api_calls:
                if api_call.api_name in _API_MITRE_LOOKUP:
                    tid = _API_MITRE_LOOKUP[api_call.api_name][0]
                    report.mitre_techniques.add(tid)

        for reg_op in report.registry_operations:
            for pattern, tid, _name, _cat, _sev in _REGISTRY_MITRE_MAP:
                if pattern.search(reg_op.key):
                    report.mitre_techniques.add(tid)

    # ------------------------------------------------------------------
    # Post-processing: C2 candidate detection
    # ------------------------------------------------------------------

    def _detect_c2_candidates(self, report: SandboxReport) -> None:
        for conn in report.network_connections:
            is_c2 = False
            if conn.dst_port in _C2_PORT_HEURISTICS:
                is_c2 = True
            if conn.user_agent and _SUSPICIOUS_UA_PATTERNS.search(conn.user_agent):
                is_c2 = True
            # HTTP beaconing: repeated GETs with short URLs
            if conn.protocol in ("http", "https") and conn.url:
                if len(conn.url) < 30 and conn.method == "GET":
                    is_c2 = True
            conn.is_c2_candidate = is_c2

    # ------------------------------------------------------------------
    # BehaviorReport construction
    # ------------------------------------------------------------------

    def _build_behavior_report(self, report: SandboxReport) -> BehaviorReport:
        br = BehaviorReport(
            sample_hash=report.sample_sha256,
            is_packed=False,
            has_network_activity=bool(report.network_connections),
            has_persistence=any(
                op.operation in ("write", "create")
                for op in report.registry_operations
            ),
        )

        # From API calls
        seen: Dict[str, BehaviorIndicator] = {}
        for proc in report.all_processes:
            for api_call in proc.api_calls:
                if api_call.api_name in _API_MITRE_LOOKUP:
                    tid, sub, name, category, severity = _API_MITRE_LOOKUP[api_call.api_name]
                    key = f"{tid}:{api_call.api_name}"
                    if key not in seen:
                        ind = BehaviorIndicator(
                            name=name,
                            category=category,
                            description=f"API call: {api_call.api_name}",
                            severity=severity,
                            mitre_technique=tid,
                            mitre_subtechnique=sub if "." in sub else "",
                            evidence=[api_call.api_name],
                        )
                        seen[key] = ind
                        br.add_indicator(ind)
                    else:
                        arg = api_call.key_arg
                        if arg and arg not in seen[key].evidence:
                            seen[key].evidence.append(arg)

        # From registry operations
        for reg_op in report.registry_operations:
            for pattern, tid, name, category, severity in _REGISTRY_MITRE_MAP:
                if pattern.search(reg_op.key):
                    key = f"{tid}:reg:{reg_op.key[:40]}"
                    if key not in seen:
                        ind = BehaviorIndicator(
                            name=name,
                            category=category,
                            description=f"Registry {reg_op.operation}: {reg_op.key}",
                            severity=severity,
                            mitre_technique=tid,
                            evidence=[reg_op.key],
                        )
                        seen[key] = ind
                        br.add_indicator(ind)

        # Network activity indicators
        if report.unique_c2_candidates:
            ind = BehaviorIndicator(
                name="C2 Communication",
                category=BehaviorCategory.NETWORK,
                description="Suspected command-and-control communication",
                severity=4,
                mitre_technique="T1071",
                evidence=report.unique_c2_candidates[:10],
            )
            br.add_indicator(ind)

        # Dropped malicious files
        malicious_drops = [f for f in report.dropped_files if f.is_malicious]
        if malicious_drops:
            ind = BehaviorIndicator(
                name="Malicious File Drop",
                category=BehaviorCategory.EXECUTION,
                description="Sample drops additional malicious files",
                severity=4,
                mitre_technique="T1105",
                evidence=[f.path for f in malicious_drops[:5]],
            )
            br.add_indicator(ind)

        # Process injection detection
        injected_procs = [p for p in report.all_processes if p.injected or p.hollowed]
        if injected_procs:
            ind = BehaviorIndicator(
                name="Process Injection",
                category=BehaviorCategory.INJECTION,
                description="Code injected into remote process",
                severity=5,
                mitre_technique="T1055",
                evidence=[p.name for p in injected_procs[:5]],
            )
            br.add_indicator(ind)

        br.has_anti_analysis = any(
            ind.category == BehaviorCategory.ANTI_ANALYSIS for ind in br.indicators
        )
        br.mitre_techniques = report.mitre_techniques

        return br

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_process(
        processes: List[ProcessNode], pid: int
    ) -> Optional[ProcessNode]:
        for proc in processes:
            if proc.pid == pid:
                return proc
            found = SandboxReportParser._find_in_children(proc, pid)
            if found:
                return found
        return None

    @staticmethod
    def _find_in_children(node: ProcessNode, pid: int) -> Optional[ProcessNode]:
        for child in node.children:
            if child.pid == pid:
                return child
            found = SandboxReportParser._find_in_children(child, pid)
            if found:
                return found
        return None


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

def parse_sandbox_report(
    data: Dict[str, Any],
    fmt: SandboxFormat = SandboxFormat.AUTO,
) -> SandboxReport:
    """Parse a sandbox JSON report dict into a normalized SandboxReport."""
    return SandboxReportParser(data, fmt).parse()


def load_sandbox_report(
    path: str,
    fmt: SandboxFormat = SandboxFormat.AUTO,
) -> SandboxReport:
    """Load a sandbox report from a JSON file path."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return parse_sandbox_report(data, fmt)
