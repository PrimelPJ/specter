"""
PE import table deep analyzer.

Given a list of ImportEntry objects from the PE parser, classifies malware
capabilities based on API call patterns, detects suspicious API clusters,
and assigns confidence-scored capability labels.

Capability taxonomy covers:
  process_injection, code_injection, process_hollowing, defense_evasion,
  anti_debug, persistence, credential_access, network_communication,
  c2_communication, file_operations, registry_operations, service_abuse,
  keylogging, screenshot_capture, ransomware_behavior, rootkit_behavior,
  lateral_movement, privilege_escalation
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


class CapabilityCategory(str, Enum):
    PROCESS_INJECTION = "process_injection"
    CODE_INJECTION = "code_injection"
    PROCESS_HOLLOWING = "process_hollowing"
    DEFENSE_EVASION = "defense_evasion"
    ANTI_DEBUG = "anti_debug"
    PERSISTENCE = "persistence"
    CREDENTIAL_ACCESS = "credential_access"
    NETWORK_COMMUNICATION = "network_communication"
    C2_COMMUNICATION = "c2_communication"
    FILE_OPERATIONS = "file_operations"
    REGISTRY_OPERATIONS = "registry_operations"
    SERVICE_ABUSE = "service_abuse"
    KEYLOGGING = "keylogging"
    SCREENSHOT_CAPTURE = "screenshot_capture"
    RANSOMWARE_BEHAVIOR = "ransomware_behavior"
    ROOTKIT_BEHAVIOR = "rootkit_behavior"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"


@dataclass(frozen=True)
class ApiCluster:
    """A named group of APIs that together indicate a specific capability."""
    name: str
    category: CapabilityCategory
    apis: FrozenSet[str]          # lower-cased API names
    threshold: int                 # how many from the set must match
    base_confidence: float         # 0.0 – 1.0; scales with match ratio
    mitre_techniques: Tuple[str, ...] = field(default_factory=tuple)
    description: str = ""

    def score(self, matched: int) -> float:
        """Return confidence in [0, 1] given the number of matched APIs."""
        if matched < self.threshold:
            return 0.0
        ratio = min(matched / max(len(self.apis), 1), 1.0)
        return round(self.base_confidence * (0.5 + 0.5 * ratio), 3)


@dataclass
class CapabilityMatch:
    category: CapabilityCategory
    cluster_name: str
    confidence: float               # 0.0 – 1.0
    matched_apis: List[str]         # the specific APIs that triggered this
    dll_sources: List[str]          # which DLLs provided the matched APIs
    mitre_techniques: List[str]
    description: str

    @property
    def is_high_confidence(self) -> bool:
        return self.confidence >= 0.7

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "cluster": self.cluster_name,
            "confidence": self.confidence,
            "matched_apis": self.matched_apis,
            "dll_sources": self.dll_sources,
            "mitre_techniques": self.mitre_techniques,
            "description": self.description,
        }


@dataclass
class MalwareFamilyHint:
    family: str
    confidence: float
    matched_indicators: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "family": self.family,
            "confidence": self.confidence,
            "indicators": self.matched_indicators,
        }


@dataclass
class ImportAnalysisResult:
    """Full output of the import table deep analysis."""
    capabilities: List[CapabilityMatch]
    family_hints: List[MalwareFamilyHint]
    total_apis_analyzed: int
    suspicious_api_count: int
    dll_count: int
    risk_score: float               # 0.0 – 10.0 composite
    summary: str

    @property
    def high_confidence_capabilities(self) -> List[CapabilityMatch]:
        return [c for c in self.capabilities if c.is_high_confidence]

    @property
    def mitre_techniques(self) -> List[str]:
        seen: Set[str] = set()
        out = []
        for cap in self.capabilities:
            for t in cap.mitre_techniques:
                if t not in seen:
                    seen.add(t)
                    out.append(t)
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "summary": self.summary,
            "total_apis": self.total_apis_analyzed,
            "suspicious_apis": self.suspicious_api_count,
            "dll_count": self.dll_count,
            "capabilities": [c.to_dict() for c in self.capabilities],
            "family_hints": [h.to_dict() for h in self.family_hints],
            "mitre_techniques": self.mitre_techniques,
        }


# ---------------------------------------------------------------------------
# API cluster definitions
# ---------------------------------------------------------------------------

_CLUSTERS: List[ApiCluster] = [
    # ── Process injection ──────────────────────────────────────────────────
    ApiCluster(
        name="Classic Process Injection",
        category=CapabilityCategory.PROCESS_INJECTION,
        apis=frozenset({
            "openprocess", "virtualallocex", "writeprocessmemory",
            "createremotethread",
        }),
        threshold=3,
        base_confidence=0.95,
        mitre_techniques=("T1055",),
        description="Allocates memory in a remote process and spawns a thread",
    ),
    ApiCluster(
        name="NtAPI Process Injection",
        category=CapabilityCategory.PROCESS_INJECTION,
        apis=frozenset({
            "ntcreatesection", "ntmapviewofsection", "ntwritevirtualmemory",
            "ntcreatethreadex",
        }),
        threshold=2,
        base_confidence=0.92,
        mitre_techniques=("T1055",),
        description="Native NT API process injection (stealth variant)",
    ),
    ApiCluster(
        name="APC Injection",
        category=CapabilityCategory.CODE_INJECTION,
        apis=frozenset({
            "queueuserapc", "ntqueueapcthread", "openthread",
            "virtualallocex", "writeprocessmemory",
        }),
        threshold=2,
        base_confidence=0.88,
        mitre_techniques=("T1055.004",),
        description="APC-based code injection into existing thread",
    ),
    ApiCluster(
        name="SetWindowsHookEx Injection",
        category=CapabilityCategory.CODE_INJECTION,
        apis=frozenset({
            "setwindowshookex", "setwindowshookexa", "setwindowshookexw",
            "loadlibrary", "getprocaddress",
        }),
        threshold=2,
        base_confidence=0.85,
        mitre_techniques=("T1055.011",),
        description="Injects DLL via Windows message hook",
    ),
    # ── Process hollowing ─────────────────────────────────────────────────
    ApiCluster(
        name="Process Hollowing",
        category=CapabilityCategory.PROCESS_HOLLOWING,
        apis=frozenset({
            "createprocessa", "createprocessw", "ntunmapviewofsection",
            "zwunmapviewofsection", "virtualallocex", "writeprocessmemory",
            "setthreadcontext", "resumethread",
        }),
        threshold=3,
        base_confidence=0.93,
        mitre_techniques=("T1055.012",),
        description="Creates suspended process and replaces image (process hollowing / RunPE)",
    ),
    # ── Defense evasion ───────────────────────────────────────────────────
    ApiCluster(
        name="API Unhooking / Direct Syscalls",
        category=CapabilityCategory.DEFENSE_EVASION,
        apis=frozenset({
            "ntcreatefile", "ntreadfile", "ntwritefile",
            "getmodulehandlea", "getmodulehandlew",
            "loadlibrarya", "loadlibraryw",
            "getprocaddress",
        }),
        threshold=4,
        base_confidence=0.70,
        mitre_techniques=("T1562.001",),
        description="Loads ntdll from disk to bypass user-mode hooks",
    ),
    ApiCluster(
        name="Timestomping / Metadata Manipulation",
        category=CapabilityCategory.DEFENSE_EVASION,
        apis=frozenset({
            "setfiletime", "createfilea", "createfilew",
            "getfiletime",
        }),
        threshold=2,
        base_confidence=0.72,
        mitre_techniques=("T1070.006",),
        description="Modifies file timestamps to hide activity",
    ),
    # ── Anti-debug ────────────────────────────────────────────────────────
    ApiCluster(
        name="Anti-Debug Checks",
        category=CapabilityCategory.ANTI_DEBUG,
        apis=frozenset({
            "isdebuggerpresent", "checkremotedebuggerpresent",
            "ntqueryinformationprocess", "outputdebugstringa",
            "outputdebugstringw", "findwindowa", "findwindoww",
            "blockinput",
        }),
        threshold=1,
        base_confidence=0.80,
        mitre_techniques=("T1622",),
        description="Runtime checks to detect attached debugger",
    ),
    ApiCluster(
        name="Timing-Based Anti-Debug",
        category=CapabilityCategory.ANTI_DEBUG,
        apis=frozenset({
            "gettickcount", "gettickcount64", "queryperformancecounter",
            "sleep", "sleepex",
        }),
        threshold=3,
        base_confidence=0.60,
        mitre_techniques=("T1622",),
        description="Uses timing measurements to detect single-stepping",
    ),
    # ── Persistence ───────────────────────────────────────────────────────
    ApiCluster(
        name="Registry Persistence",
        category=CapabilityCategory.PERSISTENCE,
        apis=frozenset({
            "regcreatekeya", "regcreatekeyexa", "regcreatekeyexw",
            "regsetvalueexa", "regsetvalueexw",
        }),
        threshold=2,
        base_confidence=0.85,
        mitre_techniques=("T1547.001",),
        description="Sets registry run keys for autostart persistence",
    ),
    ApiCluster(
        name="Service-Based Persistence",
        category=CapabilityCategory.SERVICE_ABUSE,
        apis=frozenset({
            "openscmanagera", "openscmanagerw",
            "createservicea", "createservicew",
            "startservicea", "startservicew",
            "changeserviceconfiga", "changeserviceconfigw",
        }),
        threshold=2,
        base_confidence=0.90,
        mitre_techniques=("T1543.003",),
        description="Creates or modifies Windows services for persistence/privilege",
    ),
    ApiCluster(
        name="Scheduled Task Creation",
        category=CapabilityCategory.PERSISTENCE,
        apis=frozenset({
            "itaskscheduler", "itask", "scheduledtasks",
            "cocreatein",   # COM-based task scheduler
            "coinitializeex",
        }),
        threshold=1,
        base_confidence=0.65,
        mitre_techniques=("T1053.005",),
        description="Creates scheduled tasks via COM interfaces",
    ),
    # ── Credential access ─────────────────────────────────────────────────
    ApiCluster(
        name="LSA Credential Dumping",
        category=CapabilityCategory.CREDENTIAL_ACCESS,
        apis=frozenset({
            "lsaopenpolicy", "lsaqueryinformationpolicy",
            "lsaenumeratelogonsessions",
            "samopensamserver", "samopensamdomain",
            "ntdumpsam",
        }),
        threshold=1,
        base_confidence=0.90,
        mitre_techniques=("T1003.001",),
        description="Reads LSA secrets / SAM database for credential extraction",
    ),
    ApiCluster(
        name="DPAPI Credential Decryption",
        category=CapabilityCategory.CREDENTIAL_ACCESS,
        apis=frozenset({
            "cryptunprotectdata", "cryptprotectdata",
            "cryptderivekey", "cryptdecrypt",
        }),
        threshold=2,
        base_confidence=0.75,
        mitre_techniques=("T1555",),
        description="Uses DPAPI or raw crypto to decrypt stored credentials",
    ),
    # ── Network communication ─────────────────────────────────────────────
    ApiCluster(
        name="Raw Socket Communication",
        category=CapabilityCategory.NETWORK_COMMUNICATION,
        apis=frozenset({
            "wsastartup", "socket", "connect", "send", "recv",
            "wsasend", "wsarecv", "closesocket",
        }),
        threshold=3,
        base_confidence=0.80,
        mitre_techniques=("T1095",),
        description="Direct socket communication (potential C2 or exfiltration)",
    ),
    ApiCluster(
        name="HTTP/WinInet Communication",
        category=CapabilityCategory.C2_COMMUNICATION,
        apis=frozenset({
            "internetopena", "internetopenw",
            "internetconnecta", "internetconnectw",
            "httpopenrequesta", "httpopenrequestw",
            "httpsendrequesta", "httpsendrequestw",
            "internetreadfile",
        }),
        threshold=3,
        base_confidence=0.85,
        mitre_techniques=("T1071.001",),
        description="Uses WinInet HTTP stack (common C2 transport)",
    ),
    ApiCluster(
        name="WinHTTP Communication",
        category=CapabilityCategory.C2_COMMUNICATION,
        apis=frozenset({
            "winhttpopen", "winhttpconnect",
            "winhttpopenrequest", "winhttpsendrequest",
            "winhttpreceiveresponse", "winhttpreaddata",
        }),
        threshold=3,
        base_confidence=0.85,
        mitre_techniques=("T1071.001",),
        description="Uses WinHTTP stack (common stealthy C2 transport)",
    ),
    ApiCluster(
        name="Downloader Pattern",
        category=CapabilityCategory.C2_COMMUNICATION,
        apis=frozenset({
            "urldownloadtofilea", "urldownloadtofilew",
            "urldownloadtocachefilea", "urldownloadtocachefilew",
        }),
        threshold=1,
        base_confidence=0.88,
        mitre_techniques=("T1105",),
        description="Downloads additional payloads from the internet",
    ),
    # ── Keylogging ────────────────────────────────────────────────────────
    ApiCluster(
        name="Keyboard Hook Keylogging",
        category=CapabilityCategory.KEYLOGGING,
        apis=frozenset({
            "setwindowshookex", "setwindowshookexa", "setwindowshookexw",
            "getasynckeystate", "getkeystate",
        }),
        threshold=1,
        base_confidence=0.82,
        mitre_techniques=("T1056.001",),
        description="Installs keyboard hook or polls key state for logging",
    ),
    # ── Screenshot capture ────────────────────────────────────────────────
    ApiCluster(
        name="Screen Capture",
        category=CapabilityCategory.SCREENSHOT_CAPTURE,
        apis=frozenset({
            "bitblt", "stretchblt", "getdc", "createcompatibledc",
            "createcompatiblebitmap", "selectobject",
        }),
        threshold=3,
        base_confidence=0.78,
        mitre_techniques=("T1113",),
        description="GDI-based screen capture",
    ),
    # ── Ransomware ────────────────────────────────────────────────────────
    ApiCluster(
        name="Ransomware Encryption",
        category=CapabilityCategory.RANSOMWARE_BEHAVIOR,
        apis=frozenset({
            "cryptacquirecontexta", "cryptacquirecontextw",
            "cryptgenkey", "cryptencrypt",
            "bcryptencrypt", "bcryptopenalgorithmprovider",
            "bcryptgeneratesymmetrickey",
        }),
        threshold=2,
        base_confidence=0.88,
        mitre_techniques=("T1486",),
        description="Uses CryptoAPI or BCrypt for bulk file encryption",
    ),
    ApiCluster(
        name="Ransomware File Enumeration",
        category=CapabilityCategory.RANSOMWARE_BEHAVIOR,
        apis=frozenset({
            "findfirstfilea", "findfirstfilew",
            "findnextfilea", "findnextfilew",
            "findclose", "deletefilea", "deletefilew",
            "movefileexa", "movefileexw",
        }),
        threshold=4,
        base_confidence=0.70,
        mitre_techniques=("T1486",),
        description="Enumerates and replaces files (ransomware file traversal)",
    ),
    # ── Privilege escalation ──────────────────────────────────────────────
    ApiCluster(
        name="Token Privilege Manipulation",
        category=CapabilityCategory.PRIVILEGE_ESCALATION,
        apis=frozenset({
            "adjusttokenprivileges", "lookupprivilegevaluea",
            "lookupprivilegevaluew", "openprocesstoken",
            "impersonateloggedonuser",
        }),
        threshold=2,
        base_confidence=0.88,
        mitre_techniques=("T1134",),
        description="Adjusts process token privileges for escalation",
    ),
    # ── Rootkit ───────────────────────────────────────────────────────────
    ApiCluster(
        name="SSDT / Driver Manipulation",
        category=CapabilityCategory.ROOTKIT_BEHAVIOR,
        apis=frozenset({
            "ntloaddriver", "zwloaddriver",
            "ntsetsysteminformation",
            "ntquerysysteminformation",
        }),
        threshold=1,
        base_confidence=0.85,
        mitre_techniques=("T1014",),
        description="Loads a kernel driver or modifies SSDT (rootkit indicator)",
    ),
    # ── Lateral movement ─────────────────────────────────────────────────
    ApiCluster(
        name="SMB / Named Pipe Lateral Movement",
        category=CapabilityCategory.LATERAL_MOVEMENT,
        apis=frozenset({
            "wnetaddconnection2a", "wnetaddconnection2w",
            "wnetaddconnection3a", "wnetaddconnection3w",
            "createfilea",  # combined with UNC paths
            "callnamedpipea", "callnamedpipew",
            "waitnamedpipea", "waitnamedpipew",
        }),
        threshold=2,
        base_confidence=0.80,
        mitre_techniques=("T1021.002",),
        description="SMB or named-pipe based lateral movement",
    ),
    # ── Registry operations ───────────────────────────────────────────────
    ApiCluster(
        name="Registry Read/Enumeration",
        category=CapabilityCategory.REGISTRY_OPERATIONS,
        apis=frozenset({
            "regopenkeya", "regopenkeyw", "regopenkeyexa", "regopenkeyexw",
            "regqueryvalueexa", "regqueryvalueexw",
            "regenumkeyexa", "regenumkeyexw",
            "regenumvaluea", "regenumvaluew",
        }),
        threshold=3,
        base_confidence=0.65,
        mitre_techniques=("T1012",),
        description="Queries or enumerates registry for configuration or recon",
    ),
]


# ---------------------------------------------------------------------------
# Malware family signature definitions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FamilySignature:
    family: str
    required_apis: FrozenSet[str]   # all must be present
    optional_apis: FrozenSet[str]   # partial bonus
    base_confidence: float


_FAMILY_SIGNATURES: List[FamilySignature] = [
    FamilySignature(
        family="Mimikatz-like Credential Dumper",
        required_apis=frozenset({"lsaopenpolicy", "openprocesstoken", "adjusttokenprivileges"}),
        optional_apis=frozenset({"samopensamserver", "ntdumpsam", "cryptunprotectdata"}),
        base_confidence=0.88,
    ),
    FamilySignature(
        family="Shellcode Dropper / Loader",
        required_apis=frozenset({"virtualallocex", "writeprocessmemory", "createremotethread"}),
        optional_apis=frozenset({"openprocess", "urldownloadtofilea", "urldownloadtofilew"}),
        base_confidence=0.82,
    ),
    FamilySignature(
        family="Ransomware (Encryption Engine)",
        required_apis=frozenset({"cryptencrypt", "findfirstfilew", "findnextfilew"}),
        optional_apis=frozenset({"bcryptencrypt", "cryptgenkey", "deletefilew", "movefileexw"}),
        base_confidence=0.90,
    ),
    FamilySignature(
        family="RAT / Backdoor",
        required_apis=frozenset({"wsastartup", "connect", "createprocessa"}),
        optional_apis=frozenset({
            "getasynckeystate", "bitblt", "internetopena",
            "regsetvalueexa",
        }),
        base_confidence=0.78,
    ),
    FamilySignature(
        family="Banker Trojan",
        required_apis=frozenset({
            "setwindowshookex", "internetopena", "cryptunprotectdata",
        }),
        optional_apis=frozenset({
            "httpopenrequesta", "httpsendrequesta", "regcreatekeyexa",
        }),
        base_confidence=0.80,
    ),
    FamilySignature(
        family="Rootkit / Driver-Based Malware",
        required_apis=frozenset({"ntloaddriver"}),
        optional_apis=frozenset({
            "ntsetsysteminformation", "ntquerysysteminformation",
            "zwloaddriver",
        }),
        base_confidence=0.87,
    ),
]


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class ImportTableAnalyzer:
    """
    Deep analyzer for PE import tables.

    Accepts the list of ImportEntry objects returned by PEParser and produces
    a structured ImportAnalysisResult with capability scores and family hints.
    """

    def __init__(self) -> None:
        self._clusters = _CLUSTERS
        self._family_sigs = _FAMILY_SIGNATURES

    def analyze(self, imports: List[Any]) -> ImportAnalysisResult:
        """
        Analyze import entries.

        Parameters
        ----------
        imports:
            List of ImportEntry objects (duck-typed: must have .dll_name and
            .functions attributes).
        """
        # Build a flat API set (lower-cased) and a per-api -> dll mapping
        api_to_dll: Dict[str, str] = {}
        all_apis: Set[str] = set()
        dll_count = len(imports)

        for entry in imports:
            dll = getattr(entry, "dll_name", "") or ""
            funcs = getattr(entry, "functions", []) or []
            for func in funcs:
                low = func.lower()
                all_apis.add(low)
                api_to_dll[low] = dll

        capabilities = self._match_clusters(all_apis, api_to_dll)
        family_hints = self._match_families(all_apis)
        suspicious_count = self._count_suspicious(all_apis)
        risk = self._compute_risk(capabilities, suspicious_count, all_apis)
        summary = self._build_summary(capabilities, family_hints, risk)

        return ImportAnalysisResult(
            capabilities=capabilities,
            family_hints=family_hints,
            total_apis_analyzed=len(all_apis),
            suspicious_api_count=suspicious_count,
            dll_count=dll_count,
            risk_score=risk,
            summary=summary,
        )

    def _match_clusters(
        self,
        api_set: Set[str],
        api_to_dll: Dict[str, str],
    ) -> List[CapabilityMatch]:
        results: List[CapabilityMatch] = []
        for cluster in self._clusters:
            matched = [a for a in cluster.apis if a in api_set]
            confidence = cluster.score(len(matched))
            if confidence <= 0.0:
                continue
            dll_sources = list({api_to_dll[a] for a in matched if a in api_to_dll})
            results.append(CapabilityMatch(
                category=cluster.category,
                cluster_name=cluster.name,
                confidence=confidence,
                matched_apis=matched,
                dll_sources=dll_sources,
                mitre_techniques=list(cluster.mitre_techniques),
                description=cluster.description,
            ))
        results.sort(key=lambda c: c.confidence, reverse=True)
        return results

    def _match_families(
        self, api_set: Set[str]
    ) -> List[MalwareFamilyHint]:
        hints: List[MalwareFamilyHint] = []
        for sig in self._family_sigs:
            missing = sig.required_apis - api_set
            if missing:
                continue
            optional_matched = [a for a in sig.optional_apis if a in api_set]
            bonus = 0.05 * len(optional_matched)
            confidence = min(sig.base_confidence + bonus, 1.0)
            hints.append(MalwareFamilyHint(
                family=sig.family,
                confidence=round(confidence, 3),
                matched_indicators=list(sig.required_apis | set(optional_matched)),
            ))
        hints.sort(key=lambda h: h.confidence, reverse=True)
        return hints

    @staticmethod
    def _count_suspicious(api_set: Set[str]) -> int:
        """Count APIs in the set that appear in at least one cluster definition."""
        all_cluster_apis: Set[str] = set()
        for cluster in _CLUSTERS:
            all_cluster_apis.update(cluster.apis)
        return len(api_set & all_cluster_apis)

    @staticmethod
    def _compute_risk(
        capabilities: List[CapabilityMatch],
        suspicious_count: int,
        api_set: Set[str],
    ) -> float:
        """
        Composite risk score 0–10.

        Components:
          - capability confidence sum (weighted by severity category)
          - suspicious API density (suspicious / total)
          - high-confidence match bonus
        """
        _SEVERITY_WEIGHTS = {
            CapabilityCategory.PROCESS_INJECTION: 1.4,
            CapabilityCategory.CODE_INJECTION: 1.3,
            CapabilityCategory.PROCESS_HOLLOWING: 1.5,
            CapabilityCategory.CREDENTIAL_ACCESS: 1.4,
            CapabilityCategory.RANSOMWARE_BEHAVIOR: 1.5,
            CapabilityCategory.ROOTKIT_BEHAVIOR: 1.6,
            CapabilityCategory.C2_COMMUNICATION: 1.3,
            CapabilityCategory.PRIVILEGE_ESCALATION: 1.2,
            CapabilityCategory.LATERAL_MOVEMENT: 1.2,
            CapabilityCategory.DEFENSE_EVASION: 1.1,
            CapabilityCategory.ANTI_DEBUG: 0.8,
            CapabilityCategory.KEYLOGGING: 1.2,
            CapabilityCategory.SCREENSHOT_CAPTURE: 1.0,
            CapabilityCategory.PERSISTENCE: 1.1,
            CapabilityCategory.SERVICE_ABUSE: 1.1,
            CapabilityCategory.NETWORK_COMMUNICATION: 0.9,
            CapabilityCategory.FILE_OPERATIONS: 0.6,
            CapabilityCategory.REGISTRY_OPERATIONS: 0.5,
        }
        raw = sum(
            cap.confidence * _SEVERITY_WEIGHTS.get(cap.category, 1.0)
            for cap in capabilities
        )
        density_bonus = (suspicious_count / max(len(api_set), 1)) * 2.0
        high_conf_bonus = sum(0.5 for cap in capabilities if cap.is_high_confidence)
        total = raw + density_bonus + high_conf_bonus
        return round(min(total, 10.0), 2)

    @staticmethod
    def _build_summary(
        capabilities: List[CapabilityMatch],
        family_hints: List[MalwareFamilyHint],
        risk: float,
    ) -> str:
        if not capabilities:
            return "No suspicious API patterns detected."

        severity = (
            "CRITICAL" if risk >= 8 else
            "HIGH" if risk >= 5 else
            "MEDIUM" if risk >= 2 else
            "LOW"
        )
        top_caps = [c.cluster_name for c in capabilities[:3]]
        cap_str = ", ".join(top_caps)

        if family_hints:
            family_str = f" Likely family: {family_hints[0].family}."
        else:
            family_str = ""

        return (
            f"{severity} risk (score {risk:.1f}/10.0). "
            f"Detected capabilities: {cap_str}.{family_str}"
        )
