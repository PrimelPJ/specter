"""Tests for the PE import table analyzer."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

import pytest

from specter.import_analyzer import (
    CapabilityCategory,
    ImportTableAnalyzer,
)


@dataclass
class _FakeImport:
    dll_name: str
    functions: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _analyzer() -> ImportTableAnalyzer:
    return ImportTableAnalyzer()


def _imports(*dll_func_pairs: tuple) -> List[_FakeImport]:
    return [_FakeImport(dll_name=dll, functions=list(funcs)) for dll, funcs in dll_func_pairs]


# ---------------------------------------------------------------------------
# Empty input
# ---------------------------------------------------------------------------

class TestEmptyInput:
    def test_empty_list_returns_zero_risk(self):
        result = _analyzer().analyze([])
        assert result.risk_score == 0.0
        assert result.capabilities == []
        assert result.family_hints == []
        assert result.total_apis_analyzed == 0

    def test_summary_no_patterns(self):
        result = _analyzer().analyze([])
        assert "No suspicious" in result.summary


# ---------------------------------------------------------------------------
# Process injection detection
# ---------------------------------------------------------------------------

class TestProcessInjectionDetection:
    _CLASSIC_INJECTION_IMPORTS = _imports(
        ("kernel32.dll", ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]),
    )

    def test_detects_classic_injection(self):
        result = _analyzer().analyze(self._CLASSIC_INJECTION_IMPORTS)
        cats = {c.category for c in result.capabilities}
        assert CapabilityCategory.PROCESS_INJECTION in cats

    def test_injection_confidence_high(self):
        result = _analyzer().analyze(self._CLASSIC_INJECTION_IMPORTS)
        inj = next(c for c in result.capabilities if c.category == CapabilityCategory.PROCESS_INJECTION)
        assert inj.confidence >= 0.8

    def test_injection_has_mitre_technique(self):
        result = _analyzer().analyze(self._CLASSIC_INJECTION_IMPORTS)
        inj = next(c for c in result.capabilities if c.category == CapabilityCategory.PROCESS_INJECTION)
        assert "T1055" in inj.mitre_techniques

    def test_risk_score_elevated(self):
        result = _analyzer().analyze(self._CLASSIC_INJECTION_IMPORTS)
        assert result.risk_score >= 1.0


# ---------------------------------------------------------------------------
# Process hollowing detection
# ---------------------------------------------------------------------------

class TestProcessHollowingDetection:
    _HOLLOWING_IMPORTS = _imports(
        ("kernel32.dll", [
            "CreateProcessA", "VirtualAllocEx", "WriteProcessMemory",
            "SetThreadContext", "ResumeThread",
        ]),
        ("ntdll.dll", ["NtUnmapViewOfSection"]),
    )

    def test_detects_hollowing(self):
        result = _analyzer().analyze(self._HOLLOWING_IMPORTS)
        cats = {c.category for c in result.capabilities}
        assert CapabilityCategory.PROCESS_HOLLOWING in cats

    def test_hollowing_mitre(self):
        result = _analyzer().analyze(self._HOLLOWING_IMPORTS)
        hollow = next(c for c in result.capabilities if c.category == CapabilityCategory.PROCESS_HOLLOWING)
        assert "T1055.012" in hollow.mitre_techniques


# ---------------------------------------------------------------------------
# Anti-debug detection
# ---------------------------------------------------------------------------

class TestAntiDebugDetection:
    _ANTIDEBUG_IMPORTS = _imports(
        ("kernel32.dll", ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]),
    )

    def test_detects_anti_debug(self):
        result = _analyzer().analyze(self._ANTIDEBUG_IMPORTS)
        cats = {c.category for c in result.capabilities}
        assert CapabilityCategory.ANTI_DEBUG in cats

    def test_anti_debug_mitre_t1622(self):
        result = _analyzer().analyze(self._ANTIDEBUG_IMPORTS)
        cap = next(c for c in result.capabilities if c.category == CapabilityCategory.ANTI_DEBUG)
        assert "T1622" in cap.mitre_techniques


# ---------------------------------------------------------------------------
# Ransomware detection
# ---------------------------------------------------------------------------

class TestRansomwareDetection:
    _RANSOMWARE_IMPORTS = _imports(
        ("advapi32.dll", ["CryptEncrypt", "CryptGenKey", "CryptAcquireContextA"]),
        ("kernel32.dll", ["FindFirstFileW", "FindNextFileW", "FindClose", "DeleteFileW", "MoveFileExW"]),
    )

    def test_detects_ransomware_encryption(self):
        result = _analyzer().analyze(self._RANSOMWARE_IMPORTS)
        cats = {c.category for c in result.capabilities}
        assert CapabilityCategory.RANSOMWARE_BEHAVIOR in cats

    def test_ransomware_risk_high(self):
        result = _analyzer().analyze(self._RANSOMWARE_IMPORTS)
        assert result.risk_score >= 2.0

    def test_ransomware_family_hint(self):
        result = _analyzer().analyze(
            _imports(
                ("advapi32.dll", ["CryptEncrypt", "CryptGenKey", "CryptAcquireContextA"]),
                ("kernel32.dll", ["FindFirstFileW", "FindNextFileW", "FindClose",
                                   "DeleteFileW", "MoveFileExW", "BCryptEncrypt"]),
            )
        )
        families = {h.family for h in result.family_hints}
        assert any("Ransomware" in f for f in families)


# ---------------------------------------------------------------------------
# C2 communication detection
# ---------------------------------------------------------------------------

class TestC2Detection:
    _C2_IMPORTS = _imports(
        ("wininet.dll", [
            "InternetOpenA", "InternetConnectA",
            "HttpOpenRequestA", "HttpSendRequestA", "InternetReadFile",
        ]),
    )

    def test_detects_c2_communication(self):
        result = _analyzer().analyze(self._C2_IMPORTS)
        cats = {c.category for c in result.capabilities}
        assert CapabilityCategory.C2_COMMUNICATION in cats

    def test_c2_mitre_technique(self):
        result = _analyzer().analyze(self._C2_IMPORTS)
        cap = next(c for c in result.capabilities if c.category == CapabilityCategory.C2_COMMUNICATION)
        assert "T1071.001" in cap.mitre_techniques


# ---------------------------------------------------------------------------
# Downloader detection
# ---------------------------------------------------------------------------

class TestDownloaderDetection:
    def test_detects_url_downloader(self):
        result = _analyzer().analyze(
            _imports(("urlmon.dll", ["URLDownloadToFileA"]))
        )
        caps = {c.category for c in result.capabilities}
        assert CapabilityCategory.C2_COMMUNICATION in caps


# ---------------------------------------------------------------------------
# Privilege escalation
# ---------------------------------------------------------------------------

class TestPrivilegeEscalation:
    _PRIVESC_IMPORTS = _imports(
        ("advapi32.dll", ["OpenProcessToken", "AdjustTokenPrivileges", "LookupPrivilegeValueA"]),
    )

    def test_detects_privilege_escalation(self):
        result = _analyzer().analyze(self._PRIVESC_IMPORTS)
        cats = {c.category for c in result.capabilities}
        assert CapabilityCategory.PRIVILEGE_ESCALATION in cats

    def test_privesc_mitre(self):
        result = _analyzer().analyze(self._PRIVESC_IMPORTS)
        cap = next(c for c in result.capabilities if c.category == CapabilityCategory.PRIVILEGE_ESCALATION)
        assert "T1134" in cap.mitre_techniques


# ---------------------------------------------------------------------------
# Rootkit detection
# ---------------------------------------------------------------------------

class TestRootkitDetection:
    def test_detects_driver_load(self):
        result = _analyzer().analyze(
            _imports(("ntdll.dll", ["NtLoadDriver"]))
        )
        cats = {c.category for c in result.capabilities}
        assert CapabilityCategory.ROOTKIT_BEHAVIOR in cats


# ---------------------------------------------------------------------------
# Compound sample: RAT
# ---------------------------------------------------------------------------

class TestRATSample:
    _RAT_IMPORTS = _imports(
        ("kernel32.dll", [
            "CreateProcessA", "OpenProcess", "VirtualAllocEx",
            "WriteProcessMemory", "CreateRemoteThread",
            "IsDebuggerPresent",
        ]),
        ("ws2_32.dll", ["WSAStartup", "connect", "send", "recv", "socket", "closesocket"]),
        ("advapi32.dll", ["RegCreateKeyExA", "RegSetValueExA"]),
        ("wininet.dll", ["InternetOpenA", "InternetConnectA",
                         "HttpOpenRequestA", "HttpSendRequestA"]),
    )

    def test_rat_has_multiple_capabilities(self):
        result = _analyzer().analyze(self._RAT_IMPORTS)
        assert len(result.capabilities) >= 3

    def test_rat_risk_score_high(self):
        result = _analyzer().analyze(self._RAT_IMPORTS)
        assert result.risk_score >= 4.0

    def test_rat_to_dict_structure(self):
        result = _analyzer().analyze(self._RAT_IMPORTS)
        d = result.to_dict()
        assert "risk_score" in d
        assert "capabilities" in d
        assert "family_hints" in d
        assert "mitre_techniques" in d
        assert isinstance(d["capabilities"], list)

    def test_rat_family_hint(self):
        result = _analyzer().analyze(self._RAT_IMPORTS)
        assert any("RAT" in h.family or "Backdoor" in h.family for h in result.family_hints)

    def test_mitre_techniques_deduplicated(self):
        result = _analyzer().analyze(self._RAT_IMPORTS)
        techniques = result.mitre_techniques
        assert len(techniques) == len(set(techniques))


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

class TestPersistenceDetection:
    def test_detects_registry_persistence(self):
        result = _analyzer().analyze(
            _imports(("advapi32.dll", ["RegCreateKeyExA", "RegSetValueExA"]))
        )
        cats = {c.category for c in result.capabilities}
        assert CapabilityCategory.PERSISTENCE in cats

    def test_detects_service_creation(self):
        result = _analyzer().analyze(
            _imports(("advapi32.dll", ["OpenSCManagerA", "CreateServiceA"]))
        )
        cats = {c.category for c in result.capabilities}
        assert CapabilityCategory.SERVICE_ABUSE in cats


# ---------------------------------------------------------------------------
# Result properties
# ---------------------------------------------------------------------------

class TestResultProperties:
    def test_high_confidence_filter(self):
        result = _analyzer().analyze(
            _imports(
                ("kernel32.dll", ["OpenProcess", "VirtualAllocEx",
                                   "WriteProcessMemory", "CreateRemoteThread"]),
            )
        )
        hc = result.high_confidence_capabilities
        assert all(c.confidence >= 0.7 for c in hc)

    def test_suspicious_api_count_nonzero(self):
        result = _analyzer().analyze(
            _imports(("kernel32.dll", ["IsDebuggerPresent"]))
        )
        assert result.suspicious_api_count >= 1

    def test_dll_count_matches_input(self):
        imports = [
            _FakeImport("kernel32.dll", ["CreateFileA"]),
            _FakeImport("ntdll.dll", ["NtLoadDriver"]),
        ]
        result = _analyzer().analyze(imports)
        assert result.dll_count == 2
