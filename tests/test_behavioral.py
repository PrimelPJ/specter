"""Tests for the behavioral indicator analyzer."""

import pytest

from specter.behavioral import (
    BehaviorCategory,
    BehavioralAnalyzer,
    BehaviorReport,
)


HASH = "a" * 64


class TestBehavioralAnalyzer:
    def setup_method(self):
        self.analyzer = BehavioralAnalyzer()

    def test_empty_sample_produces_empty_report(self):
        report = self.analyzer.analyze(HASH, {}, [], is_packed=False)
        assert report.sample_hash == HASH
        assert report.indicator_count == 0
        assert report.overall_severity == 0
        assert not report.has_network_activity
        assert not report.has_persistence
        assert not report.has_anti_analysis

    def test_network_imports_detected(self):
        imports = {"ws2_32.dll": ["WSAStartup", "connect", "send", "recv"]}
        report = self.analyzer.analyze(HASH, imports, [])
        assert report.has_network_activity
        assert BehaviorCategory.NETWORK in report.categories
        assert "T1071" in report.mitre_techniques

    def test_injection_imports_detected(self):
        imports = {
            "kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
        }
        report = self.analyzer.analyze(HASH, imports, [])
        assert BehaviorCategory.INJECTION in report.categories
        assert "T1055" in report.mitre_techniques
        assert report.overall_severity == 5

    def test_registry_persistence_imports(self):
        imports = {
            "advapi32.dll": ["RegSetValueExA", "RegCreateKeyExA", "RegOpenKeyExA"]
        }
        report = self.analyzer.analyze(HASH, imports, [])
        assert report.has_persistence
        assert BehaviorCategory.PERSISTENCE in report.categories

    def test_debugger_detection_imports(self):
        imports = {"kernel32.dll": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]}
        report = self.analyzer.analyze(HASH, imports, [])
        assert report.has_anti_analysis
        assert BehaviorCategory.ANTI_ANALYSIS in report.categories

    def test_hardcoded_url_string_detected(self):
        strings = [b"http://evil.example.com/payload.exe"]
        report = self.analyzer.analyze(HASH, {}, strings)
        assert report.has_network_activity
        assert BehaviorCategory.NETWORK in report.categories

    def test_hardcoded_ip_port_detected(self):
        strings = [b"192.168.1.100:4444"]
        report = self.analyzer.analyze(HASH, {}, strings)
        assert BehaviorCategory.NETWORK in report.categories

    def test_ransomware_string_detected(self):
        strings = [b"Your files have been encrypted. Pay ransom in bitcoin"]
        report = self.analyzer.analyze(HASH, {}, strings)
        assert BehaviorCategory.EXECUTION in report.categories
        assert "T1486" in report.mitre_techniques

    def test_vm_detection_string(self):
        strings = [b"VBoxService.exe"]
        report = self.analyzer.analyze(HASH, {}, strings)
        assert BehaviorCategory.ANTI_ANALYSIS in report.categories

    def test_process_hollowing_detected(self):
        imports = {"ntdll.dll": ["NtUnmapViewOfSection", "ZwUnmapViewOfSection"]}
        report = self.analyzer.analyze(HASH, imports, [])
        assert BehaviorCategory.INJECTION in report.categories
        assert any("T1055.012" in t for t in report.mitre_techniques)

    def test_keylogging_detection(self):
        imports = {"user32.dll": ["SetWindowsHookExA", "GetAsyncKeyState"]}
        report = self.analyzer.analyze(HASH, imports, [])
        assert BehaviorCategory.COLLECTION in report.categories
        assert "T1056" in report.mitre_techniques

    def test_packed_flag_preserved(self):
        report = self.analyzer.analyze(HASH, {}, [], is_packed=True)
        assert report.is_packed is True

    def test_rat_family_classification(self):
        imports = {
            "kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
            "ws2_32.dll": ["connect", "send", "recv"],
            "advapi32.dll": ["RegSetValueExA"],
        }
        report = self.analyzer.analyze(HASH, imports, [])
        assert "rat" in report.malware_families

    def test_infostealer_family_classification(self):
        imports = {
            "advapi32.dll": ["LsaOpenPolicy", "CryptUnprotectData"],
            "kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        }
        report = self.analyzer.analyze(HASH, imports, [])
        assert "infostealer" in report.malware_families

    def test_severity_label(self):
        report = BehaviorReport(sample_hash=HASH, overall_severity=4)
        assert report.severity_label == "CRITICAL"

    def test_summary_keys(self):
        imports = {"ws2_32.dll": ["connect"]}
        report = self.analyzer.analyze(HASH, imports, [])
        summary = report.summary()
        assert "severity" in summary
        assert "categories" in summary
        assert "mitre_techniques" in summary
        assert "flags" in summary

    def test_credential_access(self):
        imports = {"advapi32.dll": ["LsaOpenPolicy", "SamOpenDomain", "CryptUnprotectData"]}
        report = self.analyzer.analyze(HASH, imports, [])
        assert BehaviorCategory.CREDENTIAL_ACCESS in report.categories
        assert "T1003" in report.mitre_techniques
