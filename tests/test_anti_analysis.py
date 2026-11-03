"""
Tests for the anti_analysis module.
"""

from __future__ import annotations

from typing import List

import pytest

from specter.anti_analysis import (
    AntiAnalysisDetector,
    AntiAnalysisTechnique,
    EvasionFinding,
    EvasionReport,
    EvasionSeverity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _detect(
    imports: List[str] = None,
    strings: List[str] = None,
    raw_data: bytes = b"",
    sample_id: str = "test_sample",
) -> EvasionReport:
    detector = AntiAnalysisDetector()
    return detector.analyze(
        sample_id=sample_id,
        imports=imports or [],
        strings=strings or [],
        raw_data=raw_data if raw_data else None,
    )


# ---------------------------------------------------------------------------
# EvasionReport
# ---------------------------------------------------------------------------


class TestEvasionReport:
    def test_add_finding_updates_severity(self) -> None:
        report = EvasionReport(sample_id="s")
        report.add_finding(EvasionFinding(
            technique=AntiAnalysisTechnique.ISDEBUGGERPRESENT,
            severity=EvasionSeverity.HIGH,
            description="",
            mitre_technique="T1622",
            mitre_subtechnique="",
        ))
        assert report.overall_severity == EvasionSeverity.HIGH

    def test_add_finding_tracks_techniques(self) -> None:
        report = EvasionReport(sample_id="s")
        report.add_finding(EvasionFinding(
            technique=AntiAnalysisTechnique.CPUID_HYPERVISOR,
            severity=EvasionSeverity.MEDIUM,
            description="",
            mitre_technique="T1497",
            mitre_subtechnique="001",
        ))
        assert AntiAnalysisTechnique.CPUID_HYPERVISOR in report.techniques

    def test_score_computation_caps_at_100(self) -> None:
        report = EvasionReport(sample_id="s")
        for _ in range(10):
            report.add_finding(EvasionFinding(
                technique=AntiAnalysisTechnique.VMWARE_REGISTRY,
                severity=EvasionSeverity.CRITICAL,
                description="",
                mitre_technique="T1497",
                mitre_subtechnique="001",
            ))
        report.compute_score()
        assert report.evasion_score == 100

    def test_score_zero_for_empty_report(self) -> None:
        report = EvasionReport(sample_id="s")
        report.compute_score()
        assert report.evasion_score == 0

    def test_flag_vm_aware(self) -> None:
        report = EvasionReport(sample_id="s")
        report.add_finding(EvasionFinding(
            technique=AntiAnalysisTechnique.CPUID_HYPERVISOR,
            severity=EvasionSeverity.MEDIUM,
            description="",
            mitre_technique="T1497",
            mitre_subtechnique="001",
        ))
        report.compute_score()
        assert report.is_vm_aware
        assert not report.is_debugger_aware

    def test_flag_debugger_aware(self) -> None:
        report = EvasionReport(sample_id="s")
        report.add_finding(EvasionFinding(
            technique=AntiAnalysisTechnique.ISDEBUGGERPRESENT,
            severity=EvasionSeverity.HIGH,
            description="",
            mitre_technique="T1622",
            mitre_subtechnique="",
        ))
        report.compute_score()
        assert report.is_debugger_aware
        assert not report.is_vm_aware

    def test_to_dict_contains_expected_keys(self) -> None:
        report = EvasionReport(sample_id="abc")
        report.compute_score()
        d = report.to_dict()
        assert d["sample_id"] == "abc"
        assert "evasion_score" in d
        assert "findings" in d
        assert isinstance(d["techniques"], list)


# ---------------------------------------------------------------------------
# Import-based detection
# ---------------------------------------------------------------------------


class TestImportDetection:
    def test_detects_is_debugger_present(self) -> None:
        report = _detect(imports=["kernel32.dll!IsDebuggerPresent"])
        assert AntiAnalysisTechnique.ISDEBUGGERPRESENT in report.techniques
        assert report.is_debugger_aware

    def test_detects_nt_query_information_process(self) -> None:
        report = _detect(imports=["ntdll.dll!NtQueryInformationProcess"])
        assert AntiAnalysisTechnique.NTQUERYINFORMATIONPROCESS in report.techniques

    def test_detects_nt_set_information_thread(self) -> None:
        report = _detect(imports=["ntdll.dll!NtSetInformationThread"])
        assert AntiAnalysisTechnique.NTSETINFORMATIONTHREAD in report.techniques

    def test_detects_output_debug_string(self) -> None:
        report = _detect(imports=["kernel32.dll!OutputDebugStringA"])
        assert AntiAnalysisTechnique.OUTPUTDEBUGSTRING in report.techniques

    def test_detects_get_tick_count(self) -> None:
        report = _detect(imports=["kernel32.dll!GetTickCount"])
        assert AntiAnalysisTechnique.GETTICKCOUNT_TIMING in report.techniques
        assert report.is_timing_aware

    def test_detects_query_performance_counter(self) -> None:
        report = _detect(imports=["kernel32.dll!QueryPerformanceCounter"])
        assert AntiAnalysisTechnique.QUERYPERFORMANCECOUNTER in report.techniques

    def test_detects_nt_unmap_view_of_section(self) -> None:
        report = _detect(imports=["ntdll.dll!NtUnmapViewOfSection"])
        assert AntiAnalysisTechnique.NTUNMAPVIEWOFSECTION in report.techniques

    def test_detects_virtual_protect(self) -> None:
        report = _detect(imports=["kernel32.dll!VirtualProtect"])
        assert AntiAnalysisTechnique.VIRTUALPROTECT_EXEC in report.techniques

    def test_detects_get_computer_name(self) -> None:
        report = _detect(imports=["kernel32.dll!GetComputerNameW"])
        assert AntiAnalysisTechnique.GETCOMPUTERNAME in report.techniques
        assert report.is_environment_aware

    def test_no_false_positive_on_empty(self) -> None:
        report = _detect()
        assert len(report.findings) == 0
        assert report.evasion_score == 0

    def test_wfso_combined_check(self) -> None:
        report = _detect(imports=["kernel32.dll!WaitForSingleObject"])
        assert AntiAnalysisTechnique.WFSO_SLEEP in report.techniques

    def test_parent_process_check_combined(self) -> None:
        report = _detect(imports=[
            "kernel32.dll!CreateToolhelp32Snapshot",
            "kernel32.dll!Process32FirstW",
        ])
        assert AntiAnalysisTechnique.PARENT_PROCESS_CHECK in report.techniques

    def test_heap_flag_check_combined(self) -> None:
        report = _detect(imports=[
            "kernel32.dll!GetProcessHeap",
            "kernel32.dll!HeapWalk",
        ])
        assert AntiAnalysisTechnique.HEAP_FLAG_CHECK in report.techniques


# ---------------------------------------------------------------------------
# String-based detection
# ---------------------------------------------------------------------------


class TestStringDetection:
    def test_detects_vmware_string(self) -> None:
        report = _detect(strings=["SOFTWARE\\VMware, Inc.\\VMware Tools"])
        assert AntiAnalysisTechnique.VMWARE_REGISTRY in report.techniques
        assert report.is_vm_aware

    def test_detects_vmware_process(self) -> None:
        report = _detect(strings=["VMwareService.exe"])
        assert AntiAnalysisTechnique.VMWARE_PROCESS in report.techniques

    def test_detects_virtualbox_device(self) -> None:
        report = _detect(strings=["VBoxGuestAdditions"])
        assert AntiAnalysisTechnique.VIRTUALBOX_DEVICE in report.techniques
        assert report.is_vm_aware

    def test_detects_virtualbox_process(self) -> None:
        report = _detect(strings=["VBoxService.exe"])
        assert AntiAnalysisTechnique.VIRTUALBOX_PROCESS in report.techniques

    def test_detects_cuckoo_pipe(self) -> None:
        report = _detect(strings=["\\\\.\\pipe\\cuckoo"])
        assert AntiAnalysisTechnique.CUCKOO_PIPE in report.techniques
        assert report.is_sandbox_aware

    def test_detects_sandboxie_dll(self) -> None:
        report = _detect(strings=["SbieDll.dll"])
        assert AntiAnalysisTechnique.SBIEDLL in report.techniques
        assert report.is_sandbox_aware

    def test_detects_wine_artifact(self) -> None:
        report = _detect(strings=["wine_get_unix_file_name"])
        assert AntiAnalysisTechnique.WINE_ARTIFACT in report.techniques

    def test_detects_qemu_cpuid_string(self) -> None:
        report = _detect(strings=["KVMKVMKVM\x00"])
        assert AntiAnalysisTechnique.QEMU_ARTIFACT in report.techniques
        assert report.is_vm_aware

    def test_detects_hyperv_string(self) -> None:
        report = _detect(strings=["Microsoft Hv"])
        assert AntiAnalysisTechnique.HYPERV_ARTIFACT in report.techniques

    def test_detects_known_sandbox_hostname(self) -> None:
        report = _detect(strings=["cuckoo-host"])
        assert AntiAnalysisTechnique.KNOWN_SANDBOX_HOSTNAME in report.techniques
        assert report.is_sandbox_aware

    def test_detects_known_sandbox_username(self) -> None:
        report = _detect(strings=["malware"])
        assert AntiAnalysisTechnique.KNOWN_SANDBOX_USERNAME in report.techniques

    def test_detects_mouse_movement_check(self) -> None:
        report = _detect(strings=["GetCursorPos"])
        assert AntiAnalysisTechnique.MOUSE_MOVEMENT_CHECK in report.techniques

    def test_detects_screen_resolution_check(self) -> None:
        report = _detect(strings=["SM_CXSCREEN"])
        assert AntiAnalysisTechnique.SCREEN_RESOLUTION_CHECK in report.techniques

    def test_no_false_positive_on_benign_strings(self) -> None:
        report = _detect(strings=["Hello World", "Open file", "Error reading input"])
        assert len(report.findings) == 0


# ---------------------------------------------------------------------------
# Raw byte detection
# ---------------------------------------------------------------------------


class TestRawByteDetection:
    def test_detects_rdtsc_opcode(self) -> None:
        report = _detect(raw_data=b"\x00" * 4 + b"\x0f\x31" + b"\x00" * 4)
        assert AntiAnalysisTechnique.RDTSC_TIMING in report.techniques
        assert report.is_timing_aware

    def test_detects_cpuid_opcode(self) -> None:
        report = _detect(raw_data=b"\x00" * 4 + b"\x0f\xa2" + b"\x00" * 4)
        assert AntiAnalysisTechnique.CPUID_HYPERVISOR in report.techniques

    def test_detects_int3_sled(self) -> None:
        report = _detect(raw_data=b"\x00" * 4 + b"\xcc" * 8 + b"\x00" * 4)
        assert AntiAnalysisTechnique.INT3_PATCH in report.techniques

    def test_no_int3_false_positive_below_threshold(self) -> None:
        # Only 3 consecutive INT3s — below the 5-byte threshold
        report = _detect(raw_data=b"\x00" * 4 + b"\xcc" * 3 + b"\x00" * 4)
        assert AntiAnalysisTechnique.INT3_PATCH not in report.techniques

    def test_no_raw_checks_on_none_data(self) -> None:
        # raw_data=None must not crash
        report = _detect(raw_data=b"")
        assert isinstance(report, EvasionReport)


# ---------------------------------------------------------------------------
# Score and severity integration
# ---------------------------------------------------------------------------


class TestScoreIntegration:
    def test_critical_finding_sets_high_score(self) -> None:
        report = _detect(
            strings=["SbieDll.dll", "\\\\.\\pipe\\cuckoo"],
            imports=["IsDebuggerPresent", "NtQueryInformationProcess"],
        )
        assert report.evasion_score >= 40
        assert report.overall_severity in (
            EvasionSeverity.HIGH,
            EvasionSeverity.CRITICAL,
        )

    def test_multiple_categories_detected(self) -> None:
        report = _detect(
            imports=["IsDebuggerPresent", "GetTickCount"],
            strings=["VMwareService.exe", "SbieDll.dll"],
        )
        report.compute_score()
        assert report.is_debugger_aware
        assert report.is_timing_aware
        assert report.is_vm_aware
        assert report.is_sandbox_aware

    def test_to_dict_round_trip(self) -> None:
        report = _detect(
            imports=["IsDebuggerPresent"],
            strings=["VMwareService.exe"],
        )
        d = report.to_dict()
        assert len(d["findings"]) >= 2
        for f in d["findings"]:
            assert "technique" in f
            assert "severity" in f
            assert "mitre" in f
