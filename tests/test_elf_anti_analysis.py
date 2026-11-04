"""Tests for ELF anti-analysis and sandbox evasion detection."""

from __future__ import annotations

import pytest

from specter.elf_anti_analysis import (
    ELFAntiAnalysisDetector,
    ELFAntiTechnique,
    ELFEvasionSeverity,
    ELFEvasionReport,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect(symbols=None, strings=None, raw_data=None):
    detector = ELFAntiAnalysisDetector()
    return detector.analyze(
        sample_id="test-sha256",
        symbols=symbols or [],
        strings=strings or [],
        raw_data=raw_data,
    )


# ---------------------------------------------------------------------------
# Symbol-based detection
# ---------------------------------------------------------------------------

class TestSymbolDetection:
    def test_ptrace_detected(self):
        report = _detect(symbols=["ptrace"])
        assert ELFAntiTechnique.PTRACE_TRACEME in report.techniques
        assert report.is_ptrace_aware

    def test_prctl_detected(self):
        report = _detect(symbols=["prctl"])
        assert ELFAntiTechnique.PRCTL_SET_DUMPABLE in report.techniques
        assert report.is_ptrace_aware

    def test_clock_gettime_detected(self):
        report = _detect(symbols=["clock_gettime"])
        assert ELFAntiTechnique.CLOCK_GETTIME_DELTA in report.techniques
        assert report.is_timing_aware

    def test_gettimeofday_detected(self):
        report = _detect(symbols=["gettimeofday"])
        assert ELFAntiTechnique.GETTIMEOFDAY_DELTA in report.techniques
        assert report.is_timing_aware

    def test_memfd_create_detected(self):
        report = _detect(symbols=["memfd_create"])
        assert ELFAntiTechnique.MEMFD_SECRET in report.techniques

    def test_dlopen_dlsym_detected(self):
        report = _detect(symbols=["dlopen", "dlsym"])
        assert ELFAntiTechnique.DLOPEN_SELF_CHECK in report.techniques
        assert ELFAntiTechnique.PLT_HOOK_DETECT in report.techniques
        assert report.is_preload_aware

    def test_signal_detected(self):
        report = _detect(symbols=["signal"])
        assert ELFAntiTechnique.SIGNAL_SIGTRAP in report.techniques

    def test_sigaction_detected(self):
        report = _detect(symbols=["sigaction"])
        assert ELFAntiTechnique.SIGACTION_CHAIN in report.techniques

    def test_mprotect_detected(self):
        report = _detect(symbols=["mprotect"])
        assert ELFAntiTechnique.MPROTECT_EXEC in report.techniques

    def test_no_false_positives_on_empty(self):
        report = _detect()
        assert len(report.findings) == 0
        assert report.evasion_score == 0


# ---------------------------------------------------------------------------
# String-based detection
# ---------------------------------------------------------------------------

class TestStringDetection:
    def test_proc_self_status(self):
        report = _detect(strings=["/proc/self/status"])
        assert ELFAntiTechnique.PROC_TRACER_PID in report.techniques

    def test_tracerpid_string(self):
        report = _detect(strings=["TracerPid: 1234"])
        assert ELFAntiTechnique.PROC_TRACER_PID in report.techniques
        # Should be CRITICAL severity
        for f in report.findings:
            if f.technique == ELFAntiTechnique.PROC_TRACER_PID:
                assert f.severity == ELFEvasionSeverity.CRITICAL

    def test_proc_self_exe(self):
        report = _detect(strings=["/proc/self/exe"])
        assert ELFAntiTechnique.PROC_EXE_PATH in report.techniques

    def test_proc_self_maps(self):
        report = _detect(strings=["/proc/self/maps"])
        assert ELFAntiTechnique.PROC_MAPS_INSPECTOR in report.techniques

    def test_ld_preload(self):
        report = _detect(strings=["checking LD_PRELOAD variable"])
        assert ELFAntiTechnique.LDPRELOAD_CHECK in report.techniques
        assert report.is_env_aware

    def test_ld_audit(self):
        report = _detect(strings=["LD_AUDIT is set"])
        assert ELFAntiTechnique.LDAUDIT_CHECK in report.techniques

    def test_cuckoo_artifact(self):
        report = _detect(strings=["cuckoo sandbox detected"])
        assert ELFAntiTechnique.CUCKOO_AGENT in report.techniques
        assert report.is_sandbox_aware

    def test_drakvuf_artifact(self):
        report = _detect(strings=["drakvuf"])
        assert ELFAntiTechnique.DRAKVUF_ARTIFACT in report.techniques
        assert report.is_sandbox_aware

    def test_anyrun_artifact(self):
        report = _detect(strings=["any.run"])
        assert ELFAntiTechnique.ANYRUN_ARTIFACT in report.techniques
        assert report.is_sandbox_aware

    def test_sandbox_username(self):
        report = _detect(strings=["user=sandbox"])
        assert ELFAntiTechnique.SANDBOX_USERNAME in report.techniques

    def test_sandbox_path(self):
        report = _detect(strings=["/home/user/malware.elf"])
        assert ELFAntiTechnique.SANDBOX_PATH_ARTIFACT in report.techniques

    def test_docker_env_file(self):
        report = _detect(strings=["/.dockerenv"])
        assert ELFAntiTechnique.DOCKER_ENV_FILE in report.techniques
        assert report.is_vm_aware

    def test_cgroup_container(self):
        report = _detect(strings=["/sys/fs/cgroup"])
        assert ELFAntiTechnique.CGROUP_CONTAINER in report.techniques

    def test_dmi_hypervisor(self):
        report = _detect(strings=["/sys/class/dmi/id/product_name"])
        assert ELFAntiTechnique.DMI_HYPERVISOR in report.techniques

    def test_frida_env_var(self):
        report = _detect(strings=["FRIDA_AGENT"])
        assert ELFAntiTechnique.ENV_ANALYSIS_DETECT in report.techniques

    def test_proc_mem_inject(self):
        report = _detect(strings=["open /proc/self/mem for injection"])
        assert ELFAntiTechnique.PROC_MEM_INJECT in report.techniques
        for f in report.findings:
            if f.technique == ELFAntiTechnique.PROC_MEM_INJECT:
                assert f.severity == ELFEvasionSeverity.CRITICAL


# ---------------------------------------------------------------------------
# Raw byte checks
# ---------------------------------------------------------------------------

class TestRawByteDetection:
    def test_rdtsc_opcode(self):
        report = _detect(raw_data=b"\x90\x0f\x31\x90")
        assert ELFAntiTechnique.RDTSC_INLINE in report.techniques
        assert report.is_timing_aware

    def test_cpuid_opcode(self):
        report = _detect(raw_data=b"\x0f\xa2")
        assert ELFAntiTechnique.CPUINFO_HYPERVISOR in report.techniques
        assert report.is_vm_aware

    def test_int3_sled(self):
        report = _detect(raw_data=b"\xcc\xcc\xcc\xcc\xcc\xcc")
        assert ELFAntiTechnique.SIGNAL_SIGTRAP in report.techniques

    def test_short_int3_no_sled(self):
        # 4 consecutive 0xCC bytes should NOT trigger the INT3 sled rule
        report = _detect(raw_data=b"\xcc\xcc\xcc\xcc")
        assert ELFAntiTechnique.SIGNAL_SIGTRAP not in report.techniques


# ---------------------------------------------------------------------------
# Combined heuristics
# ---------------------------------------------------------------------------

class TestCombinedHeuristics:
    def test_ptrace_plus_fork_combination(self):
        report = _detect(symbols=["ptrace", "fork"])
        assert ELFAntiTechnique.PTRACE_TRACEME in report.techniques
        # fork reference should be noted in evidence
        for f in report.findings:
            if f.technique == ELFAntiTechnique.PTRACE_TRACEME:
                assert any("fork" in e for e in f.evidence)

    def test_timing_sleep_combination(self):
        report = _detect(symbols=["clock_gettime", "nanosleep"])
        assert ELFAntiTechnique.CLOCK_NANOSLEEP in report.techniques

    def test_getenv_with_sandbox_string(self):
        report = _detect(
            symbols=["getenv"],
            strings=["checking for LD_PRELOAD", "cuckoo sandbox"],
        )
        # Should detect both LD_PRELOAD (string rule) and combined getenv heuristic
        assert ELFAntiTechnique.LDPRELOAD_CHECK in report.techniques

    def test_open_plus_tracerpid(self):
        report = _detect(
            symbols=["open", "fopen"],
            strings=["TracerPid"],
        )
        assert ELFAntiTechnique.PROC_TRACER_PID in report.techniques


# ---------------------------------------------------------------------------
# Scoring and report
# ---------------------------------------------------------------------------

class TestScoring:
    def test_zero_score_on_empty(self):
        report = _detect()
        assert report.evasion_score == 0

    def test_score_increases_with_findings(self):
        report_low = _detect(symbols=["clock_gettime"])
        report_high = _detect(symbols=["ptrace", "prctl", "memfd_create"],
                               strings=["cuckoo", "TracerPid"])
        assert report_high.evasion_score > report_low.evasion_score

    def test_score_capped_at_100(self):
        # many high/critical findings
        report = _detect(
            symbols=["ptrace", "prctl", "signal", "sigaction", "memfd_create",
                     "mprotect", "dlopen", "dlsym", "clock_gettime", "gettimeofday"],
            strings=["cuckoo", "drakvuf", "TracerPid", "LD_PRELOAD",
                     "/proc/self/mem", "FRIDA_AGENT"],
            raw_data=b"\x0f\x31\x0f\xa2" + b"\xcc" * 10,
        )
        assert report.evasion_score <= 100

    def test_to_dict_structure(self):
        report = _detect(symbols=["ptrace"])
        d = report.to_dict()
        assert "sample_id" in d
        assert "evasion_score" in d
        assert "findings" in d
        assert isinstance(d["findings"], list)
        assert d["findings"][0]["technique"] == ELFAntiTechnique.PTRACE_TRACEME.value

    def test_overall_severity_critical_when_critical_found(self):
        report = _detect(strings=["TracerPid: 42"])
        assert report.overall_severity == ELFEvasionSeverity.CRITICAL


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def test_deduplication():
    """Same technique detected via both string and combined heuristic should not duplicate."""
    report = _detect(
        symbols=["open"],
        strings=["/proc/self/status", "TracerPid: 1"],
    )
    tracer_findings = [f for f in report.findings
                       if f.technique == ELFAntiTechnique.PROC_TRACER_PID]
    assert len(tracer_findings) == 1
