"""Tests for the x86/x64 code-flow disassembler."""

from __future__ import annotations

import struct
import pytest

from specter.disasm import (
    CodeFlowAnalyzer,
    DisasmResult,
    FindingKind,
    InsnClass,
    Instruction,
    PatternAnalyzer,
    X86Decoder,
    _make_invalid,
    _modrm_length,
)


# ---------------------------------------------------------------------------
# Helper builders for raw instruction bytes
# ---------------------------------------------------------------------------

def nop() -> bytes:
    return b"\x90"

def ret() -> bytes:
    return b"\xc3"

def int3() -> bytes:
    return b"\xcc"

def rdtsc() -> bytes:
    return b"\x0f\x31"

def cpuid() -> bytes:
    return b"\x0f\xa2"

def pushf() -> bytes:
    return b"\x9c"

def popf() -> bytes:
    return b"\x9d"

def jmp_rel8(offset: int) -> bytes:
    """Short unconditional JMP with signed 8-bit relative offset."""
    return struct.pack("Bb", 0xeb, offset)

def jmp_rel32(offset: int) -> bytes:
    """Near unconditional JMP with signed 32-bit relative offset."""
    return struct.pack("<Bi", 0xe9, offset)

def call_rel32(offset: int) -> bytes:
    """CALL with signed 32-bit relative offset."""
    return struct.pack("<Bi", 0xe8, offset)

def jz_rel8(offset: int) -> bytes:
    """JZ/JE with signed 8-bit relative offset."""
    return struct.pack("Bb", 0x74, offset)

def xor_eax_eax() -> bytes:
    """XOR eax, eax"""
    return b"\x33\xc0"

def mov_eax_imm32(val: int) -> bytes:
    """MOV eax, imm32"""
    return struct.pack("<BI", 0xb8, val)

def push_eax() -> bytes:
    return b"\x50"

def pop_eax() -> bytes:
    return b"\x58"

def int_imm8(n: int) -> bytes:
    return struct.pack("BB", 0xcd, n)

def jmp_reg_eax() -> bytes:
    """JMP eax (FF /4 with ModRM 0xE0: mod=11, reg=4, rm=0)"""
    return b"\xff\xe0"

def call_reg_eax() -> bytes:
    """CALL eax (FF /2 with ModRM 0xD0: mod=11, reg=2, rm=0)"""
    return b"\xff\xd0"


# ---------------------------------------------------------------------------
# X86Decoder unit tests
# ---------------------------------------------------------------------------

class TestX86Decoder:

    def test_decode_nop(self):
        decoder = X86Decoder()
        insns = decoder.decode(nop())
        assert len(insns) == 1
        assert insns[0].cls == InsnClass.NOP
        assert insns[0].length == 1
        assert insns[0].offset == 0

    def test_decode_ret(self):
        decoder = X86Decoder()
        insns = decoder.decode(ret())
        assert insns[0].cls == InsnClass.RET
        assert insns[0].mnemonic == "ret"

    def test_decode_int3(self):
        decoder = X86Decoder()
        insns = decoder.decode(int3())
        assert insns[0].cls == InsnClass.INT
        assert insns[0].mnemonic == "int3"

    def test_decode_rdtsc(self):
        decoder = X86Decoder()
        insns = decoder.decode(rdtsc())
        assert insns[0].cls == InsnClass.RDTSC
        assert insns[0].length == 2

    def test_decode_cpuid(self):
        decoder = X86Decoder()
        insns = decoder.decode(cpuid())
        assert insns[0].cls == InsnClass.CPUID
        assert insns[0].length == 2

    def test_decode_pushf_popf(self):
        decoder = X86Decoder()
        insns = decoder.decode(pushf() + popf())
        assert insns[0].cls == InsnClass.PUSHF
        assert insns[1].cls == InsnClass.POPF

    def test_decode_jmp_rel8(self):
        decoder = X86Decoder()
        insns = decoder.decode(jmp_rel8(5))
        assert insns[0].cls == InsnClass.JMP
        assert insns[0].length == 2
        # target = 0 (base) + 2 (length) + 5 (rel) = 7
        assert insns[0].target_offset == 7

    def test_decode_jmp_rel32(self):
        decoder = X86Decoder()
        insns = decoder.decode(jmp_rel32(100))
        assert insns[0].cls == InsnClass.JMP
        assert insns[0].length == 5
        assert insns[0].target_offset == 105

    def test_decode_call_rel32(self):
        decoder = X86Decoder()
        data = call_rel32(0)  # CALL to next instruction
        insns = decoder.decode(data)
        assert insns[0].cls == InsnClass.CALL
        assert insns[0].target_offset == 5  # offset 0 + length 5 + rel 0

    def test_decode_jcc(self):
        decoder = X86Decoder()
        insns = decoder.decode(jz_rel8(10))
        assert insns[0].cls == InsnClass.JCC

    def test_decode_xor_modrm(self):
        decoder = X86Decoder()
        insns = decoder.decode(xor_eax_eax())
        assert insns[0].cls == InsnClass.XOR
        assert insns[0].length == 2

    def test_decode_mov_imm32(self):
        decoder = X86Decoder()
        insns = decoder.decode(mov_eax_imm32(0xdeadbeef))
        assert insns[0].cls == InsnClass.MOV
        assert insns[0].length == 5

    def test_decode_push_pop(self):
        decoder = X86Decoder()
        insns = decoder.decode(push_eax() + pop_eax())
        assert insns[0].cls == InsnClass.PUSH
        assert insns[1].cls == InsnClass.POP

    def test_decode_indirect_jmp(self):
        decoder = X86Decoder()
        insns = decoder.decode(jmp_reg_eax())
        assert insns[0].cls == InsnClass.JMP
        assert insns[0].is_indirect

    def test_decode_indirect_call(self):
        decoder = X86Decoder()
        insns = decoder.decode(call_reg_eax())
        assert insns[0].cls == InsnClass.CALL
        assert insns[0].is_indirect

    def test_decode_unknown_opcode(self):
        decoder = X86Decoder()
        # 0x06 (PUSH ES) is not in our table -- should produce INVALID
        insns = decoder.decode(b"\x06")
        assert insns[0].cls == InsnClass.INVALID

    def test_decode_multi_instruction_stream(self):
        decoder = X86Decoder()
        data = nop() * 5 + ret()
        insns = decoder.decode(data)
        assert len(insns) == 6
        assert all(ins.cls == InsnClass.NOP for ins in insns[:5])
        assert insns[5].cls == InsnClass.RET

    def test_decode_base_offset(self):
        decoder = X86Decoder()
        insns = decoder.decode(nop() + ret(), base_offset=0x1000)
        assert insns[0].offset == 0x1000
        assert insns[1].offset == 0x1001

    def test_decode_empty_buffer(self):
        decoder = X86Decoder()
        insns = decoder.decode(b"")
        assert insns == []

    def test_decode_two_byte_escape_unknown(self):
        decoder = X86Decoder()
        # 0F FF is not in our 2-byte table
        insns = decoder.decode(b"\x0f\xff")
        assert insns[0].cls == InsnClass.INVALID

    def test_instruction_str(self):
        ins = Instruction(
            offset=0x1000,
            opcode_bytes=b"\x90",
            mnemonic="nop",
            cls=InsnClass.NOP,
            length=1,
        )
        s = str(ins)
        assert "0x1000" in s
        assert "nop" in s

    def test_decode_int_imm(self):
        decoder = X86Decoder()
        insns = decoder.decode(int_imm8(0x2d))
        assert insns[0].cls == InsnClass.INT
        assert insns[0].length == 2


# ---------------------------------------------------------------------------
# PatternAnalyzer unit tests
# ---------------------------------------------------------------------------

class TestPatternAnalyzer:

    def _make_insn(self, cls: InsnClass, offset: int, **kwargs) -> Instruction:
        return Instruction(
            offset=offset,
            opcode_bytes=b"\x90",
            mnemonic=cls.value,
            cls=cls,
            length=1,
            **kwargs,
        )

    def test_rdtsc_timing_detection(self):
        analyzer = PatternAnalyzer()
        insns = (
            [self._make_insn(InsnClass.NOP, i) for i in range(5)]
            + [self._make_insn(InsnClass.RDTSC, 5)]
            + [self._make_insn(InsnClass.NOP, i) for i in range(6, 16)]
            + [self._make_insn(InsnClass.RDTSC, 16)]
        )
        findings = analyzer.analyze(insns)
        rdtsc_f = [f for f in findings if f.kind == FindingKind.ANTI_DEBUG_RDTSC]
        assert len(rdtsc_f) >= 1
        assert rdtsc_f[0].confidence >= 0.8

    def test_rdtsc_no_false_positive_when_far_apart(self):
        analyzer = PatternAnalyzer()
        insns = (
            [self._make_insn(InsnClass.RDTSC, 0)]
            + [self._make_insn(InsnClass.NOP, i) for i in range(1, 50)]
            + [self._make_insn(InsnClass.RDTSC, 50)]
        )
        findings = analyzer.analyze(insns)
        rdtsc_f = [f for f in findings if f.kind == FindingKind.ANTI_DEBUG_RDTSC]
        assert len(rdtsc_f) == 0

    def test_int2d_detection(self):
        analyzer = PatternAnalyzer()
        insns = [
            Instruction(
                offset=0,
                opcode_bytes=b"\xcd\x2d",
                mnemonic="int",
                cls=InsnClass.INT,
                length=2,
                operand_str="0x2d",
            )
        ]
        findings = analyzer.analyze(insns)
        int2d = [f for f in findings if f.kind == FindingKind.ANTI_DEBUG_INT2D]
        assert len(int2d) == 1
        assert int2d[0].confidence >= 0.9

    def test_int3_cluster(self):
        analyzer = PatternAnalyzer()
        insns = [
            Instruction(
                offset=i,
                opcode_bytes=b"\xcc",
                mnemonic="int3",
                cls=InsnClass.INT,
                length=1,
            )
            for i in range(5)
        ]
        findings = analyzer.analyze(insns)
        int3_f = [f for f in findings if f.kind == FindingKind.ANTI_DEBUG_INT3]
        assert len(int3_f) >= 1

    def test_cpuid_abuse_detection(self):
        analyzer = PatternAnalyzer()
        insns = [
            self._make_insn(InsnClass.CPUID, 0),
            self._make_insn(InsnClass.CMP, 1),
            self._make_insn(InsnClass.NOP, 2),
        ]
        findings = analyzer.analyze(insns)
        cpuid_f = [f for f in findings if f.kind == FindingKind.ANTI_DEBUG_CPUID]
        assert len(cpuid_f) >= 1

    def test_pushf_tf_detection(self):
        analyzer = PatternAnalyzer()
        insns = [
            self._make_insn(InsnClass.PUSHF, 0),
            self._make_insn(InsnClass.XOR, 1),
            self._make_insn(InsnClass.POPF, 2),
        ]
        findings = analyzer.analyze(insns)
        tf_f = [f for f in findings if f.kind == FindingKind.ANTI_DEBUG_PUSHF]
        assert len(tf_f) >= 1

    def test_call_pop_pic_prolog(self):
        analyzer = PatternAnalyzer()
        # CALL targets the POP instruction (next in stream)
        call_insn = Instruction(
            offset=0, opcode_bytes=b"\xe8\x00\x00\x00\x00",
            mnemonic="call", cls=InsnClass.CALL, length=5,
            target_offset=5,  # points to POP at offset 5
        )
        pop_insn = Instruction(
            offset=5, opcode_bytes=b"\x58",
            mnemonic="pop", cls=InsnClass.POP, length=1,
        )
        insns = [call_insn, pop_insn]
        findings = analyzer.analyze(insns)
        pic_f = [f for f in findings if f.kind == FindingKind.SHELLCODE_CALL_POP]
        assert len(pic_f) >= 1
        assert pic_f[0].confidence >= 0.9

    def test_dense_jcc(self):
        analyzer = PatternAnalyzer()
        # Build 60 instructions with JCCs every 3rd (20 JCCs = 33%) -- above 25% threshold
        insns = []
        for i in range(60):
            cls = InsnClass.JCC if i % 3 == 0 else InsnClass.NOP
            insns.append(self._make_insn(cls, i))
        findings = analyzer.analyze(insns)
        jcc_f = [f for f in findings if f.kind == FindingKind.SHELLCODE_DENSE_JCC]
        assert len(jcc_f) >= 1

    def test_indirect_jmp_detection(self):
        analyzer = PatternAnalyzer()
        insns = [
            Instruction(
                offset=0, opcode_bytes=b"\xff\xe0",
                mnemonic="jmp", cls=InsnClass.JMP, length=2,
                is_indirect=True, operand_str="eax",
            )
        ]
        findings = analyzer.analyze(insns)
        ind_f = [f for f in findings if f.kind == FindingKind.SUSPICIOUS_INDIRECT_JMP]
        assert len(ind_f) >= 1

    def test_indirect_call_detection(self):
        analyzer = PatternAnalyzer()
        insns = [
            Instruction(
                offset=0, opcode_bytes=b"\xff\xd0",
                mnemonic="call", cls=InsnClass.CALL, length=2,
                is_indirect=True, operand_str="eax",
            )
        ]
        findings = analyzer.analyze(insns)
        ind_f = [f for f in findings if f.kind == FindingKind.SUSPICIOUS_INDIRECT_CALL]
        assert len(ind_f) >= 1


# ---------------------------------------------------------------------------
# CodeFlowAnalyzer integration tests
# ---------------------------------------------------------------------------

class TestCodeFlowAnalyzer:

    def test_analyze_nop_sled(self):
        analyzer = CodeFlowAnalyzer()
        data = nop() * 20 + ret()
        result = analyzer.analyze(data)
        assert result.arch == "x86"
        assert result.total_bytes == 21
        assert result.decoded_bytes > 0
        assert len(result.instructions) == 21

    def test_analyze_empty(self):
        analyzer = CodeFlowAnalyzer()
        result = analyzer.analyze(b"")
        assert result.total_bytes == 0
        assert result.instructions == []
        assert result.findings == []

    def test_analyze_rdtsc_timing(self):
        analyzer = CodeFlowAnalyzer()
        # RDTSC, 5 NOPs, RDTSC
        data = rdtsc() + nop() * 5 + rdtsc()
        result = analyzer.analyze(data)
        rdtsc_findings = result.findings_by_kind(FindingKind.ANTI_DEBUG_RDTSC)
        assert len(rdtsc_findings) >= 1

    def test_analyze_int3(self):
        analyzer = CodeFlowAnalyzer()
        data = int3() * 5
        result = analyzer.analyze(data)
        int3_findings = result.findings_by_kind(FindingKind.ANTI_DEBUG_INT3)
        assert len(int3_findings) >= 1

    def test_analyze_call_pop_shellcode(self):
        analyzer = CodeFlowAnalyzer()
        # Build CALL +0 (5 bytes: E8 00 00 00 00), then POP eax
        data = b"\xe8\x00\x00\x00\x00" + pop_eax()
        result = analyzer.analyze(data)
        pic_f = result.findings_by_kind(FindingKind.SHELLCODE_CALL_POP)
        assert len(pic_f) >= 1
        assert result.is_shellcode_candidate

    def test_analyze_indirect_jmp(self):
        analyzer = CodeFlowAnalyzer()
        data = jmp_reg_eax()
        result = analyzer.analyze(data)
        ind_f = result.findings_by_kind(FindingKind.SUSPICIOUS_INDIRECT_JMP)
        assert len(ind_f) >= 1

    def test_analyze_x64_mode(self):
        analyzer = CodeFlowAnalyzer()
        data = rdtsc() + rdtsc()
        result = analyzer.analyze(data, x64=True)
        assert result.arch == "x64"

    def test_analyze_pe_section(self):
        analyzer = CodeFlowAnalyzer()
        data = nop() * 10 + rdtsc() + nop() * 2 + rdtsc() + ret()
        result = analyzer.analyze_pe_section(data, virtual_address=0x1000)
        # All instruction offsets should be >= 0x1000
        for ins in result.instructions:
            assert ins.offset >= 0x1000
        rdtsc_f = result.findings_by_kind(FindingKind.ANTI_DEBUG_RDTSC)
        assert len(rdtsc_f) >= 1

    def test_disassemble_without_analysis(self):
        analyzer = CodeFlowAnalyzer()
        data = nop() * 10 + ret()
        insns = analyzer.disassemble(data, max_insns=5)
        assert len(insns) == 5

    def test_coverage(self):
        analyzer = CodeFlowAnalyzer()
        data = nop() * 10 + ret()
        result = analyzer.analyze(data)
        # All bytes are decodable NOPs + RET so coverage should be high
        assert result.coverage > 0.8

    def test_summary_dict(self):
        analyzer = CodeFlowAnalyzer()
        data = nop() * 5 + rdtsc() + nop() * 3 + rdtsc() + ret()
        result = analyzer.analyze(data)
        s = result.summary()
        assert "arch" in s
        assert "findings" in s
        assert "instruction_count" in s
        assert s["total_bytes"] == len(data)

    def test_max_bytes_limit(self):
        analyzer = CodeFlowAnalyzer()
        data = nop() * 100
        result = analyzer.analyze(data, max_bytes=10)
        assert result.total_bytes == 10
        assert len(result.instructions) == 10

    def test_invalid_count(self):
        analyzer = CodeFlowAnalyzer()
        # Inject some unknown opcodes
        data = b"\x06\x07\x06" + nop() * 3
        result = analyzer.analyze(data)
        assert result.invalid_count >= 2  # at least 2 unknowns (0x06, 0x07)

    def test_findings_severity(self):
        analyzer = CodeFlowAnalyzer()
        data = rdtsc() + nop() * 3 + rdtsc()
        result = analyzer.analyze(data)
        for f in result.findings:
            assert f.severity in ("low", "medium", "high")

    def test_not_shellcode_candidate_without_patterns(self):
        analyzer = CodeFlowAnalyzer()
        data = nop() * 20 + ret()
        result = analyzer.analyze(data)
        assert not result.is_shellcode_candidate
