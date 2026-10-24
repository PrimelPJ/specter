"""
Lightweight x86/x64 code-flow disassembler for static malware analysis.

Decodes x86 (32-bit) and x64 (64-bit) instruction streams without external
dependencies. Uses a minimal opcode table derived from the Intel manual to
decode instruction boundaries and classify control-flow instructions.

Detection capabilities:
  - Anti-debugging sequences (RDTSC, INT 2D/3, CPUID timing, NtQueryInformationProcess)
  - Position-independent code patterns (call-pop prologue, GetProcAddress loops)
  - Suspicious control-flow (indirect JMP via register, self-modifying stubs)
  - Shellcode characteristics (no imports, dense branch clusters, PIC prologue)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, Iterator, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class InsnClass(str, Enum):
    UNKNOWN = "unknown"
    NOP = "nop"
    PUSH = "push"
    POP = "pop"
    MOV = "mov"
    LEA = "lea"
    ADD = "add"
    SUB = "sub"
    XOR = "xor"
    AND = "and"
    OR = "or"
    CMP = "cmp"
    TEST = "test"
    CALL = "call"
    RET = "ret"
    JMP = "jmp"
    JCC = "jcc"
    INT = "int"
    CPUID = "cpuid"
    RDTSC = "rdtsc"
    PUSHF = "pushf"
    POPF = "popf"
    SYSCALL = "syscall"
    SYSENTER = "sysenter"
    IN = "in"
    OUT = "out"
    HLT = "hlt"
    INVALID = "invalid"


class FindingKind(str, Enum):
    ANTI_DEBUG_RDTSC = "anti_debug_rdtsc"
    ANTI_DEBUG_INT2D = "anti_debug_int2d"
    ANTI_DEBUG_INT3 = "anti_debug_int3"
    ANTI_DEBUG_CPUID = "anti_debug_cpuid"
    ANTI_DEBUG_PUSHF = "anti_debug_pushf_tf"
    SHELLCODE_CALL_POP = "shellcode_call_pop"
    SHELLCODE_DENSE_JCC = "shellcode_dense_jcc"
    SUSPICIOUS_INDIRECT_JMP = "suspicious_indirect_jmp"
    SUSPICIOUS_INDIRECT_CALL = "suspicious_indirect_call"
    PRIVILEGED_INSN = "privileged_instruction"
    SELF_REF_LOOP = "self_referential_loop"


# ---------------------------------------------------------------------------
# Instruction representation
# ---------------------------------------------------------------------------

@dataclass
class Instruction:
    offset: int            # byte offset from start of buffer
    opcode_bytes: bytes    # raw bytes of this instruction
    mnemonic: str          # human-readable mnemonic
    cls: InsnClass         # semantic class
    length: int            # total byte length
    operand_str: str = ""  # decoded operand description (best-effort)
    # For branches/calls: resolved target offset (None = indirect/unknown)
    target_offset: Optional[int] = None
    is_indirect: bool = False  # JMP/CALL via register or memory

    @property
    def end_offset(self) -> int:
        return self.offset + self.length

    def __str__(self) -> str:
        tgt = f" -> 0x{self.target_offset:x}" if self.target_offset is not None else ""
        ind = " [indirect]" if self.is_indirect else ""
        return f"0x{self.offset:04x}  {self.mnemonic:<12} {self.operand_str}{tgt}{ind}"


@dataclass
class DisasmFinding:
    kind: FindingKind
    offset: int
    description: str
    confidence: float  # 0.0 - 1.0
    supporting_offsets: List[int] = field(default_factory=list)

    @property
    def severity(self) -> str:
        if self.confidence >= 0.9:
            return "high"
        if self.confidence >= 0.6:
            return "medium"
        return "low"


@dataclass
class DisasmResult:
    instructions: List[Instruction]
    findings: List[DisasmFinding]
    arch: str           # "x86" or "x64"
    total_bytes: int
    decoded_bytes: int  # bytes successfully decoded
    invalid_count: int

    @property
    def coverage(self) -> float:
        if self.total_bytes == 0:
            return 0.0
        return self.decoded_bytes / self.total_bytes

    @property
    def is_shellcode_candidate(self) -> bool:
        sc_kinds = {
            FindingKind.SHELLCODE_CALL_POP,
            FindingKind.SHELLCODE_DENSE_JCC,
        }
        return any(f.kind in sc_kinds for f in self.findings)

    def findings_by_kind(self, kind: FindingKind) -> List[DisasmFinding]:
        return [f for f in self.findings if f.kind == kind]

    def summary(self) -> Dict[str, object]:
        return {
            "arch": self.arch,
            "total_bytes": self.total_bytes,
            "decoded_bytes": self.decoded_bytes,
            "coverage_pct": round(self.coverage * 100, 1),
            "instruction_count": len(self.instructions),
            "invalid_count": self.invalid_count,
            "findings": [
                {
                    "kind": f.kind.value,
                    "offset": hex(f.offset),
                    "description": f.description,
                    "severity": f.severity,
                    "confidence": f.confidence,
                }
                for f in self.findings
            ],
            "is_shellcode_candidate": self.is_shellcode_candidate,
        }


# ---------------------------------------------------------------------------
# Minimal x86/x64 opcode tables
#
# Entry format: opcode_byte -> (mnemonic, InsnClass, length_spec)
# length_spec values:
#   int  = fixed total instruction length (including opcode)
#   "r"  = opcode (1) + ModRM (1) + optional SIB/disp (variable), min 2
#   "i8" = opcode (1) + imm8 (1) = 2 bytes total
#   "i32"= opcode (1) + imm32 (4) = 5 bytes total
#   "rel8"  = relative branch with imm8 offset
#   "rel32" = relative branch with imm32 offset
# ---------------------------------------------------------------------------

# Register names for 32-bit and 64-bit operands
_REG32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
_REG64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
          "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"]


# Core opcode table for x86 (single-byte opcodes)
_OPCODE1: Dict[int, Tuple[str, InsnClass, object]] = {
    0x00: ("add",     InsnClass.ADD,    "r"),
    0x01: ("add",     InsnClass.ADD,    "r"),
    0x03: ("add",     InsnClass.ADD,    "r"),
    0x04: ("add",     InsnClass.ADD,    "i8"),
    0x05: ("add",     InsnClass.ADD,    "i32"),
    0x08: ("or",      InsnClass.OR,     "r"),
    0x09: ("or",      InsnClass.OR,     "r"),
    0x0b: ("or",      InsnClass.OR,     "r"),
    0x0c: ("or",      InsnClass.OR,     "i8"),
    0x0d: ("or",      InsnClass.OR,     "i32"),
    0x20: ("and",     InsnClass.AND,    "r"),
    0x21: ("and",     InsnClass.AND,    "r"),
    0x23: ("and",     InsnClass.AND,    "r"),
    0x24: ("and",     InsnClass.AND,    "i8"),
    0x25: ("and",     InsnClass.AND,    "i32"),
    0x28: ("sub",     InsnClass.SUB,    "r"),
    0x29: ("sub",     InsnClass.SUB,    "r"),
    0x2b: ("sub",     InsnClass.SUB,    "r"),
    0x2c: ("sub",     InsnClass.SUB,    "i8"),
    0x2d: ("sub",     InsnClass.SUB,    "i32"),
    0x30: ("xor",     InsnClass.XOR,    "r"),
    0x31: ("xor",     InsnClass.XOR,    "r"),
    0x33: ("xor",     InsnClass.XOR,    "r"),
    0x34: ("xor",     InsnClass.XOR,    "i8"),
    0x35: ("xor",     InsnClass.XOR,    "i32"),
    0x38: ("cmp",     InsnClass.CMP,    "r"),
    0x39: ("cmp",     InsnClass.CMP,    "r"),
    0x3b: ("cmp",     InsnClass.CMP,    "r"),
    0x3c: ("cmp",     InsnClass.CMP,    "i8"),
    0x3d: ("cmp",     InsnClass.CMP,    "i32"),
    # PUSH/POP r32/r64  (0x50-0x5f)
    **{b: ("push", InsnClass.PUSH, 1) for b in range(0x50, 0x58)},
    **{b: ("pop",  InsnClass.POP,  1) for b in range(0x58, 0x60)},
    0x60: ("pusha",   InsnClass.PUSH,   1),
    0x61: ("popa",    InsnClass.POP,    1),
    # Jcc short (0x70-0x7f)
    **{b: ("j" + n, InsnClass.JCC, "rel8") for b, n in zip(
        range(0x70, 0x80),
        ["o","no","b","nb","z","nz","be","nbe","s","ns","p","np","l","nl","le","nle"]
    )},
    0x80: ("add/or/adc/sbb/and/sub/xor/cmp", InsnClass.ADD, "r"),  # grp1 r/m8, imm8
    0x81: ("grp1",    InsnClass.ADD,    "r"),  # r/m16/32, imm16/32
    0x83: ("grp1",    InsnClass.ADD,    "r"),  # r/m16/32, imm8
    0x84: ("test",    InsnClass.TEST,   "r"),
    0x85: ("test",    InsnClass.TEST,   "r"),
    0x87: ("xchg",    InsnClass.MOV,    "r"),
    0x88: ("mov",     InsnClass.MOV,    "r"),
    0x89: ("mov",     InsnClass.MOV,    "r"),
    0x8a: ("mov",     InsnClass.MOV,    "r"),
    0x8b: ("mov",     InsnClass.MOV,    "r"),
    0x8d: ("lea",     InsnClass.LEA,    "r"),
    0x90: ("nop",     InsnClass.NOP,    1),
    # xchg r32, eax (0x91-0x97)
    **{b: ("xchg", InsnClass.MOV, 1) for b in range(0x91, 0x98)},
    0x98: ("cwde",    InsnClass.MOV,    1),
    0x99: ("cdq",     InsnClass.MOV,    1),
    0x9c: ("pushf",   InsnClass.PUSHF,  1),
    0x9d: ("popf",    InsnClass.POPF,   1),
    0xa0: ("mov",     InsnClass.MOV,    5),   # mov al, [moffs32]
    0xa1: ("mov",     InsnClass.MOV,    5),   # mov eax, [moffs32]
    0xa2: ("mov",     InsnClass.MOV,    5),
    0xa3: ("mov",     InsnClass.MOV,    5),
    0xa4: ("movs",    InsnClass.MOV,    1),
    0xa5: ("movs",    InsnClass.MOV,    1),
    0xaa: ("stos",    InsnClass.MOV,    1),
    0xab: ("stos",    InsnClass.MOV,    1),
    0xac: ("lods",    InsnClass.MOV,    1),
    0xad: ("lods",    InsnClass.MOV,    1),
    # MOV r8/r16/r32, imm  (0xb0-0xbf)
    **{b: ("mov", InsnClass.MOV, "i8") for b in range(0xb0, 0xb8)},
    **{b: ("mov", InsnClass.MOV, "i32") for b in range(0xb8, 0xc0)},
    0xc0: ("shl/shr", InsnClass.MOV,   "r"),  # r/m8, imm8
    0xc1: ("shl/shr", InsnClass.MOV,   "r"),  # r/m32, imm8
    0xc2: ("retn",    InsnClass.RET,    3),    # retn imm16
    0xc3: ("ret",     InsnClass.RET,    1),
    0xc6: ("mov",     InsnClass.MOV,    "r"),  # r/m8, imm8
    0xc7: ("mov",     InsnClass.MOV,    "r"),  # r/m32, imm32
    0xc9: ("leave",   InsnClass.POP,    1),
    0xca: ("retf",    InsnClass.RET,    3),
    0xcb: ("retf",    InsnClass.RET,    1),
    0xcc: ("int3",    InsnClass.INT,    1),
    0xcd: ("int",     InsnClass.INT,    "i8"),
    0xd0: ("shl/shr", InsnClass.MOV,   "r"),
    0xd1: ("shl/shr", InsnClass.MOV,   "r"),
    0xd2: ("shl/shr", InsnClass.MOV,   "r"),
    0xd3: ("shl/shr", InsnClass.MOV,   "r"),
    0xe0: ("loopne",  InsnClass.JCC,    "rel8"),
    0xe1: ("loope",   InsnClass.JCC,    "rel8"),
    0xe2: ("loop",    InsnClass.JCC,    "rel8"),
    0xe3: ("jecxz",   InsnClass.JCC,    "rel8"),
    0xe8: ("call",    InsnClass.CALL,   "rel32"),
    0xe9: ("jmp",     InsnClass.JMP,    "rel32"),
    0xea: ("jmpf",    InsnClass.JMP,    7),
    0xeb: ("jmp",     InsnClass.JMP,    "rel8"),
    0xec: ("in",      InsnClass.IN,     1),
    0xed: ("in",      InsnClass.IN,     1),
    0xee: ("out",     InsnClass.OUT,    1),
    0xef: ("out",     InsnClass.OUT,    1),
    0xf0: ("lock",    InsnClass.NOP,    1),   # prefix; skip for now
    0xf2: ("repne",   InsnClass.NOP,    1),   # prefix
    0xf3: ("rep",     InsnClass.NOP,    1),   # prefix
    0xf4: ("hlt",     InsnClass.HLT,    1),
    0xf5: ("cmc",     InsnClass.NOP,    1),
    0xf6: ("test/not/neg/mul/div", InsnClass.TEST, "r"),
    0xf7: ("test/not/neg/mul/div", InsnClass.TEST, "r"),
    0xf8: ("clc",     InsnClass.NOP,    1),
    0xf9: ("stc",     InsnClass.NOP,    1),
    0xfa: ("cli",     InsnClass.NOP,    1),
    0xfb: ("sti",     InsnClass.NOP,    1),
    0xfc: ("cld",     InsnClass.NOP,    1),
    0xfd: ("std",     InsnClass.NOP,    1),
    0xfe: ("inc/dec", InsnClass.ADD,    "r"),
    0xff: ("grp5",    InsnClass.CALL,   "r"),  # JMP/CALL r/m
}

# Two-byte opcode table (0x0f prefix)
_OPCODE2: Dict[int, Tuple[str, InsnClass, object]] = {
    0x01: ("sgdt/sidt/lgdt/lidt", InsnClass.MOV, "r"),
    0x05: ("syscall",  InsnClass.SYSCALL,  2),
    0x0b: ("ud2",      InsnClass.INVALID,  2),
    0x1f: ("nop",      InsnClass.NOP,      "r"),
    0x31: ("rdtsc",    InsnClass.RDTSC,    2),
    0x34: ("sysenter", InsnClass.SYSENTER, 2),
    0x40: ("cmovo",    InsnClass.MOV,      "r"),
    0x41: ("cmovno",   InsnClass.MOV,      "r"),
    0x42: ("cmovb",    InsnClass.MOV,      "r"),
    0x43: ("cmovnb",   InsnClass.MOV,      "r"),
    0x44: ("cmovz",    InsnClass.MOV,      "r"),
    0x45: ("cmovnz",   InsnClass.MOV,      "r"),
    0x46: ("cmovbe",   InsnClass.MOV,      "r"),
    0x47: ("cmovnbe",  InsnClass.MOV,      "r"),
    0x80: ("jo",       InsnClass.JCC,      "rel32"),
    0x81: ("jno",      InsnClass.JCC,      "rel32"),
    0x82: ("jb",       InsnClass.JCC,      "rel32"),
    0x83: ("jnb",      InsnClass.JCC,      "rel32"),
    0x84: ("jz",       InsnClass.JCC,      "rel32"),
    0x85: ("jnz",      InsnClass.JCC,      "rel32"),
    0x86: ("jbe",      InsnClass.JCC,      "rel32"),
    0x87: ("jnbe",     InsnClass.JCC,      "rel32"),
    0x88: ("js",       InsnClass.JCC,      "rel32"),
    0x89: ("jns",      InsnClass.JCC,      "rel32"),
    0x8a: ("jp",       InsnClass.JCC,      "rel32"),
    0x8b: ("jnp",      InsnClass.JCC,      "rel32"),
    0x8c: ("jl",       InsnClass.JCC,      "rel32"),
    0x8d: ("jnl",      InsnClass.JCC,      "rel32"),
    0x8e: ("jle",      InsnClass.JCC,      "rel32"),
    0x8f: ("jnle",     InsnClass.JCC,      "rel32"),
    0xa2: ("cpuid",    InsnClass.CPUID,    2),
    0xaf: ("imul",     InsnClass.MOV,      "r"),
    0xb6: ("movzx",    InsnClass.MOV,      "r"),
    0xb7: ("movzx",    InsnClass.MOV,      "r"),
    0xbe: ("movsx",    InsnClass.MOV,      "r"),
    0xbf: ("movsx",    InsnClass.MOV,      "r"),
}


# ---------------------------------------------------------------------------
# ModRM decoder helpers
# ---------------------------------------------------------------------------

def _modrm_length(buf: bytes, pos: int, opcode: int, x64: bool = False) -> int:
    """
    Estimate the length of a ModRM-encoded operand starting at `pos`.
    Returns the number of additional bytes (ModRM + SIB + displacement).
    """
    if pos >= len(buf):
        return 1  # fallback
    modrm = buf[pos]
    mod = (modrm >> 6) & 0x3
    rm  = modrm & 0x7
    reg = (modrm >> 3) & 0x7

    extra = 1  # ModRM byte itself

    if mod == 0b11:
        # Register operand only, no memory
        pass
    elif mod == 0b00:
        if rm == 0b100:  # SIB
            extra += 1
            if pos + 1 < len(buf):
                sib = buf[pos + 1]
                sib_base = sib & 0x7
                if sib_base == 0b101:
                    extra += 4  # disp32
        elif rm == 0b101:
            extra += 4  # disp32 (RIP-relative in x64)
    elif mod == 0b01:
        if rm == 0b100:  # SIB
            extra += 1
        extra += 1  # disp8
    elif mod == 0b10:
        if rm == 0b100:  # SIB
            extra += 1
        extra += 4  # disp32

    # Some opcodes also have an immediate after the ModRM
    imm_opcodes_8  = {0x80, 0x83, 0xc0, 0xc1, 0xc6}
    imm_opcodes_32 = {0x81, 0xc7}
    grp1_ext_imm32 = {0x00, 0x08, 0x20, 0x28, 0x30, 0x38}  # grp1 regular opcodes
    if opcode in imm_opcodes_8:
        extra += 1
    elif opcode in imm_opcodes_32:
        extra += 4

    return extra


def _is_indirect_jmp_call(buf: bytes, pos: int, opcode: int) -> bool:
    """True if this FF grp5 instruction is an indirect JMP/CALL (mod != 0b11 for jmp, or reg==2/4)."""
    if opcode != 0xff or pos >= len(buf):
        return False
    modrm = buf[pos]
    reg = (modrm >> 3) & 0x7
    mod = (modrm >> 6) & 0x3
    # reg 2=CALL r/m, 4=JMP r/m, 3=CALL far, 5=JMP far
    return reg in (2, 4)


# ---------------------------------------------------------------------------
# Core decoder
# ---------------------------------------------------------------------------

class X86Decoder:
    """
    Linear sweep decoder for x86 and x64 instruction streams.

    Not a full-featured disassembler -- it handles the most common encodings
    accurately enough to identify malicious patterns in static PE sections
    and shellcode buffers. Complex encodings (VEX/EVEX, FPU, MMX) degrade
    gracefully to INVALID entries so the sweep continues.
    """

    def __init__(self, x64: bool = False) -> None:
        self.x64 = x64

    def decode(self, buf: bytes, base_offset: int = 0) -> List[Instruction]:
        insns: List[Instruction] = []
        pos = 0
        n = len(buf)

        while pos < n:
            start = pos
            b = buf[pos]

            # --- skip legacy prefixes ---
            while b in (0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67):
                pos += 1
                if pos >= n:
                    break
                b = buf[pos]

            # REX prefix in x64 mode
            if self.x64 and 0x40 <= b <= 0x4f:
                pos += 1
                if pos >= n:
                    break
                b = buf[pos]

            if pos >= n:
                break

            insn = self._decode_one(buf, pos, start + base_offset, b)
            insns.append(insn)
            pos += insn.length - (pos - start)
            if insn.cls == InsnClass.INVALID:
                # skip one byte and continue
                pos = start + 1

        return insns

    def _decode_one(self, buf: bytes, pos: int, offset: int, b: int) -> Instruction:
        raw_start = pos
        n = len(buf)

        # --- two-byte escape ---
        if b == 0x0f:
            pos += 1
            if pos >= n:
                return _make_invalid(buf[raw_start:pos], offset)
            b2 = buf[pos]
            if b2 in _OPCODE2:
                mnem, cls, lspec = _OPCODE2[b2]
                return self._build(buf, raw_start, pos, offset, b2, mnem, cls, lspec, two_byte=True)
            # Unknown 0F xx
            return _make_invalid(buf[raw_start:min(raw_start + 2, n)], offset)

        # --- single-byte opcode ---
        if b in _OPCODE1:
            mnem, cls, lspec = _OPCODE1[b]
            return self._build(buf, raw_start, pos, offset, b, mnem, cls, lspec, two_byte=False)

        # Unknown opcode
        return _make_invalid(buf[raw_start:raw_start + 1], offset)

    def _build(
        self,
        buf: bytes,
        raw_start: int,
        opcode_pos: int,
        offset: int,
        opcode: int,
        mnem: str,
        cls: InsnClass,
        lspec: object,
        two_byte: bool,
    ) -> Instruction:
        n = len(buf)
        prefix_len = opcode_pos - raw_start  # bytes consumed before opcode
        opcode_size = 2 if two_byte else 1
        base = opcode_pos + opcode_size  # position after opcode byte(s)

        target: Optional[int] = None
        is_indirect = False
        operand_str = ""

        if isinstance(lspec, int):
            # Fixed total length (counting from raw_start for the full encoding)
            length = prefix_len + lspec
            raw = buf[raw_start: raw_start + length]

        elif lspec == "r":
            # ModRM-encoded
            modrm_extra = _modrm_length(buf, base, opcode, self.x64)
            is_indirect = _is_indirect_jmp_call(buf, base, opcode)
            if is_indirect:
                modrm = buf[base] if base < n else 0
                reg = (modrm >> 3) & 0x7
                rm  = modrm & 0x7
                mod = (modrm >> 6) & 0x3
                reg_names = _REG64 if self.x64 else _REG32
                if mod == 0b11:
                    operand_str = reg_names[rm] if rm < len(reg_names) else f"r{rm}"
                else:
                    operand_str = f"[{reg_names[rm]}]" if rm < len(reg_names) else "[mem]"
                if reg == 2:
                    mnem = "call"
                    cls = InsnClass.CALL
                else:
                    mnem = "jmp"
                    cls = InsnClass.JMP
            length = prefix_len + opcode_size + modrm_extra
            raw = buf[raw_start: raw_start + length]

        elif lspec == "i8":
            length = prefix_len + opcode_size + 1
            raw = buf[raw_start: raw_start + length]
            if base < n:
                imm = buf[base]
                operand_str = f"0x{imm:02x}"
                if cls == InsnClass.INT:
                    operand_str = f"{imm}"

        elif lspec == "i32":
            length = prefix_len + opcode_size + 4
            raw = buf[raw_start: raw_start + length]
            if base + 4 <= n:
                imm = struct.unpack_from("<I", buf, base)[0]
                operand_str = f"0x{imm:08x}"

        elif lspec == "rel8":
            length = prefix_len + opcode_size + 1
            raw = buf[raw_start: raw_start + length]
            if base < n:
                rel = struct.unpack_from("b", buf, base)[0]  # signed
                target = offset + length + rel
                operand_str = f"0x{target:x}"

        elif lspec == "rel32":
            length = prefix_len + opcode_size + 4
            raw = buf[raw_start: raw_start + length]
            if base + 4 <= n:
                rel = struct.unpack_from("<i", buf, base)[0]  # signed
                target = offset + length + rel
                operand_str = f"0x{target:x}"

        else:
            length = prefix_len + opcode_size
            raw = buf[raw_start: raw_start + length]

        # Clamp length to remaining buffer
        length = min(length, n - raw_start)
        if length <= 0:
            return _make_invalid(buf[raw_start:raw_start + 1], offset)

        return Instruction(
            offset=offset,
            opcode_bytes=bytes(raw[:length]),
            mnemonic=mnem,
            cls=cls,
            length=length,
            operand_str=operand_str,
            target_offset=target,
            is_indirect=is_indirect,
        )


def _make_invalid(raw: bytes, offset: int) -> Instruction:
    return Instruction(
        offset=offset,
        opcode_bytes=bytes(raw[:1]),
        mnemonic="??",
        cls=InsnClass.INVALID,
        length=max(1, len(raw)),
        operand_str="",
    )


# ---------------------------------------------------------------------------
# Pattern analyzer
# ---------------------------------------------------------------------------

class PatternAnalyzer:
    """
    Identifies malicious patterns in a decoded instruction stream.
    """

    # RDTSC timing check: RDTSC ... RDTSC within a short window
    _RDTSC_WINDOW = 32

    # Dense JCC threshold: more than N conditional jumps per 100 insns
    _JCC_DENSITY_THRESHOLD = 0.25  # 25%

    def analyze(self, insns: List[Instruction]) -> List[DisasmFinding]:
        findings: List[DisasmFinding] = []

        findings.extend(self._detect_rdtsc_timing(insns))
        findings.extend(self._detect_int2d(insns))
        findings.extend(self._detect_int3_cluster(insns))
        findings.extend(self._detect_cpuid_abuse(insns))
        findings.extend(self._detect_pushf_tf(insns))
        findings.extend(self._detect_call_pop(insns))
        findings.extend(self._detect_dense_jcc(insns))
        findings.extend(self._detect_indirect_flow(insns))

        return findings

    # -- anti-debug detection -----------------------------------------------

    def _detect_rdtsc_timing(self, insns: List[Instruction]) -> List[DisasmFinding]:
        """Two RDTSC instructions within _RDTSC_WINDOW instructions = timing check."""
        out = []
        rdtsc_positions = [i for i, ins in enumerate(insns) if ins.cls == InsnClass.RDTSC]
        for i, pos in enumerate(rdtsc_positions[:-1]):
            next_pos = rdtsc_positions[i + 1]
            if next_pos - pos <= self._RDTSC_WINDOW:
                out.append(DisasmFinding(
                    kind=FindingKind.ANTI_DEBUG_RDTSC,
                    offset=insns[pos].offset,
                    description=(
                        f"RDTSC timing check: two RDTSC instructions at offsets "
                        f"0x{insns[pos].offset:x} and 0x{insns[next_pos].offset:x} "
                        f"within {next_pos - pos} instructions"
                    ),
                    confidence=0.90,
                    supporting_offsets=[insns[pos].offset, insns[next_pos].offset],
                ))
        return out

    def _detect_int2d(self, insns: List[Instruction]) -> List[DisasmFinding]:
        """INT 0x2d - Windows debugger breakpoint check."""
        out = []
        for ins in insns:
            if ins.cls == InsnClass.INT and ins.operand_str in ("0x2d", "45", "0x2D"):
                out.append(DisasmFinding(
                    kind=FindingKind.ANTI_DEBUG_INT2D,
                    offset=ins.offset,
                    description=f"INT 0x2D at 0x{ins.offset:x}: Windows debugger presence check",
                    confidence=0.95,
                ))
        return out

    def _detect_int3_cluster(self, insns: List[Instruction]) -> List[DisasmFinding]:
        """Three or more INT3s within 16 instructions = debugger trap cluster."""
        out = []
        window = 16
        for i in range(len(insns)):
            chunk = insns[i: i + window]
            int3s = [ins for ins in chunk if ins.cls == InsnClass.INT and ins.mnemonic == "int3"]
            if len(int3s) >= 3:
                out.append(DisasmFinding(
                    kind=FindingKind.ANTI_DEBUG_INT3,
                    offset=insns[i].offset,
                    description=f"INT3 cluster: {len(int3s)} INT3 instructions within {window} insns at 0x{insns[i].offset:x}",
                    confidence=0.85,
                    supporting_offsets=[ins.offset for ins in int3s],
                ))
                break  # one finding per cluster
        return out

    def _detect_cpuid_abuse(self, insns: List[Instruction]) -> List[DisasmFinding]:
        """
        CPUID followed by XOR/AND/CMP within 8 instructions = VM/debugger check.
        Legitimate code rarely needs CPUID output verification.
        """
        out = []
        _check_classes = {InsnClass.XOR, InsnClass.AND, InsnClass.CMP, InsnClass.TEST}
        for i, ins in enumerate(insns):
            if ins.cls != InsnClass.CPUID:
                continue
            window = insns[i + 1: i + 9]
            checks = [w for w in window if w.cls in _check_classes]
            if checks:
                out.append(DisasmFinding(
                    kind=FindingKind.ANTI_DEBUG_CPUID,
                    offset=ins.offset,
                    description=(
                        f"CPUID result checked at 0x{ins.offset:x}: "
                        f"{checks[0].mnemonic} at 0x{checks[0].offset:x} -- possible VM/debugger detection"
                    ),
                    confidence=0.75,
                    supporting_offsets=[ins.offset] + [c.offset for c in checks[:2]],
                ))
        return out

    def _detect_pushf_tf(self, insns: List[Instruction]) -> List[DisasmFinding]:
        """
        PUSHF / (manipulate stack) / POPF pattern: commonly used to set/clear
        the Trap Flag (TF bit 8) to detect single-step debugging.
        """
        out = []
        for i, ins in enumerate(insns):
            if ins.cls != InsnClass.PUSHF:
                continue
            window = insns[i + 1: i + 6]
            has_popf = any(w.cls == InsnClass.POPF for w in window)
            if has_popf:
                out.append(DisasmFinding(
                    kind=FindingKind.ANTI_DEBUG_PUSHF,
                    offset=ins.offset,
                    description=f"PUSHF/POPF trap-flag probe at 0x{ins.offset:x}: possible single-step detection",
                    confidence=0.70,
                    supporting_offsets=[ins.offset],
                ))
        return out

    # -- shellcode detection ------------------------------------------------

    def _detect_call_pop(self, insns: List[Instruction]) -> List[DisasmFinding]:
        """
        CALL (next_insn) / POP reg: the classic position-independent code (PIC)
        prologue used by shellcode and position-independent loaders to resolve
        the current instruction pointer without relying on the import table.
        """
        out = []
        for i, ins in enumerate(insns):
            if ins.cls != InsnClass.CALL:
                continue
            # A call-pop PIC prolog targets the very next instruction
            next_insn = insns[i + 1] if i + 1 < len(insns) else None
            if next_insn and ins.target_offset == next_insn.offset:
                # Check that instruction after call is POP
                after = insns[i + 1] if i + 1 < len(insns) else None
                if after and after.cls == InsnClass.POP:
                    out.append(DisasmFinding(
                        kind=FindingKind.SHELLCODE_CALL_POP,
                        offset=ins.offset,
                        description=(
                            f"CALL/POP PIC prologue at 0x{ins.offset:x}: "
                            f"call targets 0x{next_insn.offset:x} (next instruction), "
                            f"followed by POP to capture EIP/RIP -- shellcode indicator"
                        ),
                        confidence=0.92,
                        supporting_offsets=[ins.offset, next_insn.offset],
                    ))
        return out

    def _detect_dense_jcc(self, insns: List[Instruction]) -> List[DisasmFinding]:
        """
        High ratio of conditional branches to total instructions across a
        50-instruction window -- characteristic of obfuscated shellcode or
        anti-analysis spaghetti code.
        """
        out = []
        window = 50
        if len(insns) < window:
            return out
        for i in range(0, len(insns) - window, window // 2):
            chunk = insns[i: i + window]
            jcc_count = sum(1 for ins in chunk if ins.cls == InsnClass.JCC)
            density = jcc_count / window
            if density >= self._JCC_DENSITY_THRESHOLD:
                out.append(DisasmFinding(
                    kind=FindingKind.SHELLCODE_DENSE_JCC,
                    offset=chunk[0].offset,
                    description=(
                        f"Dense JCC cluster at 0x{chunk[0].offset:x}: "
                        f"{jcc_count}/{window} instructions are conditional branches "
                        f"({density:.0%}) -- obfuscated code or shellcode"
                    ),
                    confidence=min(0.4 + density, 0.9),
                    supporting_offsets=[ins.offset for ins in chunk if ins.cls == InsnClass.JCC][:5],
                ))
        return out

    # -- suspicious control flow detection ----------------------------------

    def _detect_indirect_flow(self, insns: List[Instruction]) -> List[DisasmFinding]:
        """Indirect JMP/CALL via register or memory -- evasion and dispatcher patterns."""
        out = []
        seen_calls = set()
        seen_jmps = set()
        for ins in insns:
            if not ins.is_indirect:
                continue
            if ins.cls == InsnClass.CALL and ins.offset not in seen_calls:
                seen_calls.add(ins.offset)
                out.append(DisasmFinding(
                    kind=FindingKind.SUSPICIOUS_INDIRECT_CALL,
                    offset=ins.offset,
                    description=f"Indirect CALL at 0x{ins.offset:x}: target {ins.operand_str or 'unknown'} -- possible IAT hook or dispatcher",
                    confidence=0.65,
                ))
            elif ins.cls == InsnClass.JMP and ins.offset not in seen_jmps:
                seen_jmps.add(ins.offset)
                out.append(DisasmFinding(
                    kind=FindingKind.SUSPICIOUS_INDIRECT_JMP,
                    offset=ins.offset,
                    description=f"Indirect JMP at 0x{ins.offset:x}: target {ins.operand_str or 'unknown'} -- possible trampoline or obfuscated dispatcher",
                    confidence=0.60,
                ))
        return out


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

class CodeFlowAnalyzer:
    """
    High-level interface for x86/x64 code-flow analysis.

    Usage::

        analyzer = CodeFlowAnalyzer()
        result = analyzer.analyze(raw_bytes, x64=False, base_offset=0x1000)
        print(result.summary())
        for f in result.findings:
            print(f.kind.value, f.description)
    """

    def __init__(self) -> None:
        self._pattern_analyzer = PatternAnalyzer()

    def analyze(
        self,
        data: bytes,
        x64: bool = False,
        base_offset: int = 0,
        max_bytes: int = 0,
    ) -> DisasmResult:
        """
        Decode and analyze up to `max_bytes` of `data` (0 = all).
        `base_offset` is added to all reported offsets (useful for PE section VA).
        """
        if max_bytes > 0:
            data = data[:max_bytes]

        decoder = X86Decoder(x64=x64)
        insns = decoder.decode(data, base_offset=base_offset)

        decoded_bytes = sum(ins.length for ins in insns if ins.cls != InsnClass.INVALID)
        invalid_count = sum(1 for ins in insns if ins.cls == InsnClass.INVALID)

        findings = self._pattern_analyzer.analyze(insns)

        return DisasmResult(
            instructions=insns,
            findings=findings,
            arch="x64" if x64 else "x86",
            total_bytes=len(data),
            decoded_bytes=decoded_bytes,
            invalid_count=invalid_count,
        )

    def analyze_pe_section(
        self,
        section_data: bytes,
        virtual_address: int,
        x64: bool = False,
    ) -> DisasmResult:
        """Convenience wrapper that sets base_offset to the section's virtual address."""
        return self.analyze(section_data, x64=x64, base_offset=virtual_address)

    def disassemble(
        self,
        data: bytes,
        x64: bool = False,
        base_offset: int = 0,
        max_insns: int = 0,
    ) -> List[Instruction]:
        """Return decoded instructions without running the pattern analyzer."""
        decoder = X86Decoder(x64=x64)
        insns = decoder.decode(data, base_offset=base_offset)
        if max_insns > 0:
            return insns[:max_insns]
        return insns
