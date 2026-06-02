"""
Handler Semantics Analysis
===========================

Given:

* An :class:`~..trace_ingestion.ExecutionTrace`
* A list of :class:`~..vm_discovery.handler_boundaries.HandlerBoundary`
  records

…this module analyses the native instructions **inside** each handler
to determine its *semantic operation* — what the handler does from the
virtual machine's perspective (e.g. "add two stack operands", "load
from virtual memory", "conditional branch").

The result is a :class:`SemanticOpcodeTable` — the central artefact
needed for pseudocode emission.

Usage::

    from dragonslayer.analysis.handler_semantics import (
        analyse_handler_semantics,
        SemanticOpcodeTable,
    )

    table = analyse_handler_semantics(trace, boundaries)
    for entry in table.entries:
        print(f"handler 0x{entry.handler_address:X}  →  {entry.operation}")
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, TypedDict

from dragonslayer.analysis.trace_ingestion import (
    ExecutionTrace,
    TraceInstruction,
)
from dragonslayer.analysis.vm_discovery.handler_boundaries import (
    HandlerBoundary,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Semantic categories
# ---------------------------------------------------------------------------

class VMOperation:
    """Known VM semantic operation names (string constants)."""

    ADD = "vm_add"
    SUB = "vm_sub"
    MUL = "vm_mul"
    DIV = "vm_div"
    AND = "vm_and"
    OR = "vm_or"
    XOR = "vm_xor"
    NOT = "vm_not"
    NEG = "vm_neg"
    SHL = "vm_shl"
    SHR = "vm_shr"
    ROL = "vm_rol"
    ROR = "vm_ror"
    LOAD = "vm_load"
    STORE = "vm_store"
    PUSH = "vm_push"
    POP = "vm_pop"
    CMP = "vm_cmp"
    TEST = "vm_test"
    JMP = "vm_jmp"
    JCC = "vm_jcc"
    CALL = "vm_call"
    RET = "vm_ret"
    NOP = "vm_nop"
    UNKNOWN = "vm_unknown"

    # --- SIMD / vector operations ---
    SIMD_ADD = "vm_simd_add"
    SIMD_SUB = "vm_simd_sub"
    SIMD_MUL = "vm_simd_mul"
    SIMD_XOR = "vm_simd_xor"
    SIMD_AND = "vm_simd_and"
    SIMD_OR = "vm_simd_or"
    SIMD_SHUFFLE = "vm_simd_shuffle"
    SIMD_AES = "vm_simd_aes"
    SIMD_LOAD = "vm_simd_load"
    SIMD_STORE = "vm_simd_store"
    SIMD_CMP = "vm_simd_cmp"
    SIMD_SHIFT = "vm_simd_shift"
    SIMD_UNKNOWN = "vm_simd_unknown"


# Map native x86 mnemonics → VM semantic operations.
_MNEMONIC_MAP: dict[str, str] = {
    "add": VMOperation.ADD,
    "adc": VMOperation.ADD,
    "sub": VMOperation.SUB,
    "sbb": VMOperation.SUB,
    "imul": VMOperation.MUL,
    "mul": VMOperation.MUL,
    "idiv": VMOperation.DIV,
    "div": VMOperation.DIV,
    "and": VMOperation.AND,
    "or": VMOperation.OR,
    "xor": VMOperation.XOR,
    "not": VMOperation.NOT,
    "neg": VMOperation.NEG,
    "shl": VMOperation.SHL,
    "sal": VMOperation.SHL,
    "shr": VMOperation.SHR,
    "sar": VMOperation.SHR,
    "rol": VMOperation.ROL,
    "ror": VMOperation.ROR,
    "push": VMOperation.PUSH,
    "pop": VMOperation.POP,
    "cmp": VMOperation.CMP,
    "test": VMOperation.TEST,
    "call": VMOperation.CALL,
    "ret": VMOperation.RET,
    "retn": VMOperation.RET,
    "jmp": VMOperation.JMP,
    "nop": VMOperation.NOP,
    # --- Data-movement instructions (context-dependent resolution) ------
    # mov is the most common instruction in VM handlers; its VM
    # operation depends on whether the destination or source is a
    # memory operand.  _mnemonic_to_vm_op resolves this dynamically.
    "mov": VMOperation.LOAD,      # default; overridden per-instruction
    "movzx": VMOperation.LOAD,
    "movsx": VMOperation.LOAD,
    "movsxd": VMOperation.LOAD,
    "lea": VMOperation.LOAD,
    # Conditional moves
    "cmove": VMOperation.LOAD,  "cmovne": VMOperation.LOAD,
    "cmova": VMOperation.LOAD,  "cmovae": VMOperation.LOAD,
    "cmovb": VMOperation.LOAD,  "cmovbe": VMOperation.LOAD,
    "cmovg": VMOperation.LOAD,  "cmovge": VMOperation.LOAD,
    "cmovl": VMOperation.LOAD,  "cmovle": VMOperation.LOAD,
    # Byte-set instructions
    "sete": VMOperation.CMP,  "setne": VMOperation.CMP,
    "seta": VMOperation.CMP,  "setae": VMOperation.CMP,
    "setb": VMOperation.CMP,  "setbe": VMOperation.CMP,
    "setg": VMOperation.CMP,  "setge": VMOperation.CMP,
    "setl": VMOperation.CMP,  "setle": VMOperation.CMP,
    # Exchange (common in handlers) — map to LOAD as it's data movement
    "xchg": VMOperation.LOAD,
    "bswap": VMOperation.LOAD,
    # --- SSE / AVX SIMD instructions ---
    # Packed integer arithmetic
    "paddb": VMOperation.SIMD_ADD,
    "paddw": VMOperation.SIMD_ADD,
    "paddd": VMOperation.SIMD_ADD,
    "paddq": VMOperation.SIMD_ADD,
    "paddsb": VMOperation.SIMD_ADD,
    "paddsw": VMOperation.SIMD_ADD,
    "paddusb": VMOperation.SIMD_ADD,
    "paddusw": VMOperation.SIMD_ADD,
    "psubb": VMOperation.SIMD_SUB,
    "psubw": VMOperation.SIMD_SUB,
    "psubd": VMOperation.SIMD_SUB,
    "psubq": VMOperation.SIMD_SUB,
    "psubsb": VMOperation.SIMD_SUB,
    "psubsw": VMOperation.SIMD_SUB,
    "psubusb": VMOperation.SIMD_SUB,
    "psubusw": VMOperation.SIMD_SUB,
    "pmullw": VMOperation.SIMD_MUL,
    "pmulld": VMOperation.SIMD_MUL,
    "pmulhw": VMOperation.SIMD_MUL,
    "pmuludq": VMOperation.SIMD_MUL,
    # Packed floating-point arithmetic
    "addps": VMOperation.SIMD_ADD,
    "addpd": VMOperation.SIMD_ADD,
    "addss": VMOperation.SIMD_ADD,
    "addsd": VMOperation.SIMD_ADD,
    "subps": VMOperation.SIMD_SUB,
    "subpd": VMOperation.SIMD_SUB,
    "subss": VMOperation.SIMD_SUB,
    "subsd": VMOperation.SIMD_SUB,
    "mulps": VMOperation.SIMD_MUL,
    "mulpd": VMOperation.SIMD_MUL,
    "mulss": VMOperation.SIMD_MUL,
    "mulsd": VMOperation.SIMD_MUL,
    # Packed bitwise
    "pxor": VMOperation.SIMD_XOR,
    "pand": VMOperation.SIMD_AND,
    "pandn": VMOperation.SIMD_AND,
    "por": VMOperation.SIMD_OR,
    "xorps": VMOperation.SIMD_XOR,
    "xorpd": VMOperation.SIMD_XOR,
    "andps": VMOperation.SIMD_AND,
    "andpd": VMOperation.SIMD_AND,
    "andnps": VMOperation.SIMD_AND,
    "andnpd": VMOperation.SIMD_AND,
    "orps": VMOperation.SIMD_OR,
    "orpd": VMOperation.SIMD_OR,
    # Shuffle / permute
    "pshufb": VMOperation.SIMD_SHUFFLE,
    "pshufd": VMOperation.SIMD_SHUFFLE,
    "pshuflw": VMOperation.SIMD_SHUFFLE,
    "pshufhw": VMOperation.SIMD_SHUFFLE,
    "shufps": VMOperation.SIMD_SHUFFLE,
    "shufpd": VMOperation.SIMD_SHUFFLE,
    "palignr": VMOperation.SIMD_SHUFFLE,
    "punpcklbw": VMOperation.SIMD_SHUFFLE,
    "punpckhbw": VMOperation.SIMD_SHUFFLE,
    "punpckldq": VMOperation.SIMD_SHUFFLE,
    "punpckhdq": VMOperation.SIMD_SHUFFLE,
    "punpcklqdq": VMOperation.SIMD_SHUFFLE,
    "punpckhqdq": VMOperation.SIMD_SHUFFLE,
    "pblendvb": VMOperation.SIMD_SHUFFLE,
    "blendps": VMOperation.SIMD_SHUFFLE,
    "blendpd": VMOperation.SIMD_SHUFFLE,
    # AES-NI (common in VM bytecode decryption)
    "aesenc": VMOperation.SIMD_AES,
    "aesenclast": VMOperation.SIMD_AES,
    "aesdec": VMOperation.SIMD_AES,
    "aesdeclast": VMOperation.SIMD_AES,
    "aesimc": VMOperation.SIMD_AES,
    "aeskeygenassist": VMOperation.SIMD_AES,
    # SIMD data movement
    "movdqa": VMOperation.SIMD_LOAD,
    "movdqu": VMOperation.SIMD_LOAD,
    "movaps": VMOperation.SIMD_LOAD,
    "movups": VMOperation.SIMD_LOAD,
    "movapd": VMOperation.SIMD_LOAD,
    "movupd": VMOperation.SIMD_LOAD,
    "movd": VMOperation.SIMD_LOAD,
    "movq": VMOperation.SIMD_LOAD,
    "movss": VMOperation.SIMD_LOAD,
    "movsd": VMOperation.SIMD_LOAD,
    "movlps": VMOperation.SIMD_LOAD,
    "movhps": VMOperation.SIMD_LOAD,
    "movlpd": VMOperation.SIMD_LOAD,
    "movhpd": VMOperation.SIMD_LOAD,
    "lddqu": VMOperation.SIMD_LOAD,
    # SIMD comparison
    "pcmpeqb": VMOperation.SIMD_CMP,
    "pcmpeqw": VMOperation.SIMD_CMP,
    "pcmpeqd": VMOperation.SIMD_CMP,
    "pcmpeqq": VMOperation.SIMD_CMP,
    "pcmpgtb": VMOperation.SIMD_CMP,
    "pcmpgtw": VMOperation.SIMD_CMP,
    "pcmpgtd": VMOperation.SIMD_CMP,
    "pcmpgtq": VMOperation.SIMD_CMP,
    "cmpps": VMOperation.SIMD_CMP,
    "cmppd": VMOperation.SIMD_CMP,
    # SIMD shift
    "psllw": VMOperation.SIMD_SHIFT,
    "pslld": VMOperation.SIMD_SHIFT,
    "psllq": VMOperation.SIMD_SHIFT,
    "pslldq": VMOperation.SIMD_SHIFT,
    "psrlw": VMOperation.SIMD_SHIFT,
    "psrld": VMOperation.SIMD_SHIFT,
    "psrlq": VMOperation.SIMD_SHIFT,
    "psrldq": VMOperation.SIMD_SHIFT,
    "psraw": VMOperation.SIMD_SHIFT,
    "psrad": VMOperation.SIMD_SHIFT,
    # --- AVX VEX-encoded equivalents (v-prefix) ---
    "vpaddb": VMOperation.SIMD_ADD,
    "vpaddw": VMOperation.SIMD_ADD,
    "vpaddd": VMOperation.SIMD_ADD,
    "vpaddq": VMOperation.SIMD_ADD,
    "vpsubb": VMOperation.SIMD_SUB,
    "vpsubw": VMOperation.SIMD_SUB,
    "vpsubd": VMOperation.SIMD_SUB,
    "vpsubq": VMOperation.SIMD_SUB,
    "vpmullw": VMOperation.SIMD_MUL,
    "vpmulld": VMOperation.SIMD_MUL,
    "vpxor": VMOperation.SIMD_XOR,
    "vpxord": VMOperation.SIMD_XOR,
    "vpxorq": VMOperation.SIMD_XOR,
    "vpand": VMOperation.SIMD_AND,
    "vpandn": VMOperation.SIMD_AND,
    "vpor": VMOperation.SIMD_OR,
    "vxorps": VMOperation.SIMD_XOR,
    "vxorpd": VMOperation.SIMD_XOR,
    "vandps": VMOperation.SIMD_AND,
    "vandpd": VMOperation.SIMD_AND,
    "vandnps": VMOperation.SIMD_AND,
    "vandnpd": VMOperation.SIMD_AND,
    "vorps": VMOperation.SIMD_OR,
    "vorpd": VMOperation.SIMD_OR,
    "vpshufb": VMOperation.SIMD_SHUFFLE,
    "vpshufd": VMOperation.SIMD_SHUFFLE,
    "vshufps": VMOperation.SIMD_SHUFFLE,
    "vshufpd": VMOperation.SIMD_SHUFFLE,
    "vperm2f128": VMOperation.SIMD_SHUFFLE,
    "vperm2i128": VMOperation.SIMD_SHUFFLE,
    "vpermd": VMOperation.SIMD_SHUFFLE,
    "vpermq": VMOperation.SIMD_SHUFFLE,
    "vaesenc": VMOperation.SIMD_AES,
    "vaesenclast": VMOperation.SIMD_AES,
    "vaesdec": VMOperation.SIMD_AES,
    "vaesdeclast": VMOperation.SIMD_AES,
    "vmovdqa": VMOperation.SIMD_LOAD,
    "vmovdqu": VMOperation.SIMD_LOAD,
    "vmovaps": VMOperation.SIMD_LOAD,
    "vmovups": VMOperation.SIMD_LOAD,
    "vmovapd": VMOperation.SIMD_LOAD,
    "vmovupd": VMOperation.SIMD_LOAD,
    "vmovd": VMOperation.SIMD_LOAD,
    "vmovq": VMOperation.SIMD_LOAD,
    "vaddps": VMOperation.SIMD_ADD,
    "vaddpd": VMOperation.SIMD_ADD,
    "vaddss": VMOperation.SIMD_ADD,
    "vaddsd": VMOperation.SIMD_ADD,
    "vsubps": VMOperation.SIMD_SUB,
    "vsubpd": VMOperation.SIMD_SUB,
    "vmulps": VMOperation.SIMD_MUL,
    "vmulpd": VMOperation.SIMD_MUL,
    "vpcmpeqb": VMOperation.SIMD_CMP,
    "vpcmpeqd": VMOperation.SIMD_CMP,
    "vpcmpgtb": VMOperation.SIMD_CMP,
    "vpcmpgtd": VMOperation.SIMD_CMP,
    "vpsllw": VMOperation.SIMD_SHIFT,
    "vpslld": VMOperation.SIMD_SHIFT,
    "vpsllq": VMOperation.SIMD_SHIFT,
    "vpsrlw": VMOperation.SIMD_SHIFT,
    "vpsrld": VMOperation.SIMD_SHIFT,
    "vpsrlq": VMOperation.SIMD_SHIFT,
}

# Instructions that are typically VM infrastructure / junk code.
# Used by junk-code filter to down-weight noise instructions.
_JUNK_MNEMONICS: set[str] = {
    "nop", "int3", "ud2", "hlt",
    # Opaque predicate building blocks
    "pushf", "pushfd", "pushfq", "popf", "popfd", "popfq",
    "clc", "stc", "cmc", "cld", "std",
    # Often used as NOPs or alignment
    "xchg",  # when source == dest
    "fnop", "fwait", "wait",
}

# Conditional jumps all map to JCC.
_JCC_PREFIXES = {"je", "jne", "jz", "jnz", "ja", "jb", "jg", "jl",
                 "jae", "jbe", "jge", "jle", "jo", "jno", "js", "jns",
                 "jp", "jnp", "jecxz", "jrcxz", "loop", "loope", "loopne"}


# ---------------------------------------------------------------------------
# Data-classes
# ---------------------------------------------------------------------------


class HandlerSemanticDict(TypedDict):
    """Shape returned by :meth:`HandlerSemantic.to_dict`."""
    handler_address: str
    operation: str
    confidence: float
    operand_count: int
    operand_width: int
    reads_memory: bool
    writes_memory: bool
    modifies_flags: bool
    detail: str


class OpcodeTableEntryDict(TypedDict):
    """Shape returned by :meth:`OpcodeTableEntry.to_dict`."""
    opcode: str
    handler_address: str
    operation: str
    confidence: float
    vip_delta: int


class SemanticOpcodeTableDict(TypedDict):
    """Shape returned by :meth:`SemanticOpcodeTable.to_dict`."""
    handler_count: int
    unique_operations: int
    operations_summary: dict[str, int]
    entries: list[OpcodeTableEntryDict]


@dataclass
class HandlerSemantic:
    """Semantic analysis result for one handler.

    Attributes:
        handler_address: Virtual address of the handler entry point.
        operation: Detected :class:`VMOperation` string constant.
        confidence: Classification confidence in ``[0.0, 1.0]``.
        operand_count: Number of operands the handler consumes.
        operand_width: Operand width in bytes (4 = dword, 8 = qword).
        reads_memory: Whether the handler reads from memory.
        writes_memory: Whether the handler writes to memory.
        modifies_flags: Whether the handler modifies CPU flags.
        mnemonic_histogram: Frequency of native mnemonics in the handler.
        detail: Human-readable classification rationale.
    """

    handler_address: int
    operation: str = VMOperation.UNKNOWN
    confidence: float = 0.0
    operand_count: int = 0
    operand_width: int = 0        # in bytes (4 = dword, 8 = qword)
    reads_memory: bool = False
    writes_memory: bool = False
    modifies_flags: bool = False
    mnemonic_histogram: dict[str, int] = field(default_factory=dict)
    detail: str = ""

    def to_dict(self) -> HandlerSemanticDict:
        return {
            "handler_address": hex(self.handler_address),
            "operation": self.operation,
            "confidence": self.confidence,
            "operand_count": self.operand_count,
            "operand_width": self.operand_width,
            "reads_memory": self.reads_memory,
            "writes_memory": self.writes_memory,
            "modifies_flags": self.modifies_flags,
            "detail": self.detail,
        }


@dataclass
class OpcodeTableEntry:
    """Combines VM opcode value, handler address, and semantics.

    Attributes:
        opcode: Raw VM opcode (integer).
        handler_address: Native address of the handler.
        semantic: Full :class:`HandlerSemantic` for this opcode.
        vip_delta: Virtual-instruction-pointer advance in bytes.
    """

    opcode: int
    handler_address: int
    semantic: HandlerSemantic
    vip_delta: int = 0

    def to_dict(self) -> OpcodeTableEntryDict:
        return {
            "opcode": hex(self.opcode),
            "handler_address": hex(self.handler_address),
            "operation": self.semantic.operation,
            "confidence": self.semantic.confidence,
            "vip_delta": self.vip_delta,
        }


@dataclass
class SemanticOpcodeTable:
    """The fully-analysed VM opcode table with semantic annotations.

    Attributes:
        entries: Ordered list of :class:`OpcodeTableEntry` items.
        handler_count: Number of distinct handler addresses.
        unique_operations: Number of distinct semantic operations.
    """

    entries: list[OpcodeTableEntry] = field(default_factory=list)
    handler_count: int = 0
    unique_operations: int = 0

    def lookup_opcode(self, opcode: int) -> OpcodeTableEntry | None:
        for e in self.entries:
            if e.opcode == opcode:
                return e
        return None

    def lookup_handler(self, address: int) -> OpcodeTableEntry | None:
        for e in self.entries:
            if e.handler_address == address:
                return e
        return None

    def operations_summary(self) -> dict[str, int]:
        """Count how many opcodes map to each semantic operation."""
        counter: Counter = Counter()
        for e in self.entries:
            counter[e.semantic.operation] += 1
        return dict(counter.most_common())

    def to_dict(self) -> SemanticOpcodeTableDict:
        return {
            "handler_count": self.handler_count,
            "unique_operations": self.unique_operations,
            "operations_summary": self.operations_summary(),
            "entries": [e.to_dict() for e in self.entries],
        }


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyse_handler_semantics(
    trace: ExecutionTrace,
    boundaries: list[HandlerBoundary],
    *,
    opcode_assignments: dict[int, int] | None = None,
    symbolic_summaries: dict[int, Any] | None = None,
) -> SemanticOpcodeTable:
    """Analyse handler semantics from trace instruction slices.

    For each :class:`HandlerBoundary`, extracts the native instructions
    in that slice, builds a mnemonic histogram, and applies heuristic
    rules to classify the handler's VM-level operation.

    If *symbolic_summaries* are provided (a mapping from handler address
    to ``HandlerSymbolicSummary``), the classifier will first try to
    infer the VM operation from the symbolic expressions.  This gives
    high-confidence results even on obfuscated handlers.

    Args:
        trace: The execution trace.
        boundaries: Handler boundaries from segmentation.
        opcode_assignments: Optional mapping
            ``{handler_address: opcode_value}`` from bytecode extraction.
            If not provided, opcodes are assigned sequentially.
        symbolic_summaries: Optional mapping from handler address to a
            :class:`HandlerSymbolicSummary` (or its ``to_dict()`` output).
            When present, symbolic classification is attempted first and
            the heuristic histogram is used as a fallback.

    Returns:
        A :class:`SemanticOpcodeTable` with one entry per unique handler.
    """
    # Deduplicate by handler address — same native handler = same semantics.
    seen_handlers: dict[int, HandlerSemantic] = {}
    boundary_by_handler: dict[int, HandlerBoundary] = {}

    for boundary in boundaries:
        addr = boundary.handler_address
        if addr in seen_handlers:
            continue

        # Extract the trace slice for this handler.
        start = boundary.trace_start
        end = boundary.trace_end
        handler_insns = trace.instructions[start:end] if trace.instructions else []

        semantic = _classify_handler(
            addr, handler_insns,
            symbolic_summary=symbolic_summaries.get(addr) if symbolic_summaries else None,
        )
        seen_handlers[addr] = semantic
        boundary_by_handler[addr] = boundary

    # Build opcode table.
    if opcode_assignments is None:
        # Generate sequential opcode values.
        opcode_assignments = {
            addr: idx for idx, addr in enumerate(sorted(seen_handlers.keys()))
        }

    entries: list[OpcodeTableEntry] = []
    for addr, semantic in sorted(seen_handlers.items()):
        opcode = opcode_assignments.get(addr, 0)
        boundary = boundary_by_handler[addr]
        entries.append(OpcodeTableEntry(
            opcode=opcode,
            handler_address=addr,
            semantic=semantic,
            vip_delta=boundary.vip_delta,
        ))

    unique_ops = len({e.semantic.operation for e in entries})

    return SemanticOpcodeTable(
        entries=entries,
        handler_count=len(entries),
        unique_operations=unique_ops,
    )


# ---------------------------------------------------------------------------
# Symbolic-summary classification
# ---------------------------------------------------------------------------

# Regex patterns for recognising canonical z3 expression forms in the
# stringified ``simplified_registers`` / ``final_registers`` produced by
# SymbolicExecutor.execute_handler().
#
# The patterns intentionally ignore register-name specifics so that
# "init_rax + init_rbx" and "init_r12 + init_rsi" both match ADD.
_SYM_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    # (compiled_regex, VMOperation, confidence)
    # Arithmetic
    (re.compile(r"init_\w+\s*\+\s*init_\w+"), VMOperation.ADD, 0.92),
    (re.compile(r"init_\w+\s*-\s*init_\w+"), VMOperation.SUB, 0.92),
    (re.compile(r"init_\w+\s*\*\s*init_\w+"), VMOperation.MUL, 0.90),
    (re.compile(r"UDiv|udiv"), VMOperation.DIV, 0.90),
    (re.compile(r"SDiv|sdiv"), VMOperation.DIV, 0.90),
    # Bitwise
    (re.compile(r"init_\w+\s*&\s*init_\w+"), VMOperation.AND, 0.92),
    (re.compile(r"init_\w+\s*\|\s*init_\w+"), VMOperation.OR, 0.92),
    (re.compile(r"init_\w+\s*\^\s*init_\w+"), VMOperation.XOR, 0.92),  # z3 uses Xor() but str may be ^
    (re.compile(r"Xor\("), VMOperation.XOR, 0.90),
    (re.compile(r"~init_\w+"), VMOperation.NOT, 0.90),
    (re.compile(r"-init_\w+"), VMOperation.NEG, 0.90),
    # Shifts
    (re.compile(r"init_\w+\s*<<\s*"), VMOperation.SHL, 0.90),
    (re.compile(r"LShR\("), VMOperation.SHR, 0.90),
    (re.compile(r"init_\w+\s*>>\s*"), VMOperation.SHR, 0.88),
    (re.compile(r"RotateLeft\("), VMOperation.ROL, 0.90),
    (re.compile(r"RotateRight\("), VMOperation.ROR, 0.90),
    # Memory access (via symbolic memory symbols)
    (re.compile(r"mem_"), VMOperation.LOAD, 0.80),
]

# Patterns for detecting push/pop/store via memory_writes
_SYM_MEM_PUSH = re.compile(r"init_rsp|init_esp", re.IGNORECASE)
_SYM_MEM_STORE = re.compile(r"init_\w+", re.IGNORECASE)

# Precompiled: detect "lea reg, [reg]" nop-equivalents
_RE_LEA_NOP = re.compile(r"(\w+),\s*\[\1\]$")


def _classify_from_symbolic(
    address: int,
    summary: Any,
) -> HandlerSemantic | None:
    """Try to classify handler from its symbolic summary.

    Returns a ``HandlerSemantic`` with high confidence when the
    symbolic output matches a known pattern, or ``None`` to fall
    through to the histogram heuristic.
    """
    # Accept both dataclass and dict forms
    if hasattr(summary, "to_dict"):
        s = summary.to_dict()
    elif isinstance(summary, dict):
        s = summary
    else:
        return None

    if s.get("error"):
        return None

    # Prefer simplified_registers (MBA-simplified), fall back to final_registers.
    regs = s.get("simplified_registers") or s.get("final_registers") or {}
    mem_writes = s.get("memory_writes") or []

    if not regs and not mem_writes:
        return None

    # Collect the expression strings for non-identity register outputs.
    input_syms = s.get("input_symbols") or {}
    # An output register is "interesting" if its final value differs from
    # its initial symbolic input.
    interesting_exprs: list[str] = []
    for rname, expr_str in regs.items():
        init_sym = input_syms.get(rname, "")
        if expr_str != init_sym and expr_str != "0" and expr_str != str(0):
            interesting_exprs.append(expr_str)

    combined = " ".join(interesting_exprs)

    # Memory-write analysis
    has_stack_write = any(
        _SYM_MEM_PUSH.search(str(w.get("address", ""))) for w in mem_writes
    )
    has_mem_write = len(mem_writes) > 0

    # Check for STORE: handler writes to memory at a non-stack address
    if has_mem_write and not has_stack_write:
        return HandlerSemantic(
            handler_address=address,
            operation=VMOperation.STORE,
            confidence=0.88,
            writes_memory=True,
            detail="symbolic: memory write to non-stack address",
        )

    # Check for VM_PUSH: writes to stack address
    if has_stack_write and not interesting_exprs:
        return HandlerSemantic(
            handler_address=address,
            operation=VMOperation.PUSH,
            confidence=0.85,
            writes_memory=True,
            detail="symbolic: stack push",
        )

    # Pattern-match the expression strings
    scores: dict[str, float] = {}
    for pattern, vm_op, conf in _SYM_PATTERNS:
        if pattern.search(combined):
            scores[vm_op] = max(scores.get(vm_op, 0.0), conf)

    if not scores:
        # No match → let the histogram heuristic handle it
        return None

    best_op = max(scores, key=lambda k: scores[k])
    confidence = scores[best_op]

    return HandlerSemantic(
        handler_address=address,
        operation=best_op,
        confidence=round(confidence, 3),
        reads_memory="mem_" in combined,
        writes_memory=has_mem_write,
        detail=f"symbolic: {combined[:120]}",
    )


def _classify_handler(
    address: int,
    instructions: list[TraceInstruction],
    *,
    symbolic_summary: Any | None = None,
) -> HandlerSemantic:
    """Classify a single handler from its native instruction trace.

    When *symbolic_summary* is provided, the symbolic expression tree
    is pattern-matched first.  The traditional histogram-based heuristic
    is used as a fallback.
    """

    # ---- Symbolic classification (high-confidence) ----
    if symbolic_summary is not None:
        sym_result = _classify_from_symbolic(address, symbolic_summary)
        if sym_result is not None:
            return sym_result

    if not instructions:
        return HandlerSemantic(
            handler_address=address,
            operation=VMOperation.NOP,
            confidence=0.5,
            detail="empty handler",
        )

    # Apply junk-code filter: remove instructions that are likely noise
    # (opaque predicates, alignment nops, etc.).
    filtered = _filter_junk(instructions)
    effective = filtered if filtered else instructions

    # Apply taint-based semantic slicing: keep only instructions that
    # contribute to the handler's output (data-flow from VM context).
    taint_sliced = _taint_slice(effective)
    if taint_sliced and len(taint_sliced) >= 2:
        effective = taint_sliced

    # Build mnemonic histogram.
    mnemonics: list[str] = []
    for ti in effective:
        mnem = _extract_mnemonic(ti.disassembly)
        if mnem:
            mnemonics.append(mnem)

    hist = Counter(mnemonics)
    total = len(mnemonics) or 1

    # Check for memory access patterns.
    reads_mem = any(_accesses_memory(ti.disassembly, "read") for ti in instructions)
    writes_mem = any(_accesses_memory(ti.disassembly, "write") for ti in instructions)

    # Check for flag-modifying instructions.
    flag_modifiers = {"add", "sub", "and", "or", "xor", "cmp", "test",
                      "inc", "dec", "neg", "shl", "shr", "sal", "sar",
                      "imul", "mul"}
    modifies_flags = any(m in flag_modifiers for m in mnemonics)

    # ---- Heuristic classification ----

    # Score each potential VM operation by how well the mnemonic
    # histogram matches expected patterns.
    scores: dict[str, float] = {}

    # push/pop are VM stack infrastructure — de-weight them so the
    # "core" operation dominates.  Same for SIMD load/store.
    infra_ops = {VMOperation.PUSH, VMOperation.POP,
                 VMOperation.SIMD_LOAD, VMOperation.SIMD_STORE}

    for mnem, count in hist.items():
        # Pass disasm context for mov resolution — use first instruction
        # with this mnemonic to determine memory direction.
        sample_disasm = ""
        for ti in effective:
            if _extract_mnemonic(ti.disassembly) == mnem:
                sample_disasm = ti.disassembly
                break
        vm_op = _mnemonic_to_vm_op(mnem, sample_disasm)
        if vm_op and vm_op != VMOperation.UNKNOWN:
            weight = 0.3 if vm_op in infra_ops else 1.0
            scores[vm_op] = scores.get(vm_op, 0) + (count / total) * weight

    # Memory load pattern: mov with memory source, no store.
    if reads_mem and not writes_mem and "mov" in hist:
        scores[VMOperation.LOAD] = scores.get(VMOperation.LOAD, 0) + 0.4

    # Memory store pattern: mov with memory destination.
    if writes_mem and "mov" in hist:
        scores[VMOperation.STORE] = scores.get(VMOperation.STORE, 0) + 0.4

    # Pure memory ops (both read and write) → could be LOAD or STORE.
    if reads_mem and writes_mem:
        # Prefer store if there's a push or write-heavy pattern.
        if hist.get("push", 0) > hist.get("pop", 0):
            scores[VMOperation.PUSH] = scores.get(VMOperation.PUSH, 0) + 0.2
        elif hist.get("pop", 0) > hist.get("push", 0):
            scores[VMOperation.POP] = scores.get(VMOperation.POP, 0) + 0.2

    if not scores:
        # Can't determine — check if it's a nop (very short, no
        # meaningful operations).
        if len(instructions) <= 3:
            return HandlerSemantic(
                handler_address=address,
                operation=VMOperation.NOP,
                confidence=0.6,
                mnemonic_histogram=dict(hist),
                detail="short handler, no classifiable operations",
            )
        return HandlerSemantic(
            handler_address=address,
            operation=VMOperation.UNKNOWN,
            confidence=0.3,
            reads_memory=reads_mem,
            writes_memory=writes_mem,
            modifies_flags=modifies_flags,
            mnemonic_histogram=dict(hist),
            detail="unrecognised pattern",
        )

    # Pick the highest-scoring operation.
    best_op = max(scores, key=lambda k: scores[k])
    best_score = scores[best_op]
    confidence = min(best_score + 0.3, 0.95)  # base boost + cap

    # Estimate operand count from push/pop pairs.
    operand_count = _estimate_operands(hist)

    # Estimate operand width from register names in instructions.
    operand_width = _estimate_width(instructions)

    return HandlerSemantic(
        handler_address=address,
        operation=best_op,
        confidence=round(confidence, 3),
        operand_count=operand_count,
        operand_width=operand_width,
        reads_memory=reads_mem,
        writes_memory=writes_mem,
        modifies_flags=modifies_flags,
        mnemonic_histogram=dict(hist),
        detail=f"scores={dict(sorted(scores.items(), key=lambda x: -x[1]))}",
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_mnemonic(disasm: str) -> str:
    """Extract the mnemonic from a disassembly string."""
    if not disasm:
        return ""
    # Handle prefix-annotated lines like "lock add ..."
    parts = disasm.strip().split(None, 1)
    if not parts:
        return ""
    mnem = parts[0].lower()
    # Skip address prefixes (e.g. "0x401000:")
    if mnem.endswith(":"):
        parts = parts[1].split(None, 1) if len(parts) > 1 else []
        mnem = parts[0].lower() if parts else ""
    # Skip lock/rep prefixes
    if mnem in ("lock", "rep", "repe", "repne", "repz", "repnz"):
        sub = parts[1].split(None, 1) if len(parts) > 1 else []
        mnem = sub[0].lower() if sub else mnem
    return mnem


def _filter_junk(
    instructions: list[TraceInstruction],
) -> list[TraceInstruction]:
    """Remove likely junk / opaque-predicate code from a handler slice.

    Junk-code patterns common in VM-protected binaries:
    * ``xor reg, reg`` followed by branch (opaque predicate)
    * Pure flag manipulation (pushf/popf/clc/stc) sequences
    * ``nop``-equivalent instructions (``xchg reg, reg``, ``lea reg, [reg]``)
    * Unreachable dead code after unconditional jumps

    Returns the filtered list, or the original list if filtering would
    remove everything (safety net).
    """
    if not instructions:
        return instructions

    filtered: list[TraceInstruction] = []
    skip_until_label = False

    for i, ti in enumerate(instructions):
        mnem = _extract_mnemonic(ti.disassembly)
        disasm = ti.disassembly.lower().strip()

        # Skip known junk mnemonics
        if mnem in _JUNK_MNEMONICS:
            # Exception: xchg is only junk when source == dest
            if mnem == "xchg":
                ops = disasm.split(None, 1)
                operands = ops[1] if len(ops) > 1 else ""
                op_parts = [p.strip() for p in operands.split(",")]
                if len(op_parts) == 2 and op_parts[0] == op_parts[1]:
                    continue  # Skip xchg reg, reg
                # else: keep it, it's meaningful data exchange
            else:
                continue

        # Skip dead code after unconditional jump
        if skip_until_label:
            # A label / new basic block starts at branch targets
            # Heuristic: next handler instruction or a target of a jmp
            if mnem and mnem not in _JUNK_MNEMONICS:
                skip_until_label = False
            else:
                continue

        # Detect opaque-predicate pattern: xor reg, reg → jz/jnz
        if mnem == "xor":
            ops = disasm.split(None, 1)
            operands = ops[1] if len(ops) > 1 else ""
            op_parts = [p.strip() for p in operands.split(",")]
            if len(op_parts) == 2 and op_parts[0] == op_parts[1]:
                # xor reg, reg is opaque predicate setup — skip it
                # and the following conditional branch
                if i + 1 < len(instructions):
                    next_mnem = _extract_mnemonic(instructions[i + 1].disassembly)
                    if next_mnem in _JCC_PREFIXES:
                        continue
                continue

        # Detect nop-equivalents: lea reg, [reg] (no displacement)
        if mnem == "lea":
            # lea rax, [rax] is a nop-equivalent
            ops = disasm.split(None, 1)
            operands = ops[1] if len(ops) > 1 else ""
            match = _RE_LEA_NOP.match(operands)
            if match:
                continue

        # After unconditional jmp, mark dead code
        if mnem == "jmp":
            skip_until_label = True

        filtered.append(ti)

    # Safety net: never return empty
    return filtered if filtered else instructions


def _mnemonic_to_vm_op(mnem: str, disasm: str = "") -> str:
    """Map a native mnemonic to a VM operation.

    For ``mov`` and variants, resolves to LOAD or STORE based on
    whether the destination operand is a memory reference.
    For SIMD data-movement instructions (movdqa, vmovaps, etc.),
    resolves to SIMD_LOAD or SIMD_STORE analogously.
    """
    if mnem in _MNEMONIC_MAP:
        vm_op = _MNEMONIC_MAP[mnem]
        # Context-dependent resolution for mov/movzx/movsx
        if mnem in ("mov", "movzx", "movsx", "movsxd") and disasm:
            if _accesses_memory(disasm, "write"):
                return VMOperation.STORE
            return VMOperation.LOAD
        # Context-dependent resolution for SIMD data-movement
        if (
            vm_op == VMOperation.SIMD_LOAD
            and disasm
            and _accesses_memory(disasm, "write")
        ):
            return VMOperation.SIMD_STORE
        return vm_op
    if mnem in _JCC_PREFIXES:
        return VMOperation.JCC
    if mnem.startswith("cmov"):
        return VMOperation.LOAD
    if mnem.startswith("set"):
        return VMOperation.CMP
    return VMOperation.UNKNOWN


def _accesses_memory(disasm: str, mode: str) -> bool:
    """Check if a disassembly line accesses memory.

    Mode 'read' checks source operand, 'write' checks destination.
    Supports both Intel syntax (``[...]``) and AT&T syntax (``(...)``
    with ``%`` register prefix).
    """
    if not disasm:
        return False

    # Detect syntax: AT&T uses %reg and (reg) for memory
    is_att = "%" in disasm

    if is_att:
        # AT&T: source is first, destination is last
        parts = disasm.split(",")

        def has_mem(s: str) -> bool:
            return "(" in s and ")" in s

        if mode == "write" and parts:
            return has_mem(parts[-1])  # AT&T dest is last
        if mode == "read" and parts:
            return has_mem(parts[0])   # AT&T source is first
        return any(has_mem(p) for p in parts)
    else:
        # Intel: destination is first, source is last
        parts = disasm.split(",")
        if mode == "write" and parts:
            return "[" in parts[0]
        if mode == "read" and len(parts) > 1:
            return "[" in parts[-1]
        return "[" in disasm


def _taint_slice(
    instructions: list[TraceInstruction],
) -> list[TraceInstruction]:
    """Taint-based semantic slicing of a handler's instructions.

    Taints likely VM context registers (rsi/rbp/rdi/esi/ebp/edi) and
    propagates through the instruction sequence.  Returns only those
    instructions that are in the taint-flow graph — i.e. instructions
    that read or write tainted data, which are the handler's *semantic
    core*.  This eliminates junk code that doesn't interact with the VM
    context.
    """
    if not instructions:
        return instructions

    try:
        from dragonslayer.analysis.taint_tracking.tracker import (
            TaintTag,
            TaintTracker,
        )
    except ImportError:
        return instructions

    # Convert TraceInstructions to duck-typed objects for the tracker
    lifted = []
    for ti in instructions:
        parts = ti.disassembly.strip().split(None, 1) if ti.disassembly else []
        mnem = parts[0].lower() if parts else "nop"
        operands = parts[1] if len(parts) > 1 else ""

        reads: list[str] = []
        writes: list[str] = []
        # Use mnemonic-aware extraction from trace_ingestion module.
        try:
            from .trace_ingestion import _extract_reg_reads_writes
            reads, writes = _extract_reg_reads_writes(mnem, operands)
        except ImportError:
            # Fallback: positional heuristic using precompiled register patterns
            ops_low = operands.lower()
            for reg, reg_pat in _TAINT_REG_PATTERNS.items():
                if reg_pat.search(ops_low):
                    if not writes:
                        writes.append(reg)
                    else:
                        reads.append(reg)

        lifted.append(_TaintableInstruction(
            address=ti.address,
            mnemonic=mnem,
            operands=operands,
            category=_guess_taint_category(mnem),
            reads=reads,
            writes=writes,
        ))

    tracker = TaintTracker()
    # Taint VM context registers
    for reg in ("rsi", "rbp", "rdi", "r12", "esi", "ebp", "edi"):
        tracker.taint_register(reg, TaintTag.VM_CONTEXT)

    result = tracker.analyze(lifted)

    # Collect addresses of tainted instructions
    tainted_addrs: set[int] = set()
    for event in result.events:
        addr = event.get("address", 0) if isinstance(event, dict) else getattr(event, "address", 0)
        if addr:
            tainted_addrs.add(addr)

    if not tainted_addrs:
        return instructions

    return [ti for ti in instructions if ti.address in tainted_addrs]


# Registers to track for taint slicing
_COMMON_TAINT_REGS = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp",
}

# Precompiled word-boundary patterns for each register (fallback path)
_TAINT_REG_PATTERNS: dict[str, re.Pattern[str]] = {
    reg: re.compile(r"\b" + re.escape(reg) + r"\b")
    for reg in sorted(_COMMON_TAINT_REGS, key=len, reverse=True)
}


def _guess_taint_category(mnemonic: str) -> str:
    """Map mnemonic to a taint-tracker category string."""
    _CATS = {
        "mov": "memory_read", "movzx": "memory_read", "movsx": "memory_read",
        "push": "stack_push", "pop": "stack_pop",
        "add": "arithmetic", "sub": "arithmetic", "xor": "logic",
        "and": "logic", "or": "logic", "cmp": "logic", "test": "logic",
        "jmp": "branch_unconditional", "call": "call", "ret": "return",
    }
    return _CATS.get(mnemonic, "unknown")


@dataclass
class _TaintableInstruction:
    """Minimal duck-typed instruction for TaintTracker.analyze()."""
    address: int
    mnemonic: str
    operands: str
    category: str
    reads: list[str] = field(default_factory=list)
    writes: list[str] = field(default_factory=list)


def _estimate_operands(hist: dict[str, int]) -> int:
    """Estimate the number of VM operands from push/pop usage."""
    pushes = hist.get("push", 0)
    pops = hist.get("pop", 0)
    return max(pushes, pops, 1)


def _estimate_width(instructions: list[TraceInstruction]) -> int:
    """Estimate operand width from register names in disassembly."""
    for ti in instructions:
        text = ti.disassembly.lower()
        # Check for YMM (256-bit = 32 bytes)
        if any(f"ymm{i}" in text for i in range(16)):
            return 32
        # Check for XMM (128-bit = 16 bytes)
        if any(f"xmm{i}" in text for i in range(16)):
            return 16
        if any(r in text for r in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                                     "rsp", "rbp", "r8", "r9")):
            return 8
        if any(r in text for r in ("eax", "ebx", "ecx", "edx", "esi", "edi")):
            return 4
    return 4  # default to 32-bit
