"""
Symbolic Execution — Lifter
============================

Lifts raw x86/x64 machine code bytes into a simplified intermediate
representation (IR) suitable for symbolic execution.  Uses ``capstone``
for disassembly and converts to :class:`LiftedInstruction` objects.

The lifted IR is consumed by :class:`SymbolicExecutor` to drive
symbolic state transitions, and by the LLM analyzer for code recovery.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

try:
    import capstone

    _CAPSTONE_AVAILABLE = True
except ImportError:
    capstone = None
    _CAPSTONE_AVAILABLE = False


# ---------------------------------------------------------------------------
# Instruction categories
# ---------------------------------------------------------------------------

class InstructionCategory:
    """Semantic categories for lifted instructions."""
    ARITHMETIC = "arithmetic"
    LOGIC = "logic"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    STACK_PUSH = "stack_push"
    STACK_POP = "stack_pop"
    BRANCH_COND = "branch_conditional"
    BRANCH_UNCOND = "branch_unconditional"
    CALL = "call"
    RETURN = "return"
    NOP = "nop"
    SYSTEM = "system"
    UNKNOWN = "unknown"


# x86 mnemonic → category mapping
_MNEMONIC_CATEGORIES: dict[str, str] = {
    # Arithmetic
    "add": InstructionCategory.ARITHMETIC,
    "sub": InstructionCategory.ARITHMETIC,
    "mul": InstructionCategory.ARITHMETIC,
    "imul": InstructionCategory.ARITHMETIC,
    "div": InstructionCategory.ARITHMETIC,
    "idiv": InstructionCategory.ARITHMETIC,
    "inc": InstructionCategory.ARITHMETIC,
    "dec": InstructionCategory.ARITHMETIC,
    "neg": InstructionCategory.ARITHMETIC,
    "adc": InstructionCategory.ARITHMETIC,
    "sbb": InstructionCategory.ARITHMETIC,
    "lea": InstructionCategory.ARITHMETIC,
    # Logic
    "and": InstructionCategory.LOGIC,
    "or": InstructionCategory.LOGIC,
    "xor": InstructionCategory.LOGIC,
    "not": InstructionCategory.LOGIC,
    "shl": InstructionCategory.LOGIC,
    "shr": InstructionCategory.LOGIC,
    "sar": InstructionCategory.LOGIC,
    "rol": InstructionCategory.LOGIC,
    "ror": InstructionCategory.LOGIC,
    "test": InstructionCategory.LOGIC,
    "cmp": InstructionCategory.LOGIC,
    "bt": InstructionCategory.LOGIC,
    # Stack
    "push": InstructionCategory.STACK_PUSH,
    "pop": InstructionCategory.STACK_POP,
    "pushf": InstructionCategory.STACK_PUSH,
    "pushfq": InstructionCategory.STACK_PUSH,
    "popf": InstructionCategory.STACK_POP,
    "popfq": InstructionCategory.STACK_POP,
    "pusha": InstructionCategory.STACK_PUSH,
    "popa": InstructionCategory.STACK_POP,
    # Memory
    "mov": InstructionCategory.MEMORY_READ,  # refined by operand analysis
    "movzx": InstructionCategory.MEMORY_READ,
    "movsx": InstructionCategory.MEMORY_READ,
    "movsxd": InstructionCategory.MEMORY_READ,
    "cmovz": InstructionCategory.MEMORY_READ,
    "cmovnz": InstructionCategory.MEMORY_READ,
    "xchg": InstructionCategory.MEMORY_READ,
    "lods": InstructionCategory.MEMORY_READ,
    "stos": InstructionCategory.MEMORY_WRITE,
    "movs": InstructionCategory.MEMORY_WRITE,
    # Branch
    "jmp": InstructionCategory.BRANCH_UNCOND,
    "je": InstructionCategory.BRANCH_COND,
    "jne": InstructionCategory.BRANCH_COND,
    "jz": InstructionCategory.BRANCH_COND,
    "jnz": InstructionCategory.BRANCH_COND,
    "jg": InstructionCategory.BRANCH_COND,
    "jge": InstructionCategory.BRANCH_COND,
    "jl": InstructionCategory.BRANCH_COND,
    "jle": InstructionCategory.BRANCH_COND,
    "ja": InstructionCategory.BRANCH_COND,
    "jae": InstructionCategory.BRANCH_COND,
    "jb": InstructionCategory.BRANCH_COND,
    "jbe": InstructionCategory.BRANCH_COND,
    "loop": InstructionCategory.BRANCH_COND,
    # Call / Return
    "call": InstructionCategory.CALL,
    "ret": InstructionCategory.RETURN,
    "retn": InstructionCategory.RETURN,
    # NOP
    "nop": InstructionCategory.NOP,
    # System (int3 is a trap, not a NOP)
    "int3": InstructionCategory.SYSTEM,
    # System
    "syscall": InstructionCategory.SYSTEM,
    "sysenter": InstructionCategory.SYSTEM,
    "int": InstructionCategory.SYSTEM,
    "cpuid": InstructionCategory.SYSTEM,
    "rdtsc": InstructionCategory.SYSTEM,
}


@dataclass
class LiftedInstruction:
    """Single lifted instruction in simplified IR form.

    When produced from a dynamic execution trace (via
    :meth:`ExecutionTrace.to_lifted_instructions`), the ``registers``
    dict carries concrete register snapshots from the trace engine
    (Qiling / angr / Triton), enabling precise memory-address
    resolution in the taint tracker.  ``is_tainted`` reflects the
    Triton taint engine's per-instruction flag when available.
    """
    address: int
    size: int
    mnemonic: str
    operands: str
    category: str
    raw_bytes: bytes
    reads: list[str] = field(default_factory=list)   # registers/memory read
    writes: list[str] = field(default_factory=list)   # registers/memory written
    is_branch: bool = False
    branch_target: int | None = None
    registers: dict[str, int] = field(default_factory=dict)
    is_tainted: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = {
            "address": self.address,
            "size": self.size,
            "mnemonic": self.mnemonic,
            "operands": self.operands,
            "category": self.category,
            "raw_bytes": self.raw_bytes.hex().upper(),
            "reads": self.reads,
            "writes": self.writes,
            "is_branch": self.is_branch,
            "branch_target": self.branch_target,
        }
        if self.registers:
            d["registers"] = self.registers
        if self.is_tainted:
            d["is_tainted"] = True
        return d

    def __str__(self) -> str:
        return f"0x{self.address:08x}: {self.mnemonic} {self.operands}"


class InstructionLifter:
    """
    Lift raw machine code to :class:`LiftedInstruction` IR.

    Can optionally delegate disassembly to the unified
    :class:`~dragonslayer.core.disassembler.Disassembler` from
    the core module.

    Usage::

        lifter = InstructionLifter(arch="x86_64")
        instructions = lifter.lift(code_bytes, base_address=0x401000)

        # Or with an explicit Disassembler:
        from dragonslayer.core.disassembler import create_disassembler
        lifter = InstructionLifter(arch="x86_64",
                                   disassembler=create_disassembler("x64"))
    """

    def __init__(
        self,
        arch: str = "x86_64",
        *,
        disassembler: Any = None,
    ) -> None:
        self.arch = arch
        self._md = None
        self._unified_disasm = disassembler  # Disassembler | None

        if self._unified_disasm is None and _CAPSTONE_AVAILABLE:
            if "64" in arch:
                self._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            else:
                self._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            self._md.detail = True

    @staticmethod
    def available() -> bool:
        return _CAPSTONE_AVAILABLE

    def lift(
        self,
        code: bytes,
        base_address: int = 0,
        max_instructions: int = 10000,
    ) -> list[LiftedInstruction]:
        """
        Disassemble and lift *code* to IR.

        Parameters
        ----------
        code : bytes
            Raw machine code.
        base_address : int
            Virtual address of the first byte.
        max_instructions : int
            Safety limit.

        Returns
        -------
        list[LiftedInstruction]
        """
        if not _CAPSTONE_AVAILABLE or self._md is None:
            if self._unified_disasm is not None:
                return self._lift_via_unified(code, base_address, max_instructions)
            return self._fallback_lift(code, base_address, max_instructions)

        instructions: list[LiftedInstruction] = []
        for insn in self._md.disasm(code, base_address):
            if len(instructions) >= max_instructions:
                break

            mnemonic = insn.mnemonic.lower()
            category = _MNEMONIC_CATEGORIES.get(mnemonic, InstructionCategory.UNKNOWN)

            # Refine mov-family category based on first operand (destination).
            # If destination is a memory reference, it's a write, not a read.
            if category == InstructionCategory.MEMORY_READ and insn.op_str:
                dest = insn.op_str.split(",")[0].strip()
                if dest.startswith("[") or "ptr" in dest.lower():
                    category = InstructionCategory.MEMORY_WRITE

            # Extract read/write registers. Detail mode is enabled on ``_md``,
            # so the capstone bindings expose ``regs_read``/``regs_write`` (and
            # ``operands``) directly on the instruction. Newer bindings no longer
            # surface a ``CsInsn.detail`` attribute, so guard with try/except
            # rather than probing ``insn.detail``.
            reads: list[str] = []
            writes: list[str] = []
            try:
                reads = [insn.reg_name(r) for r in insn.regs_read]
                writes = [insn.reg_name(r) for r in insn.regs_write]
            except (AttributeError, capstone.CsError):
                pass

            # Branch detection
            is_branch = category in (
                InstructionCategory.BRANCH_COND,
                InstructionCategory.BRANCH_UNCOND,
                InstructionCategory.CALL,
            )
            branch_target = None
            if is_branch:
                try:
                    operands = insn.operands
                except (AttributeError, capstone.CsError):
                    operands = None
                if operands:
                    op = operands[0]
                    if op.type == capstone.x86.X86_OP_IMM:
                        branch_target = op.imm

            instructions.append(LiftedInstruction(
                address=insn.address,
                size=insn.size,
                mnemonic=mnemonic,
                operands=insn.op_str,
                category=category,
                raw_bytes=bytes(insn.bytes),
                reads=reads,
                writes=writes,
                is_branch=is_branch,
                branch_target=branch_target,
            ))

        return instructions

    def _lift_via_unified(
        self,
        code: bytes,
        base_address: int,
        max_instructions: int,
    ) -> list[LiftedInstruction]:
        """Delegate to the unified :class:`Disassembler` and convert."""
        from dragonslayer.core.disassembler import to_lifted_instructions as _convert
        raw = self._unified_disasm.disassemble(
            code, base_address, max_instructions=max_instructions,
        )
        return _convert(raw)

    @staticmethod
    def _fallback_lift(
        code: bytes,
        base_address: int,
        max_instructions: int,
    ) -> list[LiftedInstruction]:
        """
        Minimal fallback when capstone is not available.

        Produces one pseudo-instruction per byte (useful for entropy / pattern
        analysis but not for real symbolic execution).
        """
        instructions: list[LiftedInstruction] = []
        for i, byte in enumerate(code):
            if len(instructions) >= max_instructions:
                break
            instructions.append(LiftedInstruction(
                address=base_address + i,
                size=1,
                mnemonic="db",
                operands=f"0x{byte:02x}",
                category=InstructionCategory.UNKNOWN,
                raw_bytes=bytes([byte]),
            ))
        return instructions

    def lift_function(
        self,
        code: bytes,
        base_address: int = 0,
        max_instructions: int = 5000,
    ) -> tuple[list[LiftedInstruction], dict[str, Any]]:
        """
        Lift a single function and extract metadata.

        Returns (instructions, metadata) where metadata includes:
        category_counts, branch_count, call_targets, etc.
        """
        instructions = self.lift(code, base_address, max_instructions)

        category_counts: dict[str, int] = {}
        call_targets: list[int] = []
        branch_targets: list[int] = []

        for insn in instructions:
            category_counts[insn.category] = category_counts.get(insn.category, 0) + 1
            if insn.category == InstructionCategory.CALL and insn.branch_target:
                call_targets.append(insn.branch_target)
            if insn.is_branch and insn.branch_target:
                branch_targets.append(insn.branch_target)

        metadata = {
            "instruction_count": len(instructions),
            "category_counts": category_counts,
            "call_targets": call_targets,
            "branch_targets": branch_targets,
            "unique_categories": len(category_counts),
        }

        return instructions, metadata
