"""
Unified Disassembler Backend  (Batch 38)
=========================================

Provides a single, reusable :class:`Disassembler` that other modules can
import instead of creating ad-hoc ``capstone.Cs()`` instances.

Features
--------
* **Architecture abstraction** — :func:`create_disassembler` accepts
  :class:`Architecture` enums or plain strings (``"x86"``, ``"x64"``).
* **Batch & single-instruction** — ``disassemble()`` and ``disassemble_one()``.
* **``DisassembledInstruction`` dataclass** — lightweight, compatible with
  the existing :class:`LiftedInstruction` interface (same attributes).
* **Graceful fallback** — when ``capstone`` is not installed, the module
  still loads and returns ``_FallbackInstruction`` objects with minimal
  ``db`` pseudo-mnemonics so nothing crashes.
* **PE-aware factory** — ``from_pe(parsed_binary)`` auto-selects architecture.
* **Thread-safe** — no shared mutable state; each ``Disassembler`` owns its
  own ``capstone.Cs`` instance.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    capstone = None  # type: ignore[assignment]
    CAPSTONE_AVAILABLE = False


# ---------------------------------------------------------------------------
# Architecture enum (mirrors database.Architecture)
# ---------------------------------------------------------------------------

class DisasmArchitecture(Enum):
    """Architectures supported by the disassembler."""
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"


# ---------------------------------------------------------------------------
# Instruction category mapping (reused from lifter.py for consistency)
# ---------------------------------------------------------------------------

_MNEMONIC_CATEGORIES: Dict[str, str] = {
    # Arithmetic
    "add": "arithmetic", "sub": "arithmetic", "mul": "arithmetic",
    "imul": "arithmetic", "div": "arithmetic", "idiv": "arithmetic",
    "inc": "arithmetic", "dec": "arithmetic", "neg": "arithmetic",
    "adc": "arithmetic", "sbb": "arithmetic", "lea": "arithmetic",
    # Logic
    "and": "logic", "or": "logic", "xor": "logic", "not": "logic",
    "shl": "logic", "shr": "logic", "sar": "logic", "rol": "logic",
    "ror": "logic", "test": "logic", "cmp": "logic", "bt": "logic",
    # Stack
    "push": "stack_push", "pop": "stack_pop",
    "pushf": "stack_push", "pushfq": "stack_push",
    "popf": "stack_pop", "popfq": "stack_pop",
    # Memory
    "mov": "memory", "movzx": "memory", "movsx": "memory",
    "movsxd": "memory", "xchg": "memory",
    # Branch
    "jmp": "branch_unconditional",
    "je": "branch_conditional", "jne": "branch_conditional",
    "jz": "branch_conditional", "jnz": "branch_conditional",
    "jg": "branch_conditional", "jge": "branch_conditional",
    "jl": "branch_conditional", "jle": "branch_conditional",
    "ja": "branch_conditional", "jae": "branch_conditional",
    "jb": "branch_conditional", "jbe": "branch_conditional",
    "loop": "branch_conditional",
    # Call / Ret
    "call": "call", "ret": "return", "retn": "return",
    # NOP
    "nop": "nop",
    # System
    "int3": "system", "syscall": "system", "sysenter": "system",
    "cpuid": "system", "rdtsc": "system", "int": "system",
}


# ---------------------------------------------------------------------------
# DisassembledInstruction
# ---------------------------------------------------------------------------

@dataclass
class DisassembledInstruction:
    """A single disassembled instruction.

    The attribute names are deliberately compatible with
    :class:`~dragonslayer.analysis.symbolic_execution.lifter.LiftedInstruction`
    so consumers can use either type interchangeably.
    """
    address: int
    size: int
    mnemonic: str
    operands: str
    category: str
    raw_bytes: bytes
    reads: List[str] = field(default_factory=list)
    writes: List[str] = field(default_factory=list)
    is_branch: bool = False
    branch_target: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "size": self.size,
            "mnemonic": self.mnemonic,
            "operands": self.operands,
            "category": self.category,
            "raw_bytes": self.raw_bytes.hex().upper(),
            "reads": list(self.reads),
            "writes": list(self.writes),
            "is_branch": self.is_branch,
            "branch_target": self.branch_target,
        }

    def __str__(self) -> str:
        return f"0x{self.address:08x}: {self.mnemonic} {self.operands}"


# ---------------------------------------------------------------------------
# Disassembler
# ---------------------------------------------------------------------------

class Disassembler:
    """Unified disassembly interface wrapping Capstone.

    Usage::

        dis = Disassembler("x64")
        # or: dis = create_disassembler("x64")
        instructions = dis.disassemble(code_bytes, 0x401000)
        one = dis.disassemble_one(code_bytes, 0x401000)
    """

    def __init__(self, architecture: str | DisasmArchitecture = "x64") -> None:
        if isinstance(architecture, DisasmArchitecture):
            self._arch_str = architecture.value
        else:
            self._arch_str = architecture.lower()

        self._cs: Any = None  # capstone.Cs or None
        if CAPSTONE_AVAILABLE:
            arch, mode = self._resolve_capstone_params()
            self._cs = capstone.Cs(arch, mode)
            self._cs.detail = True
        else:
            logger.warning("capstone not available — fallback disassembly only")

    # -- Public API ---------------------------------------------------------

    def disassemble(
        self,
        code: bytes,
        base_address: int = 0,
        *,
        max_instructions: int = 0,
    ) -> List[DisassembledInstruction]:
        """Disassemble *code* bytes starting at *base_address*.

        Parameters
        ----------
        max_instructions
            If > 0, stop after this many instructions.
        """
        if not code:
            return []

        if self._cs is not None:
            return self._disassemble_capstone(code, base_address, max_instructions)
        return self._disassemble_fallback(code, base_address, max_instructions)

    def disassemble_one(
        self,
        code: bytes,
        address: int = 0,
    ) -> Optional[DisassembledInstruction]:
        """Disassemble a single instruction. Returns *None* on failure."""
        result = self.disassemble(code, address, max_instructions=1)
        return result[0] if result else None

    @property
    def architecture(self) -> str:
        return self._arch_str

    @property
    def is_capstone_available(self) -> bool:
        return self._cs is not None

    def disassemble_to_text(
        self,
        code: bytes,
        address: int = 0,
    ) -> Tuple[str, int]:
        """Disassemble one instruction and return ``(text, size)``.

        Convenience wrapper for trace engines that only need the
        mnemonic+operands string.  Returns ``("db 0x??", 1)`` on
        failure or when capstone is not available.
        """
        insn = self.disassemble_one(code, address)
        if insn is None or insn.mnemonic == "db":
            fallback = f"db 0x{code[0]:02x}" if code else "db 0x00"
            return fallback, max(len(code), 1)
        text = f"{insn.mnemonic} {insn.operands}".strip()
        return text, insn.size

    def get_info(self) -> Dict[str, Any]:
        """Return diagnostic info about this disassembler instance."""
        return {
            "architecture": self._arch_str,
            "backend": "capstone" if self._cs else "fallback",
            "capstone_available": CAPSTONE_AVAILABLE,
        }

    # -- Internal -----------------------------------------------------------

    def _resolve_capstone_params(self) -> Tuple[int, int]:
        """Map architecture string → capstone (arch, mode) pair."""
        arch_map = {
            "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            "x64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        }
        if self._arch_str in arch_map:
            return arch_map[self._arch_str]
        # ARM stubs for future support
        if self._arch_str in ("arm",):
            return (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        if self._arch_str in ("arm64", "aarch64"):
            return (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        # Default to x64
        logger.warning("Unknown architecture %r, defaulting to x64", self._arch_str)
        return (capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    def _disassemble_capstone(
        self,
        code: bytes,
        base: int,
        max_insns: int,
    ) -> List[DisassembledInstruction]:
        """Disassemble using Capstone backend."""
        instructions: List[DisassembledInstruction] = []
        count = 0
        for insn in self._cs.disasm(code, base):
            reads: List[str] = []
            writes: List[str] = []
            branch_target: Optional[int] = None

            # Extract register reads/writes
            if insn.regs_read:
                reads = [insn.reg_name(r) for r in insn.regs_read]
            if insn.regs_write:
                writes = [insn.reg_name(r) for r in insn.regs_write]

            # Extract branch target for x86
            mnem = insn.mnemonic.lower()
            is_branch = mnem.startswith("j") or mnem in ("call", "ret", "retn", "loop")
            if is_branch and self._arch_str in ("x86", "x64"):
                try:
                    if insn.operands:
                        op = insn.operands[0]
                        if op.type == capstone.x86.X86_OP_IMM:
                            branch_target = op.imm
                except (AttributeError, IndexError):
                    pass

            category = _MNEMONIC_CATEGORIES.get(mnem, "unknown")

            instructions.append(DisassembledInstruction(
                address=insn.address,
                size=insn.size,
                mnemonic=mnem,
                operands=insn.op_str,
                category=category,
                raw_bytes=bytes(insn.bytes),
                reads=reads,
                writes=writes,
                is_branch=is_branch,
                branch_target=branch_target,
            ))

            count += 1
            if max_insns > 0 and count >= max_insns:
                break

        return instructions

    def _disassemble_fallback(
        self,
        code: bytes,
        base: int,
        max_insns: int,
    ) -> List[DisassembledInstruction]:
        """Minimal 1-byte 'db' pseudo-instructions when Capstone is missing."""
        instructions: List[DisassembledInstruction] = []
        count = 0
        for i, byte_val in enumerate(code):
            instructions.append(DisassembledInstruction(
                address=base + i,
                size=1,
                mnemonic="db",
                operands=f"0x{byte_val:02x}",
                category="unknown",
                raw_bytes=bytes([byte_val]),
            ))
            count += 1
            if max_insns > 0 and count >= max_insns:
                break
        return instructions


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------

def create_disassembler(architecture: str | DisasmArchitecture = "x64") -> Disassembler:
    """Create a :class:`Disassembler` for the given architecture."""
    return Disassembler(architecture)


def from_pe(parsed_binary: Any) -> Disassembler:
    """Create a :class:`Disassembler` whose architecture matches a PE.

    *parsed_binary* should be a :class:`ParsedBinary` from
    ``dragonslayer.analysis.binary_format``.
    """
    arch = getattr(parsed_binary, "architecture", None)
    if arch is None:
        return Disassembler("x64")

    # Handle enum or string
    arch_str = arch.value if hasattr(arch, "value") else str(arch)
    arch_lower = arch_str.lower()

    mapping = {
        "x64": "x64", "amd64": "x64", "x86_64": "x64",
        "x86": "x86", "i386": "x86", "i686": "x86",
        "arm": "arm", "arm64": "arm64", "aarch64": "arm64",
    }
    return Disassembler(mapping.get(arch_lower, "x64"))


def disassemble_section(
    section_data: bytes,
    base_address: int,
    architecture: str = "x64",
) -> List[DisassembledInstruction]:
    """Convenience: disassemble an entire code section."""
    dis = create_disassembler(architecture)
    return dis.disassemble(section_data, base_address)


# ---------------------------------------------------------------------------
# Adapter: DisassembledInstruction → LiftedInstruction
# ---------------------------------------------------------------------------

def to_lifted_instruction(insn: DisassembledInstruction) -> Any:
    """Convert a :class:`DisassembledInstruction` to a ``LiftedInstruction``.

    The import is deferred to avoid circular imports when the disassembler
    module is loaded before the lifter.

    An additional mov-family refinement is applied: if the category is
    ``"memory"`` and the destination operand contains ``[`` or ``ptr``,
    the category is set to ``"memory_write"``; otherwise ``"memory_read"``.
    """
    from dragonslayer.analysis.symbolic_execution.lifter import LiftedInstruction

    category = insn.category
    # Refine mov-family: memory → memory_read / memory_write
    if category == "memory" and insn.operands:
        dest = insn.operands.split(",")[0].strip()
        if dest.startswith("[") or "ptr" in dest.lower():
            category = "memory_write"
        else:
            category = "memory_read"

    return LiftedInstruction(
        address=insn.address,
        size=insn.size,
        mnemonic=insn.mnemonic,
        operands=insn.operands,
        category=category,
        raw_bytes=insn.raw_bytes,
        reads=list(insn.reads),
        writes=list(insn.writes),
        is_branch=insn.is_branch,
        branch_target=insn.branch_target,
    )


def to_lifted_instructions(
    insns: Sequence[DisassembledInstruction],
) -> list:
    """Batch-convert a sequence of :class:`DisassembledInstruction` objects."""
    return [to_lifted_instruction(i) for i in insns]
