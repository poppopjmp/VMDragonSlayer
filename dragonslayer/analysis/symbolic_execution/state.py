"""
Symbolic Execution — State
==========================

Represents the symbolic state of a program during symbolic execution.
Tracks registers, memory, and path constraints using z3 symbolic variables.

This is the foundation that the :class:`SymbolicExecutor` manipulates
as it explores VM handler paths.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# z3 is an optional heavy dependency
try:
    import z3

    _Z3_AVAILABLE = True
except ImportError:
    z3 = None  # type: ignore[assignment]
    _Z3_AVAILABLE = False


@dataclass
class MemoryWrite:
    """Record of a symbolic write to memory."""
    address: Any  # z3 BitVecRef or int
    value: Any    # z3 BitVecRef or int
    size: int     # bytes
    timestamp: int = 0


class SymbolicState:
    """
    Captures the symbolic state of execution at a given program point.

    Attributes
    ----------
    registers : dict[str, z3.BitVecRef | int]
        Mapping of register names to symbolic or concrete values.
    memory : dict[int, z3.BitVecRef | int]
        Concrete-addressed memory cells (symbolic values allowed).
    constraints : list[z3.BoolRef]
        Path constraints accumulated along this execution path.
    pc : int
        Current program counter (concrete).
    depth : int
        Execution depth (number of instructions executed on this path).
    """

    X86_64_REGISTERS = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "rip", "rflags",
    ]

    X86_32_REGISTERS = [
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags",
    ]

    def __init__(
        self,
        arch: str = "x86_64",
        bit_width: int = 64,
        initial_pc: int = 0,
    ) -> None:
        self.arch = arch
        self.bit_width = bit_width
        self.pc: int = initial_pc
        self.depth: int = 0
        self.halted: bool = False
        self.halt_reason: str = ""

        self.registers: Dict[str, Any] = {}
        self.memory: Dict[int, Any] = {}
        self.constraints: List[Any] = []
        self._memory_log: List[MemoryWrite] = []
        self._visited_pcs: Set[int] = set()

        # Initialise registers
        reg_names = self.X86_64_REGISTERS if "64" in arch else self.X86_32_REGISTERS
        if _Z3_AVAILABLE:
            for name in reg_names:
                self.registers[name] = z3.BitVec(f"init_{name}", bit_width)
        else:
            for name in reg_names:
                self.registers[name] = 0

    # -- Register access ----------------------------------------------------

    def get_register(self, name: str) -> Any:
        """Get the current value (symbolic or concrete) of a register."""
        return self.registers.get(name.lower(), 0)

    def set_register(self, name: str, value: Any) -> None:
        """Set a register to a symbolic or concrete value."""
        self.registers[name.lower()] = value

    # -- Memory access -------------------------------------------------------

    def read_memory(self, address: int, size: int = 8) -> Any:
        """Read *size* bytes from memory at *address*."""
        val = self.memory.get(address)
        if val is not None:
            return val
        if _Z3_AVAILABLE:
            return z3.BitVec(f"mem_{address:#x}", size * 8)
        return 0

    def write_memory(self, address: int, value: Any, size: int = 8) -> None:
        """Write *value* to memory at *address*."""
        self.memory[address] = value
        self._memory_log.append(MemoryWrite(
            address=address, value=value, size=size, timestamp=self.depth,
        ))

    # -- Constraints --------------------------------------------------------

    def add_constraint(self, constraint: Any) -> None:
        """Add a path constraint."""
        self.constraints.append(constraint)

    def is_satisfiable(self) -> bool:
        """Check if current path constraints are satisfiable."""
        if not _Z3_AVAILABLE or not self.constraints:
            return True
        solver = z3.Solver()
        solver.add(*self.constraints)
        return solver.check() == z3.sat

    # -- State management ---------------------------------------------------

    def fork(self) -> "SymbolicState":
        """Create a deep copy for path forking."""
        new = SymbolicState(arch=self.arch, bit_width=self.bit_width, initial_pc=self.pc)
        new.depth = self.depth
        new.registers = dict(self.registers)
        new.memory = dict(self.memory)
        new.constraints = list(self.constraints)
        new._memory_log = list(self._memory_log)
        new._visited_pcs = set(self._visited_pcs)
        return new

    def visit(self, pc: int) -> None:
        """Record a visited program counter."""
        self._visited_pcs.add(pc)
        self.pc = pc
        self.depth += 1

    @property
    def visited_addresses(self) -> Set[int]:
        return set(self._visited_pcs)

    @property
    def memory_writes(self) -> List[MemoryWrite]:
        return list(self._memory_log)

    def halt(self, reason: str = "completed") -> None:
        self.halted = True
        self.halt_reason = reason

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to JSON-friendly dict (symbolic values → strings)."""
        def _ser(val: Any) -> Any:
            if _Z3_AVAILABLE and hasattr(val, "sexpr"):
                return str(val)
            return val

        return {
            "arch": self.arch,
            "pc": self.pc,
            "depth": self.depth,
            "halted": self.halted,
            "halt_reason": self.halt_reason,
            "registers": {k: _ser(v) for k, v in self.registers.items()},
            "constraints_count": len(self.constraints),
            "memory_writes_count": len(self._memory_log),
            "visited_count": len(self._visited_pcs),
        }
