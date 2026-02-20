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
    flags : dict[str, z3.BoolRef | bool]
        CPU flags — ZF, CF, SF, OF tracked as z3 Bool or Python bool.
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
        self._last_cmp: Any = None  # legacy compat — kept for callers

        # Explicit EFLAGS: ZF (zero), CF (carry/borrow), SF (sign), OF (overflow)
        self.flags: Dict[str, Any] = {
            "ZF": False,
            "CF": False,
            "SF": False,
            "OF": False,
        }

        # Initialise registers
        reg_names = self.X86_64_REGISTERS if "64" in arch else self.X86_32_REGISTERS
        if _Z3_AVAILABLE:
            for name in reg_names:
                self.registers[name] = z3.BitVec(f"init_{name}", bit_width)
        else:
            for name in reg_names:
                self.registers[name] = 0

    # -- EFLAGS helpers ------------------------------------------------------

    def update_flags_arith(
        self, result: Any, left: Any, right: Any, *, is_sub: bool = False,
    ) -> None:
        """Update ZF/CF/SF/OF after an ADD or SUB-like operation.

        Parameters
        ----------
        result : z3.BitVecRef | int
            The arithmetic result.
        left, right : z3.BitVecRef | int
            Original operands (before the operation).
        is_sub : bool
            True for SUB/CMP semantics, False for ADD.
        """
        bw = self.bit_width
        if _Z3_AVAILABLE and hasattr(result, "sort"):
            zero = z3.BitVecVal(0, bw)
            self.flags["ZF"] = result == zero
            self.flags["SF"] = z3.Extract(bw - 1, bw - 1, result) == z3.BitVecVal(1, 1)
            # CF: unsigned borrow (sub) or unsigned carry (add)
            left_bv = self._ensure_bv_static(left, bw)
            right_bv = self._ensure_bv_static(right, bw)
            if is_sub:
                self.flags["CF"] = z3.ULT(left_bv, right_bv)
            else:
                self.flags["CF"] = z3.ULT(result, left_bv)
            # OF: signed overflow
            sign_l = z3.Extract(bw - 1, bw - 1, left_bv)
            sign_r = z3.Extract(bw - 1, bw - 1, right_bv)
            sign_res = z3.Extract(bw - 1, bw - 1, result)
            if is_sub:
                # Overflow if operands have different signs and result sign
                # differs from left operand sign.
                self.flags["OF"] = z3.And(sign_l != sign_r, sign_res != sign_l)
            else:
                # Overflow if operands have the same sign but the result has
                # a different sign.
                self.flags["OF"] = z3.And(sign_l == sign_r, sign_res != sign_l)
        else:
            # Concrete path
            mask = (1 << bw) - 1
            r = result & mask
            self.flags["ZF"] = (r == 0)
            self.flags["SF"] = bool(r >> (bw - 1))
            li = left if isinstance(left, int) else 0
            ri = right if isinstance(right, int) else 0
            if is_sub:
                self.flags["CF"] = (li & mask) < (ri & mask)
                # Signed overflow check
                sl = (li >> (bw - 1)) & 1
                sr = (ri >> (bw - 1)) & 1
                sres = (r >> (bw - 1)) & 1
                self.flags["OF"] = (sl != sr) and (sres != sl)
            else:
                self.flags["CF"] = (r < (li & mask))
                sl = (li >> (bw - 1)) & 1
                sr = (ri >> (bw - 1)) & 1
                sres = (r >> (bw - 1)) & 1
                self.flags["OF"] = (sl == sr) and (sres != sl)

    def update_flags_logic(self, result: Any) -> None:
        """Update ZF/SF after a logical operation (AND/OR/XOR/TEST).

        CF and OF are cleared per the x86 ISA.
        """
        bw = self.bit_width
        if _Z3_AVAILABLE and hasattr(result, "sort"):
            zero = z3.BitVecVal(0, bw)
            self.flags["ZF"] = result == zero
            self.flags["SF"] = z3.Extract(bw - 1, bw - 1, result) == z3.BitVecVal(1, 1)
        else:
            mask = (1 << bw) - 1
            r = result & mask
            self.flags["ZF"] = (r == 0)
            self.flags["SF"] = bool(r >> (bw - 1))
        self.flags["CF"] = False if not _Z3_AVAILABLE else z3.BoolVal(False)
        self.flags["OF"] = False if not _Z3_AVAILABLE else z3.BoolVal(False)

    def update_flags_inc_dec(self, result: Any, original: Any, *, is_dec: bool) -> None:
        """Update ZF/SF/OF for INC/DEC (CF is unaffected)."""
        bw = self.bit_width
        one: Any = 1
        if _Z3_AVAILABLE and hasattr(result, "sort"):
            one = z3.BitVecVal(1, bw)
        if is_dec:
            self.update_flags_arith(result, original, one, is_sub=True)
        else:
            self.update_flags_arith(result, original, one, is_sub=False)
        # Restore CF — INC/DEC don't touch it
        # (update_flags_arith overwrote it; save/restore pattern)

    @staticmethod
    def _ensure_bv_static(val: Any, bw: int) -> Any:
        """Ensure *val* is a z3 BitVec of width *bw*."""
        if _Z3_AVAILABLE:
            if hasattr(val, "sort"):
                if val.sort().size() != bw:
                    return z3.ZeroExt(bw - val.sort().size(), val)
                return val
            return z3.BitVecVal(val, bw)
        return val

    # -- Register access ----------------------------------------------------

    def get_register(self, name: str) -> Any:
        """Get the current value (symbolic or concrete) of a register."""
        return self.registers.get(name.lower(), 0)

    def set_register(self, name: str, value: Any) -> None:
        """Set a register to a symbolic or concrete value."""
        self.registers[name.lower()] = value

    # -- Memory access -------------------------------------------------------

    def read_memory(self, address: int, size: int = 0) -> Any:
        """Read *size* bytes from memory at *address*.
        
        If *size* is 0 (default), uses the architecture word size.
        """
        if size == 0:
            size = self.bit_width // 8
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
        new._last_cmp = self._last_cmp
        new.flags = dict(self.flags)
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
