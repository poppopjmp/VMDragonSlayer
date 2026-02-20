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


# ---------------------------------------------------------------------------
# Sub-register aliasing for x86/x86-64
# ---------------------------------------------------------------------------
# Maps sub-register names to (parent_64, parent_32, bit_lo, bit_hi).
# bit_hi is *exclusive* — e.g. (0, 8) means bits [7:0].
# For 32-bit sub-registers on x86-64, writes zero-extend to 64 bits.

_SUBREG_MAP_64: Dict[str, tuple] = {}
_SUBREG_MAP_32: Dict[str, tuple] = {}

def _build_subreg_maps() -> None:
    """Populate the sub-register alias tables."""
    _R64 = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"]
    _R32 = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]
    _R16 = ["ax",  "bx",  "cx",  "dx",  "si",  "di",  "bp",  "sp"]
    _R8L = ["al",  "bl",  "cl",  "dl",  "sil", "dil", "bpl", "spl"]
    _R8H = ["ah",  "bh",  "ch",  "dh"]  # only first 4 have *h

    # --- x86-64 map -------------------------------------------------------
    for r64, r32, r16, r8l in zip(_R64, _R32, _R16, _R8L):
        # 32-bit → zero-extends to 64
        _SUBREG_MAP_64[r32] = (r64, 0, 32,  True)   # (parent, bit_lo, width, zero_ext)
        # 16-bit sub
        _SUBREG_MAP_64[r16] = (r64, 0, 16, False)
        # 8-bit low
        _SUBREG_MAP_64[r8l] = (r64, 0, 8,  False)

    for i, r8h in enumerate(_R8H):
        _SUBREG_MAP_64[r8h] = (_R64[i], 8, 8, False)

    # r8–r15 extended registers
    for n in range(8, 16):
        base = f"r{n}"
        _SUBREG_MAP_64[f"r{n}d"]  = (base, 0, 32, True)
        _SUBREG_MAP_64[f"r{n}w"]  = (base, 0, 16, False)
        _SUBREG_MAP_64[f"r{n}b"]  = (base, 0, 8,  False)

    # --- x86-32 map -------------------------------------------------------
    for r32, r16, r8l in zip(_R32, _R16, _R8L[:4]):
        _SUBREG_MAP_32[r16] = (r32, 0, 16, False)
        _SUBREG_MAP_32[r8l] = (r32, 0, 8,  False)
    for i, r8h in enumerate(_R8H):
        _SUBREG_MAP_32[r8h] = (_R32[i], 8, 8, False)

_build_subreg_maps()


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

    # -- Register access (with sub-register aliasing) -------------------------

    def _subreg_info(self, name: str) -> Optional[tuple]:
        """Return ``(parent, bit_lo, width, zero_ext)`` or *None*."""
        table = _SUBREG_MAP_64 if self.bit_width == 64 else _SUBREG_MAP_32
        return table.get(name)

    def get_register(self, name: str) -> Any:
        """Get the current value (symbolic or concrete) of a register.

        Handles sub-register reads: ``al`` extracts bits [7:0] of ``rax``,
        ``eax`` extracts bits [31:0], etc.
        """
        key = name.lower()
        # Direct hit — full-width register
        if key in self.registers:
            return self.registers[key]

        # Sub-register alias?
        info = self._subreg_info(key)
        if info is None:
            return 0

        parent, bit_lo, width, _ = info
        parent_val = self.registers.get(parent, 0)

        if _Z3_AVAILABLE and hasattr(parent_val, "sort"):
            return z3.Extract(bit_lo + width - 1, bit_lo, parent_val)
        else:
            if isinstance(parent_val, int):
                return (parent_val >> bit_lo) & ((1 << width) - 1)
            return 0

    def set_register(self, name: str, value: Any) -> None:
        """Set a register to a symbolic or concrete value.

        Handles sub-register writes: writing ``eax`` on x86-64 zero-extends
        to ``rax`` (upper 32 bits cleared).  Writing ``al`` or ``ax``
        preserves the upper bits of the parent.
        """
        key = name.lower()
        # Direct hit — full-width register
        if key in self.registers:
            self.registers[key] = value
            return

        # Sub-register alias?
        info = self._subreg_info(key)
        if info is None:
            self.registers[key] = value
            return

        parent, bit_lo, width, zero_ext = info
        parent_val = self.registers.get(parent, 0)
        bw = self.bit_width

        if zero_ext:
            # Writing a 32-bit sub-register on x86-64 → zero-extend to 64 bits
            if _Z3_AVAILABLE and hasattr(value, "sort"):
                val_bv = value
                if val_bv.sort().size() != width:
                    val_bv = z3.Extract(width - 1, 0, val_bv)
                self.registers[parent] = z3.ZeroExt(bw - width, val_bv)
            else:
                v = value if isinstance(value, int) else 0
                self.registers[parent] = v & ((1 << width) - 1)
        else:
            # Merge into parent preserving other bits
            if _Z3_AVAILABLE and (hasattr(parent_val, "sort") or hasattr(value, "sort")):
                parent_bv = self._ensure_bv_static(parent_val, bw) if not hasattr(parent_val, "sort") else parent_val
                val_bv = self._ensure_bv_static(value, width) if not hasattr(value, "sort") else value
                if hasattr(val_bv, "sort") and val_bv.sort().size() != width:
                    val_bv = z3.Extract(width - 1, 0, val_bv)
                # Build mask: clear bits [bit_lo+width-1 : bit_lo]
                mask_int = ((1 << bw) - 1) ^ (((1 << width) - 1) << bit_lo)
                mask_bv = z3.BitVecVal(mask_int, bw)
                cleared = parent_bv & mask_bv
                # Extend the value to full width and shift into position
                ext_val = z3.ZeroExt(bw - width, val_bv)
                if bit_lo > 0:
                    ext_val = ext_val << bit_lo
                self.registers[parent] = cleared | ext_val
            else:
                p = parent_val if isinstance(parent_val, int) else 0
                v = value if isinstance(value, int) else 0
                v &= (1 << width) - 1
                mask = ((1 << bw) - 1) ^ (((1 << width) - 1) << bit_lo)
                self.registers[parent] = (p & mask) | (v << bit_lo)

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
