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


# ---------------------------------------------------------------------------
# Symbolic memory region
# ---------------------------------------------------------------------------

@dataclass
class SymbolicMemoryRegion:
    """A named region of symbolic memory with a base symbol.

    Regions allow the memory model to reason about accesses like
    ``vm_context[vip]`` or ``stack[rsp-8]`` symbolically.  When a
    load/store falls within a mapped region the model can use the
    region's base symbol to build structured z3 expressions rather than
    creating disconnected fresh variables.

    Parameters
    ----------
    name : str
        Human-readable label (``"stack"``, ``"vm_context"``, …).
    base : Any
        z3 BitVec symbol OR concrete int for the region start.
    size : int
        Region size in bytes (0 = unbounded).
    """
    name: str
    base: Any          # z3 BitVecRef | int
    size: int = 0      # 0 = unbounded


@dataclass
class MemoryAccessRecord:
    """High-level record of a symbolic memory operation (read **or** write).

    Used by :meth:`SymbolicState.summarize_memory_effects` to produce
    structured LOAD/STORE summaries for handler clustering.
    """
    kind: str              # "load" or "store"
    address_expr: str      # z3 s-expression or hex string
    value_expr: str        # z3 s-expression or hex string / concrete
    size: int              # bytes
    region: Optional[str] = None  # region name if resolved
    timestamp: int = 0


# ---------------------------------------------------------------------------
# Alias query results
# ---------------------------------------------------------------------------

class AliasResult:
    """Result of a memory alias query."""
    MUST = "must"   # addresses are provably equal
    MAY = "may"     # addresses could be equal (under some constraints)
    NO = "no"       # addresses are provably different


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
        self._symbolic_store: List[MemoryWrite] = []  # writes with symbolic addresses
        self._read_log: List[MemoryAccessRecord] = []   # symbolic reads
        self._write_log: List[MemoryAccessRecord] = []  # symbolic writes
        self._visited_pcs: Set[int] = set()
        self._visit_counts: Dict[int, int] = {}  # per-address visit count
        self._last_cmp: Any = None  # legacy compat — kept for callers

        # Named memory regions (e.g. "stack", "vm_context")
        self._regions: Dict[str, SymbolicMemoryRegion] = {}
        # Counter for generating unique symbolic memory read names
        self._sym_read_counter: int = 0

        # B45: Alias query result cache  {(id(a1), id(a2)): result}
        self._alias_cache: Dict[tuple, str] = {}

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
        operand_size: int = 0,
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
        operand_size : int
            Effective operand width in bits (8, 16, 32, 64).  When 0
            (the default) falls back to ``self.bit_width`` for backward
            compatibility.
        """
        bw = operand_size if operand_size else self.bit_width
        if _Z3_AVAILABLE and hasattr(result, "sort"):
            rbw = result.sort().size()
            # Truncate/extend result to the operand width for flag
            # computation so that SF/ZF reflect the real operand size.
            if rbw != bw:
                if rbw > bw:
                    result = z3.Extract(bw - 1, 0, result)
                else:
                    result = z3.ZeroExt(bw - rbw, result)
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
                self.flags["OF"] = z3.And(sign_l != sign_r, sign_res != sign_l)
            else:
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

    def update_flags_logic(self, result: Any, *, operand_size: int = 0) -> None:
        """Update ZF/SF after a logical operation (AND/OR/XOR/TEST).

        CF and OF are cleared per the x86 ISA.

        Parameters
        ----------
        operand_size : int
            Effective operand width in bits.  ``0`` falls back to
            ``self.bit_width``.
        """
        bw = operand_size if operand_size else self.bit_width
        if _Z3_AVAILABLE and hasattr(result, "sort"):
            rbw = result.sort().size()
            if rbw != bw:
                if rbw > bw:
                    result = z3.Extract(bw - 1, 0, result)
                else:
                    result = z3.ZeroExt(bw - rbw, result)
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

    def update_flags_inc_dec(
        self, result: Any, original: Any, *, is_dec: bool,
        operand_size: int = 0,
    ) -> None:
        """Update ZF/SF/OF for INC/DEC (CF is unaffected)."""
        bw = operand_size if operand_size else self.bit_width
        one: Any = 1
        if _Z3_AVAILABLE and hasattr(result, "sort"):
            one = z3.BitVecVal(1, bw)
        # Save CF — INC/DEC must not modify carry flag
        saved_cf = self.flags.get("CF", False)
        if is_dec:
            self.update_flags_arith(result, original, one, is_sub=True, operand_size=bw)
        else:
            self.update_flags_arith(result, original, one, is_sub=False, operand_size=bw)
        # Restore CF
        self.flags["CF"] = saved_cf

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

    # -- Named memory regions ------------------------------------------------

    def map_region(self, name: str, base: Any, size: int = 0) -> None:
        """Register a named memory region.

        Parameters
        ----------
        name : str
            Region label (``"stack"``, ``"vm_context"``, ``"heap"``).
        base : z3.BitVecRef | int
            Base address of the region.
        size : int
            Region size in bytes (0 = unbounded).
        """
        self._regions[name] = SymbolicMemoryRegion(name=name, base=base, size=size)

    def get_region(self, name: str) -> Optional[SymbolicMemoryRegion]:
        """Look up a named region."""
        return self._regions.get(name)

    def resolve_region(self, address: Any) -> Optional[SymbolicMemoryRegion]:
        """Identify which region *address* belongs to, if any.

        For concrete addresses, checks if the address falls within a
        concrete region's ``[base, base+size)`` range.  For symbolic
        addresses, checks if the address can be expressed as
        ``region.base + offset`` under the current path constraints.
        """
        if isinstance(address, int):
            for region in self._regions.values():
                if isinstance(region.base, int):
                    if region.size > 0:
                        if region.base <= address < region.base + region.size:
                            return region
                    elif address >= region.base:
                        return region
            return None

        if not _Z3_AVAILABLE or not hasattr(address, "sort"):
            return None

        # For symbolic addresses: try to prove address == base + offset
        # for each region using the solver.
        for region in self._regions.values():
            base = region.base
            if not hasattr(base, "sort"):
                base = z3.BitVecVal(base, self.bit_width)
            offset = z3.simplify(address - base)
            # If the offset simplifies to a concrete non-negative value
            # (or any value for unbounded regions), the address is in the region.
            if z3.is_bv_value(offset):
                off_val = offset.as_long()
                if region.size == 0 or off_val < region.size:
                    return region
        return None

    def _log_read(self, address: Any, value: Any, size: int,
                  region: Optional[SymbolicMemoryRegion] = None) -> None:
        """Record a read access for the memory effects summary."""
        addr_str = str(address) if hasattr(address, "sexpr") else f"{address:#x}" if isinstance(address, int) else str(address)
        val_str = str(value) if hasattr(value, "sexpr") else f"{value:#x}" if isinstance(value, int) else str(value)
        self._read_log.append(MemoryAccessRecord(
            kind="load",
            address_expr=addr_str,
            value_expr=val_str,
            size=size,
            region=region.name if region else None,
            timestamp=self.depth,
        ))

    def _log_write(self, address: Any, value: Any, size: int,
                   region: Optional[SymbolicMemoryRegion] = None) -> None:
        """Record a write access for the memory effects summary."""
        addr_str = str(address) if hasattr(address, "sexpr") else f"{address:#x}" if isinstance(address, int) else str(address)
        val_str = str(value) if hasattr(value, "sexpr") else f"{value:#x}" if isinstance(value, int) else str(value)
        self._write_log.append(MemoryAccessRecord(
            kind="store",
            address_expr=addr_str,
            value_expr=val_str,
            size=size,
            region=region.name if region else None,
            timestamp=self.depth,
        ))

    def summarize_memory_effects(self) -> Dict[str, Any]:
        """Produce a structured summary of all memory reads and writes.

        Returns a dict with ``loads`` (list of load records) and
        ``stores`` (list of store records), each annotated with region
        names where resolved.  This is used for handler classification
        and clustering.
        """
        def _rec_to_dict(rec: MemoryAccessRecord) -> Dict[str, Any]:
            d: Dict[str, Any] = {
                "kind": rec.kind,
                "address": rec.address_expr,
                "value": rec.value_expr,
                "size": rec.size,
                "timestamp": rec.timestamp,
            }
            if rec.region:
                d["region"] = rec.region
            return d

        return {
            "loads": [_rec_to_dict(r) for r in self._read_log],
            "stores": [_rec_to_dict(r) for r in self._write_log],
            "regions": {n: {"base": str(r.base), "size": r.size}
                        for n, r in self._regions.items()},
        }

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

    @staticmethod
    def _is_symbolic_addr(address: Any) -> bool:
        """Return True if *address* is a z3 expression (not a concrete int)."""
        return _Z3_AVAILABLE and hasattr(address, "sort")

    def _try_concretise(self, address: Any) -> Optional[int]:
        """Try to reduce a symbolic address to a concrete int.

        Uses the accumulated path constraints.  Returns ``None`` if
        the address cannot be uniquely concretised.
        """
        if not _Z3_AVAILABLE or not hasattr(address, "sort"):
            return int(address) if isinstance(address, int) else None
        try:
            s = z3.Solver()
            s.add(*self.constraints)
            if s.check() != z3.sat:
                return None
            model = s.model()
            val = model.eval(address, model_completion=True)
            if val is None:
                return None
            concrete = val.as_long() if hasattr(val, "as_long") else None
            if concrete is None:
                return None
            # Check uniqueness: the address *must* equal this value
            s2 = z3.Solver()
            s2.add(*self.constraints)
            s2.add(address != z3.BitVecVal(concrete, address.sort().size()))
            if s2.check() == z3.unsat:
                return concrete
            return None  # multiple concrete values possible
        except Exception:
            return None

    def query_alias(self, addr1: Any, addr2: Any) -> str:
        """Determine the alias relationship between *addr1* and *addr2*.

        Returns one of :attr:`AliasResult.MUST`, :attr:`AliasResult.MAY`,
        or :attr:`AliasResult.NO`.

        B45: results are cached by (id(addr1), id(addr2)) to avoid
        redundant Z3 queries when the same symbolic pair is checked
        multiple times during store forwarding.
        """
        # Both concrete → trivial
        if isinstance(addr1, int) and isinstance(addr2, int):
            return AliasResult.MUST if addr1 == addr2 else AliasResult.NO

        # B45: check cache
        cache_key = (id(addr1), id(addr2))
        cached = self._alias_cache.get(cache_key)
        if cached is not None:
            return cached

        if not _Z3_AVAILABLE:
            return AliasResult.MAY  # conservative

        try:
            a1 = addr1 if hasattr(addr1, "sort") else z3.BitVecVal(addr1, self.bit_width)
            a2 = addr2 if hasattr(addr2, "sort") else z3.BitVecVal(addr2, self.bit_width)
            # Normalise widths
            w1 = a1.sort().size()
            w2 = a2.sort().size()
            if w1 != w2:
                target = max(w1, w2)
                if w1 < target:
                    a1 = z3.ZeroExt(target - w1, a1)
                if w2 < target:
                    a2 = z3.ZeroExt(target - w2, a2)

            s_eq = z3.Solver()
            s_eq.add(*self.constraints)
            s_eq.add(a1 != a2)
            if s_eq.check() == z3.unsat:
                self._alias_cache[cache_key] = AliasResult.MUST
                return AliasResult.MUST  # can never differ → must alias

            s_neq = z3.Solver()
            s_neq.add(*self.constraints)
            s_neq.add(a1 == a2)
            if s_neq.check() == z3.unsat:
                self._alias_cache[cache_key] = AliasResult.NO
                return AliasResult.NO  # can never be equal → no alias

            self._alias_cache[cache_key] = AliasResult.MAY
            return AliasResult.MAY
        except Exception:
            return AliasResult.MAY

    def alias_analysis_batch(
        self,
        addresses: List[Any],
    ) -> Dict[tuple, str]:
        """Batch alias analysis for a list of addresses (B45).

        Returns a dictionary mapping ``(i, j)`` index-pairs to alias
        results.  Exploits the cache so previously-resolved pairs are
        instant.
        """
        results: Dict[tuple, str] = {}
        for i in range(len(addresses)):
            for j in range(i + 1, len(addresses)):
                results[(i, j)] = self.query_alias(addresses[i], addresses[j])
        return results

    def _forward_from_symbolic_store(self, address: Any, size: int) -> Optional[Any]:
        """Search the symbolic store (most recent first) for a must-aliasing write.

        If a prior write to a *must-alias* address of the same size is
        found, the stored value is forwarded.  Returns ``None`` when no
        forwarding is possible.

        B45: also handles partial-width forwarding — if a wider write
        must-aliases the read address, the low bytes are extracted.
        """
        for write in reversed(self._symbolic_store):
            alias = self.query_alias(write.address, address)
            if alias == AliasResult.MUST:
                if write.size == size:
                    return write.value
                # B45: Partial-width forwarding (read narrower than write).
                if write.size > size and _Z3_AVAILABLE and hasattr(write.value, "sort"):
                    try:
                        return z3.Extract(size * 8 - 1, 0, write.value)
                    except Exception:
                        pass
        return None

    def _make_symbolic_read_name(self, address: Any, size: int) -> str:
        """Build a meaningful name for a fresh symbolic memory read.

        If the address falls within a known region, the name encodes
        the region and offset: ``vm_context_load_0``, ``stack_load_1``.
        Otherwise falls back to ``mem_load_<counter>``.
        """
        self._sym_read_counter += 1
        region = self.resolve_region(address) if hasattr(address, "sort") or isinstance(address, int) else None
        if region is not None:
            return f"{region.name}_load_{self._sym_read_counter}"
        return f"mem_load_{self._sym_read_counter}"

    def read_memory(self, address: Any, size: int = 0) -> Any:
        """Read *size* bytes from memory at *address* (little-endian).

        Supports both concrete and symbolic addresses.  For symbolic
        addresses, attempts concretisation then falls back to store
        forwarding from prior symbolic writes.  Fresh symbolic values
        are named by region when possible (e.g.
        ``vm_context_load_1``).

        The internal store is byte-granular.  If the requested region
        contains only concrete bytes they are assembled into a Python int.
        If any byte is symbolic (z3 BitVec), a z3 expression is returned.
        Missing bytes are treated as symbolic (z3) or zero (no z3).
        """
        if size == 0:
            size = self.bit_width // 8

        # Handle symbolic addresses
        if self._is_symbolic_addr(address):
            concrete = self._try_concretise(address)
            if concrete is not None:
                address = concrete
            else:
                # Try store forwarding from symbolic writes
                forwarded = self._forward_from_symbolic_store(address, size)
                if forwarded is not None:
                    region = self.resolve_region(address)
                    self._log_read(address, forwarded, size, region)
                    return forwarded
                # Create a region-aware fresh symbolic value
                if _Z3_AVAILABLE:
                    name = self._make_symbolic_read_name(address, size)
                    val = z3.BitVec(name, size * 8)
                    region = self.resolve_region(address)
                    self._log_read(address, val, size, region)
                    return val
                return 0

        # Concrete address path (original logic)
        # Fast-path: single-slot legacy hit (un-split value from old API)
        if size > 1 and address in self.memory and (address + 1) not in self.memory:
            v = self.memory[address]
            # If it was stored without byte-split, return it directly
            if not isinstance(v, int) or v > 255:
                return v

        byte_vals: list[Any] = []
        all_concrete = True
        for i in range(size):
            b = self.memory.get(address + i)
            if b is None:
                all_concrete = False
                if _Z3_AVAILABLE:
                    b = z3.BitVec(f"mem_{(address + i):#x}", 8)
                else:
                    b = 0
            elif _Z3_AVAILABLE and hasattr(b, "sort"):
                all_concrete = False
                if b.sort().size() != 8:
                    b = z3.Extract(7, 0, b)
            else:
                b = b & 0xFF
            byte_vals.append(b)

        if all_concrete:
            # Little-endian assembly
            result = 0
            for i, bv in enumerate(byte_vals):
                result |= (bv & 0xFF) << (i * 8)
            return result

        # Symbolic assembly — Concat(byte[n-1], ..., byte[0]) in big-endian order
        if _Z3_AVAILABLE:
            parts = []
            for bv in reversed(byte_vals):
                if not hasattr(bv, "sort"):
                    bv = z3.BitVecVal(bv, 8)
                elif bv.sort().size() != 8:
                    bv = z3.Extract(7, 0, bv)
                parts.append(bv)
            if len(parts) == 1:
                return parts[0]
            result = parts[0]
            for p in parts[1:]:
                result = z3.Concat(result, p)
            return result
        return 0

    def write_memory(self, address: Any, value: Any, size: int = 0) -> None:
        """Write *value* to memory at *address* (little-endian, byte-granular).

        Supports both concrete and symbolic addresses.  Symbolic
        addresses are recorded in the symbolic store for later
        forwarding; concrete addresses are split into individual bytes.
        """
        if size == 0:
            size = self.bit_width // 8

        # Handle symbolic addresses
        if self._is_symbolic_addr(address):
            concrete = self._try_concretise(address)
            if concrete is not None:
                address = concrete
            else:
                # Store in symbolic store for later forwarding
                self._symbolic_store.append(MemoryWrite(
                    address=address, value=value, size=size,
                    timestamp=self.depth,
                ))
                self._memory_log.append(MemoryWrite(
                    address=address, value=value, size=size,
                    timestamp=self.depth,
                ))
                region = self.resolve_region(address)
                self._log_write(address, value, size, region)
                return

        # Concrete address path (original logic)
        if _Z3_AVAILABLE and hasattr(value, "sort"):
            vw = value.sort().size()
            for i in range(size):
                lo = i * 8
                hi = lo + 7
                if hi < vw:
                    self.memory[address + i] = z3.Extract(hi, lo, value)
                else:
                    self.memory[address + i] = z3.BitVecVal(0, 8)
        elif isinstance(value, int):
            for i in range(size):
                self.memory[address + i] = (value >> (i * 8)) & 0xFF
        else:
            # Fallback: store raw value at base address only
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
        new._symbolic_store = list(self._symbolic_store)
        new._read_log = list(self._read_log)
        new._write_log = list(self._write_log)
        new._visited_pcs = set(self._visited_pcs)
        new._visit_counts = dict(self._visit_counts)
        new._last_cmp = self._last_cmp
        new.flags = dict(self.flags)
        new._regions = dict(self._regions)
        new._sym_read_counter = self._sym_read_counter
        new._alias_cache = dict(self._alias_cache)
        return new

    def visit(self, pc: int) -> None:
        """Record a visited program counter and increment visit count."""
        self._visited_pcs.add(pc)
        self._visit_counts[pc] = self._visit_counts.get(pc, 0) + 1
        self.pc = pc
        self.depth += 1

    def visit_count(self, pc: int) -> int:
        """Return how many times *pc* has been visited on this path."""
        return self._visit_counts.get(pc, 0)

    @property
    def max_visit_count(self) -> int:
        """Return the highest visit count for any single address."""
        return max(self._visit_counts.values()) if self._visit_counts else 0

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
            "max_visit_count": self.max_visit_count,
        }
