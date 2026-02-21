"""
Taint Tracking — Core Tracker
==============================

Implements a data-flow taint tracking engine for binary analysis.
Tracks how tainted inputs (e.g. user data, VM bytecode operands) flow
through registers and memory, enabling identification of:

* Which VM handlers consume / produce tainted data.
* Data dependencies between handlers (def-use chains).
* Implicit flows through conditional branches.

The tracker operates on :class:`LiftedInstruction` sequences from the
symbolic execution lifter, making it independent of any specific
disassembler.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import IntFlag
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# B66: Pre-compiled regexes used by _extract_memory_address / _resolve_addr_expr
_RE_INTEL_MEM = re.compile(r"\[([^\]]+)\]")
_RE_ATT_MEM = re.compile(r"(-?(?:0x[0-9a-fA-F]+|\d+))?\(([^)]+)\)")
_RE_ADDR_SPLIT = re.compile(r"(?=[+\-])")
_RE_MUL = re.compile(r"(\w+)\s*\*\s*(\w+)")  # B75: handles both reg*scale and scale*reg
_RE_NUM = re.compile(r"(?:0x)?([0-9a-fA-F]+)")

# B80: Volatile / non-pointer registers that should NOT be tracked as pointers.
_VOLATILE_REGS: frozenset[str] = frozenset({
    "rsp", "esp", "sp", "spl",
    "rip", "eip", "ip",
    "eflags", "rflags", "flags",
    "cs", "ds", "es", "fs", "gs", "ss",
})


# ═══════════════════════════════════════════════════════════════════════════════
# x86 sub-register family map  (Batch 31)
# ═══════════════════════════════════════════════════════════════════════════════
# Maps every GP sub-register name to (canonical_64, bit_lo, width_bits,
# zero_extend).  ``zero_extend`` is True for 32-bit writes that zero the
# upper 32 bits of the 64-bit parent.

_SUBREG_FAMILIES: Dict[str, tuple] = {}
_REG_FAMILY: Dict[str, Set[str]] = {}   # canonical → all names in family

def _build_family_tables() -> None:
    """Populate the sub-register lookup tables once at import time."""
    _specs: List[tuple] = [
        # (canonical64, [(name, bit_lo, width, zero_ext), ...])
    ]
    _base_names = [
        ("rax", "eax", "ax", "al", "ah"),
        ("rbx", "ebx", "bx", "bl", "bh"),
        ("rcx", "ecx", "cx", "cl", "ch"),
        ("rdx", "edx", "dx", "dl", "dh"),
        ("rsi", "esi", "si", "sil"),
        ("rdi", "edi", "di", "dil"),
        ("rbp", "ebp", "bp", "bpl"),
        ("rsp", "esp", "sp", "spl"),
    ]
    for fam in _base_names:
        canonical = fam[0]  # 64-bit parent
        members: List[tuple] = []
        for name in fam:
            if name == canonical:
                members.append((name, 0, 64, False))
            elif name.startswith("e"):
                members.append((name, 0, 32, True))
            elif len(name) == 2 and name.endswith("x"):
                members.append((name, 0, 16, False))
            elif len(name) == 2 and name.endswith("h"):
                members.append((name, 8, 8, False))
            elif len(name) == 2 and name.endswith("l"):
                members.append((name, 0, 8, False))
            elif len(name) == 3 and name.endswith("l"):  # e.g. sil
                members.append((name, 0, 8, False))
            elif len(name) == 2 and name.endswith("i"):  # si, di
                members.append((name, 0, 16, False))
            elif len(name) == 2 and name.endswith("p"):  # bp, sp
                members.append((name, 0, 16, False))
            else:
                members.append((name, 0, 16, False))  # fallback
        _specs.append((canonical, members))

    # r8 – r15
    for n in range(8, 16):
        canonical = f"r{n}"
        members = [
            (f"r{n}", 0, 64, False),
            (f"r{n}d", 0, 32, True),
            (f"r{n}w", 0, 16, False),
            (f"r{n}b", 0, 8, False),
        ]
        _specs.append((canonical, members))

    for canonical, members in _specs:
        family_set: Set[str] = set()
        for name, bit_lo, width, zext in members:
            _SUBREG_FAMILIES[name] = (canonical, bit_lo, width, zext)
            family_set.add(name)
        _REG_FAMILY[canonical] = family_set

    # B69: SIMD register families — xmm/ymm/zmm share a single 512-bit slot.
    for n in range(16):
        canonical = f"zmm{n}"
        simd_members = [
            (f"xmm{n}", 0, 128, False),
            (f"ymm{n}", 0, 256, False),
            (f"zmm{n}", 0, 512, False),
        ]
        family_set = set()
        for name, bit_lo, width, zext in simd_members:
            _SUBREG_FAMILIES[name] = (canonical, bit_lo, width, zext)
            family_set.add(name)
        _REG_FAMILY[canonical] = family_set

_build_family_tables()


# ═══════════════════════════════════════════════════════════════════════════════
# EFLAGS taint tables  (Batch 33)
# ═══════════════════════════════════════════════════════════════════════════════
# Individual flag pseudo-registers tracked: eflags, cf, pf, af, zf, sf, of, df
_INDIVIDUAL_FLAGS: Set[str] = {"eflags", "cf", "pf", "af", "zf", "sf", "of", "df"}

# Mnemonics that write (produce) EFLAGS.
_EFLAGS_PRODUCERS: Set[str] = {
    # Arithmetic
    "add", "adc", "sub", "sbb", "neg", "inc", "dec", "imul", "mul", "div", "idiv",
    "cmp", "test",
    # Bitwise
    "and", "or", "xor", "not",
    "shl", "sal", "shr", "sar", "rol", "ror", "rcl", "rcr",
    "bt", "btc", "btr", "bts", "bsf", "bsr",
    "shld", "shrd", "popcnt", "lzcnt", "tzcnt",
    # Misc
    "sahf", "popf", "popfd", "popfq",
}

# Mnemonics that read (consume) EFLAGS.
_EFLAGS_CONSUMERS: Set[str] = {
    # Conditional jumps
    "ja", "jae", "jb", "jbe", "jc", "je", "jg", "jge", "jl", "jle",
    "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge", "jnl",
    "jnle", "jno", "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo", "js", "jz",
    # Conditional moves
    "cmova", "cmovae", "cmovb", "cmovbe", "cmovc", "cmove", "cmovg",
    "cmovge", "cmovl", "cmovle", "cmovna", "cmovnae", "cmovnb", "cmovnbe",
    "cmovnc", "cmovne", "cmovng", "cmovnge", "cmovnl", "cmovnle",
    "cmovno", "cmovnp", "cmovns", "cmovnz", "cmovo", "cmovp", "cmovpe",
    "cmovpo", "cmovs", "cmovz",
    # SETcc
    "seta", "setae", "setb", "setbe", "setc", "sete", "setg", "setge",
    "setl", "setle", "setna", "setnae", "setnb", "setnbe", "setnc",
    "setne", "setng", "setnge", "setnl", "setnle", "setno", "setnp",
    "setns", "setnz", "seto", "setp", "setpe", "setpo", "sets", "setz",
    # Misc
    "adc", "sbb", "lahf", "pushf", "pushfd", "pushfq",
    "salc",  # set al from carry
}


def is_eflags_producer(mnemonic: str) -> bool:
    """Return True if *mnemonic* writes (produces) flags."""
    return mnemonic.lower() in _EFLAGS_PRODUCERS


def is_eflags_consumer(mnemonic: str) -> bool:
    """Return True if *mnemonic* reads (consumes) flags."""
    return mnemonic.lower() in _EFLAGS_CONSUMERS


def subreg_canonical(reg: str) -> str:
    """Return the canonical 64-bit parent for *reg*, or *reg* itself."""
    info = _SUBREG_FAMILIES.get(reg.lower())
    return info[0] if info else reg.lower()


def subreg_aliases(reg: str) -> Set[str]:
    """Return all names in the same register family as *reg*."""
    info = _SUBREG_FAMILIES.get(reg.lower())
    if info is None:
        return {reg.lower()}
    return _REG_FAMILY.get(info[0], {reg.lower()})


def subreg_info(reg: str) -> Optional[tuple]:
    """Return ``(canonical, bit_lo, width, zero_ext)`` or ``None``."""
    return _SUBREG_FAMILIES.get(reg.lower())


class TaintTag(IntFlag):
    """Taint source categories (combinable via OR)."""
    CLEAN = 0
    INPUT = 1           # User / network input
    VM_OPERAND = 2      # VM bytecode operand
    VM_CONTEXT = 4      # VM context / virtual register
    MEMORY = 8          # Value read from memory
    COMPUTED = 16       # Result of tainted computation
    CONTROL = 32        # Affects control flow (implicit taint)
    CRYPTO = 64         # Involved in cryptographic operation


# ═══════════════════════════════════════════════════════════════════════════════
# Pointer-tracking memory alias detector  (B76)
# ═══════════════════════════════════════════════════════════════════════════════


class MemoryAliasTracker:
    """Lightweight must-alias detector for concrete pointer values.

    Tracks register→address bindings from observed ``mov reg, addr``
    and ``lea reg, [addr]`` instructions.  When two registers hold
    the same concrete address, stores through one are visible via the
    other.

    Usage::

        mat = MemoryAliasTracker()
        mat.bind("rax", 0x1000)
        mat.bind("rbx", 0x1000)
        assert mat.must_alias("rax", "rbx")
    """

    def __init__(self) -> None:
        self._bindings: Dict[str, int] = {}
        # Reverse: address → set of register names
        self._addr_to_regs: Dict[int, set[str]] = {}

    def bind(self, reg: str, addr: int) -> None:
        """Record that *reg* now points to concrete *addr*."""
        reg = reg.lower()
        # Unbind old
        old = self._bindings.get(reg)
        if old is not None and old in self._addr_to_regs:
            self._addr_to_regs[old].discard(reg)
            if not self._addr_to_regs[old]:
                del self._addr_to_regs[old]
        self._bindings[reg] = addr
        self._addr_to_regs.setdefault(addr, set()).add(reg)

    def unbind(self, reg: str) -> None:
        """Remove *reg* from alias tracking (e.g. on write to reg)."""
        reg = reg.lower()
        old = self._bindings.pop(reg, None)
        if old is not None and old in self._addr_to_regs:
            self._addr_to_regs[old].discard(reg)
            if not self._addr_to_regs[old]:
                del self._addr_to_regs[old]

    def resolve(self, reg: str) -> Optional[int]:
        """Return the concrete address *reg* is known to hold, or None."""
        return self._bindings.get(reg.lower())

    def must_alias(self, reg_a: str, reg_b: str) -> bool:
        """Return True if *reg_a* and *reg_b* are known to hold the same address."""
        a = self._bindings.get(reg_a.lower())
        b = self._bindings.get(reg_b.lower())
        return a is not None and a == b

    def aliases_of(self, reg: str) -> Set[str]:
        """Return all registers that must-alias *reg* (excluding itself)."""
        addr = self._bindings.get(reg.lower())
        if addr is None:
            return set()
        return self._addr_to_regs.get(addr, set()) - {reg.lower()}

    def clear(self) -> None:
        """Remove all bindings."""
        self._bindings.clear()
        self._addr_to_regs.clear()


# ═══════════════════════════════════════════════════════════════════════════════
# Byte-level taint map  (B58)
# ═══════════════════════════════════════════════════════════════════════════════

class ByteTaintMap:
    """Per-byte taint storage for registers of varying width.

    GP registers (rax, rbx, …, r15) are tracked as 8-byte arrays.
    SIMD registers (zmm0–zmm15) are tracked as 64-byte arrays so that
    xmm (16 B), ymm (32 B), and zmm (64 B) sub-ranges are all represented.
    """

    # B74: canonical register → byte count
    _CANONICAL_SIZES: Dict[str, int] = {}

    @classmethod
    def _init_sizes(cls) -> None:
        if cls._CANONICAL_SIZES:
            return
        # GP: 8 bytes
        for name in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"):
            cls._CANONICAL_SIZES[name] = 8
        for n in range(8, 16):
            cls._CANONICAL_SIZES[f"r{n}"] = 8
        # SIMD: zmm canonical → 64 bytes
        for n in range(16):
            cls._CANONICAL_SIZES[f"zmm{n}"] = 64

    def __init__(self) -> None:
        ByteTaintMap._init_sizes()
        self._map: Dict[str, List[TaintTag]] = {}

    def _ensure(self, canonical: str) -> List[TaintTag]:
        """Lazily create a correctly-sized array for *canonical*."""
        arr = self._map.get(canonical)
        if arr is None:
            nbytes = self._CANONICAL_SIZES.get(canonical, 8)
            arr = [TaintTag.CLEAN] * nbytes
            self._map[canonical] = arr
        return arr

    def set_bytes(self, reg: str, tag: TaintTag) -> None:
        """Set taint on the byte range covered by *reg*.

        For 32-bit writes the upper 32 bits are zeroed (zero-extend).
        """
        info = subreg_info(reg.lower())
        if info is None:
            # Unknown register — treat as full register by name.
            arr = self._ensure(reg.lower())
            for i in range(len(arr)):
                arr[i] = tag
            return
        canonical, bit_lo, width, zext = info
        arr = self._ensure(canonical)
        byte_lo = bit_lo // 8
        byte_hi = byte_lo + width // 8
        for i in range(byte_lo, min(byte_hi, len(arr))):
            arr[i] = tag
        if zext:
            # 32-bit write zero-extends upper 32 bits → clear bytes 4–7
            for i in range(4, min(8, len(arr))):
                arr[i] = TaintTag.CLEAN

    def get_bytes(self, reg: str) -> TaintTag:
        """Return the OR of all taint tags in the byte range of *reg*."""
        info = subreg_info(reg.lower())
        if info is None:
            arr = self._map.get(reg.lower())
            if arr is None:
                return TaintTag.CLEAN
            combined = TaintTag.CLEAN
            for t in arr:
                combined |= t
            return combined
        canonical, bit_lo, width, _zext = info
        arr = self._map.get(canonical)
        if arr is None:
            return TaintTag.CLEAN
        byte_lo = bit_lo // 8
        byte_hi = byte_lo + width // 8
        combined = TaintTag.CLEAN
        for i in range(byte_lo, min(byte_hi, len(arr))):
            combined |= arr[i]
        return combined

    def clear_bytes(self, reg: str) -> None:
        """Clear taint for the byte range of *reg*.

        32-bit writes clear the entire register (zero-extend semantics).
        Full-width writes clear all bytes.
        """
        info = subreg_info(reg.lower())
        if info is None:
            arr = self._map.get(reg.lower())
            if arr is not None:
                for i in range(len(arr)):
                    arr[i] = TaintTag.CLEAN
            return
        canonical, bit_lo, width, zext = info
        arr = self._map.get(canonical)
        if arr is None:
            return
        byte_lo = bit_lo // 8
        byte_hi = byte_lo + width // 8
        for i in range(byte_lo, min(byte_hi, len(arr))):
            arr[i] = TaintTag.CLEAN
        if zext or width == 64:
            for i in range(len(arr)):
                arr[i] = TaintTag.CLEAN

    def get_full(self, canonical: str) -> TaintTag:
        """Return the OR of all bytes for a canonical register."""
        arr = self._map.get(canonical)
        if arr is None:
            return TaintTag.CLEAN
        combined = TaintTag.CLEAN
        for t in arr:
            combined |= t
        return combined

    def clear(self) -> None:
        """Remove all taint data."""
        self._map.clear()

    def to_dict(self) -> Dict[str, List[str]]:
        """Serialise for debugging / tests."""
        return {
            k: [str(t) for t in v]
            for k, v in self._map.items()
            if any(t != TaintTag.CLEAN for t in v)
        }


@dataclass
class TaintState:
    """Snapshot of taint status for registers and memory."""
    registers: Dict[str, TaintTag] = field(default_factory=dict)
    memory: Dict[int, TaintTag] = field(default_factory=dict)
    active_tags: Set[TaintTag] = field(default_factory=set)


@dataclass
class TaintEvent:
    """A single taint propagation event."""
    address: int
    instruction: str
    event_type: str      # "propagate", "taint", "untaint", "implicit"
    source: str          # register or memory address
    destination: str     # register or memory address
    tag: TaintTag = TaintTag.CLEAN
    detail: str = ""


@dataclass
class TaintResult:
    """Complete taint analysis result."""
    success: bool
    tainted_registers: Dict[str, str] = field(default_factory=dict)
    tainted_memory: Dict[str, str] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    taint_flow_graph: Dict[str, List[str]] = field(default_factory=dict)
    instructions_analyzed: int = 0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "tainted_registers": self.tainted_registers,
            "tainted_memory": self.tainted_memory,
            "events_count": len(self.events),
            "events": self.events[:100],  # cap for serialisation
            "taint_flow_graph": self.taint_flow_graph,
            "instructions_analyzed": self.instructions_analyzed,
            "error": self.error,
        }


class TaintTracker:
    """
    Data-flow taint tracker for lifted instruction sequences.

    Usage::

        tracker = TaintTracker()
        tracker.taint_register("rdi", TaintTag.INPUT)
        result = tracker.analyze(lifted_instructions)

    For memory-sensitive taint propagation, supply an *alias_oracle*
    callable that resolves whether two memory addresses may alias::

        from dragonslayer.analysis.symbolic_execution.state import (
            SymbolicState, AliasResult,
        )
        state = SymbolicState()
        tracker = TaintTracker(alias_oracle=state.query_alias)
    """

    def __init__(
        self,
        *,
        sub_register_aware: bool = True,
        alias_oracle: Any = None,
        implicit_flow_depth: int = 16,
    ) -> None:
        self._reg_taint: Dict[str, TaintTag] = {}
        self._mem_taint: Dict[int, TaintTag] = {}
        self._symbolic_mem_taint: Dict[Any, TaintTag] = {}
        self._events: List[TaintEvent] = []
        self._flow_graph: Dict[str, Set[str]] = {}
        self._subreg_aware = sub_register_aware
        self._alias_oracle = alias_oracle

        # B58: Per-byte taint map for precise sub-register tracking
        self._byte_taint = ByteTaintMap()

        # B58: Implicit-flow scope — when a tainted conditional branch is
        # encountered, the next *implicit_flow_depth* instructions inherit
        # TaintTag.CONTROL on all their writes.
        self._implicit_flow_depth = implicit_flow_depth
        self._implicit_scope_remaining: int = 0
        self._implicit_scope_tag: TaintTag = TaintTag.CLEAN

        # B72: Interprocedural taint context — tracks register taint at
        # call boundaries so cross-function analysis is possible.
        self._context_stack: List[
            tuple[Dict[str, TaintTag], Dict[str, List[TaintTag]], Dict[str, int]]
        ] = []
        self._call_depth: int = 0

        # B76: Pointer-tracking alias detector — tracks concrete register
        # values to detect must-alias relationships for memory operands.
        self._pointer_tracker = MemoryAliasTracker()

    # ── B72: Interprocedural context management ─────────────────────────────

    def push_call_context(self) -> None:
        """Save current register + byte-level taint for interprocedural analysis.

        Call this when entering a callee to preserve the caller's
        register-taint snapshot (both ``_reg_taint`` and ``_byte_taint``),
        as well as pointer-alias bindings.
        On return, :meth:`pop_call_context` restores it while merging any
        new taint from the callee's return registers.
        """
        reg_snapshot = dict(self._reg_taint)
        # B73: Also snapshot the byte-level taint map to prevent desync
        byte_snapshot = {
            k: list(v) for k, v in self._byte_taint._map.items()
        }
        # B78: Snapshot pointer-alias bindings
        pointer_snapshot = dict(self._pointer_tracker._bindings)
        self._context_stack.append((reg_snapshot, byte_snapshot, pointer_snapshot))
        self._call_depth += 1
        logger.debug("push_call_context: depth=%d", self._call_depth)

    def pop_call_context(self, *, return_regs: tuple[str, ...] = ("rax", "rdx")) -> None:
        """Restore caller taint, merging taint from callee return registers.

        Parameters
        ----------
        return_regs:
            Registers that carry return values (default: x86-64 ABI
            ``rax`` and ``rdx``).  Their taint from the callee scope
            is OR-merged into the restored caller state.
        """
        if not self._context_stack:
            logger.warning("pop_call_context: stack empty")
            return

        # Capture return-register taint from callee scope BEFORE restoring
        return_taint = {
            r: self._reg_taint.get(r.lower(), TaintTag.CLEAN)
            for r in return_regs
        }
        # B73: Also capture callee byte-taint for return regs
        return_byte_taint: Dict[str, List[TaintTag]] = {}
        for r in return_regs:
            info = subreg_info(r.lower())
            canonical = info[0] if info else r.lower()
            arr = self._byte_taint._map.get(canonical)
            if arr is not None:
                return_byte_taint[canonical] = list(arr)

        ctx = self._context_stack.pop()
        # B78: Unpack 3-tuple (reg, byte, pointer) or legacy 2-tuple
        if len(ctx) == 3:
            caller_reg, caller_bytes, caller_pointers = ctx
        else:
            caller_reg, caller_bytes = ctx
            caller_pointers = None
        self._call_depth = max(0, self._call_depth - 1)

        # Restore caller register taint
        self._reg_taint = caller_reg

        # B73: Restore caller byte-level taint map
        self._byte_taint._map = caller_bytes

        # B78: Restore caller pointer-alias bindings
        if caller_pointers is not None:
            self._pointer_tracker.clear()
            for reg, addr in caller_pointers.items():
                self._pointer_tracker.bind(reg, addr)

        # Merge callee return-register taint
        for r, tag in return_taint.items():
            if tag != TaintTag.CLEAN:
                existing = self._reg_taint.get(r.lower(), TaintTag.CLEAN)
                self._reg_taint[r.lower()] = existing | tag

        # B73: Merge callee return-register byte taint
        for canonical, callee_arr in return_byte_taint.items():
            caller_arr = self._byte_taint._map.get(canonical)
            if caller_arr is None:
                nbytes = ByteTaintMap._CANONICAL_SIZES.get(canonical, 8)
                caller_arr = [TaintTag.CLEAN] * nbytes
                self._byte_taint._map[canonical] = caller_arr
            merge_len = min(len(callee_arr), len(caller_arr))
            for i in range(merge_len):
                if callee_arr[i] != TaintTag.CLEAN:
                    caller_arr[i] = caller_arr[i] | callee_arr[i]

        logger.debug("pop_call_context: depth=%d, merged %s", self._call_depth, return_taint)

    @property
    def call_depth(self) -> int:
        """Current interprocedural nesting depth."""
        return self._call_depth

    def _resolve_reg(self, reg: str) -> str:
        """Normalise to canonical 64-bit name when sub-register aware."""
        r = reg.lower()
        if self._subreg_aware:
            return subreg_canonical(r)
        return r

    def _propagate_subreg_taint(self, reg: str, tag: TaintTag) -> None:
        """Set taint on *reg* and, if sub-register aware, all aliases.

        B58: Also updates the byte-level taint map for precise
        sub-register tracking.
        """
        r = reg.lower()
        self._reg_taint[r] = tag
        if self._subreg_aware:
            # B58: byte-level granularity
            self._byte_taint.set_bytes(r, tag)
            for alias in subreg_aliases(r):
                # Keep legacy per-name map in sync: OR of byte range
                self._reg_taint[alias] = self._byte_taint.get_bytes(alias)

    def _clear_subreg_taint(self, reg: str) -> None:
        """Clear taint on *reg* and all aliases.

        B58: Also clears the byte-level taint map.
        """
        r = reg.lower()
        self._reg_taint[r] = TaintTag.CLEAN
        if self._subreg_aware:
            # B58: byte-level granularity
            self._byte_taint.clear_bytes(r)
            info = subreg_info(r)
            if info is not None:
                _canon, bit_lo, width, zext = info
                if width == 64 or zext:
                    # Full-width or 32-bit zero-extend → clears whole family
                    for alias in subreg_aliases(r):
                        self._reg_taint[alias] = TaintTag.CLEAN
                # For 8/16-bit writes we do NOT auto-clear the parent,
                # only the exact sub-register is cleared.
            # Sync legacy map from byte-level truth
            for alias in subreg_aliases(r):
                self._reg_taint[alias] = self._byte_taint.get_bytes(alias)

    def _collect_taint(self, reg: str) -> TaintTag:
        """Read the taint for *reg*, using byte-level map (B58)."""
        r = reg.lower()
        if self._subreg_aware:
            # B58: primary source of truth is the byte-level map
            tag = self._byte_taint.get_bytes(r)
            if tag != TaintTag.CLEAN:
                return tag
        # Fallback: check legacy per-name map for non-GP registers
        # (eflags, segment regs, etc.) or when sub_register_aware=False
        return self._reg_taint.get(r, TaintTag.CLEAN)

    # ── Alias-oracle memory taint (B51) ─────────────────────────────────

    def _query_memory_taint_via_oracle(self, addr: Any) -> TaintTag:
        """Check all tainted memory addresses for aliasing with *addr*.

        Uses the alias oracle (e.g. ``SymbolicState.query_alias``) to
        determine whether a symbolic memory address may overlap with
        previously tainted addresses.  Returns the union of all tags
        from addresses that MUST or MAY alias.
        """
        if self._alias_oracle is None:
            return TaintTag.CLEAN

        combined = TaintTag.CLEAN

        # Check concrete tainted addresses
        for tainted_addr, tag in list(self._mem_taint.items()):
            if tag == TaintTag.CLEAN:
                continue
            try:
                result = self._alias_oracle(addr, tainted_addr)
            except (ValueError, TypeError, AttributeError, RuntimeError):
                continue
            if result in ("must", "may"):
                combined |= tag

        # Check symbolic tainted addresses
        for tainted_addr, tag in list(self._symbolic_mem_taint.items()):
            if tag == TaintTag.CLEAN:
                continue
            try:
                result = self._alias_oracle(addr, tainted_addr)
            except (ValueError, TypeError, AttributeError, RuntimeError):
                continue
            if result in ("must", "may"):
                combined |= tag

        return combined

    def taint_symbolic_memory(self, addr: Any, tag: TaintTag = TaintTag.MEMORY) -> None:
        """Mark a symbolic (non-concrete) memory address as tainted.

        This is used when the store address is a symbolic expression
        that cannot be resolved to a concrete integer.  The alias oracle
        will be consulted on future loads to determine whether they
        overlap with this address.
        """
        self._symbolic_mem_taint[addr] = tag

    def taint_register(self, reg: str, tag: TaintTag = TaintTag.INPUT) -> None:
        """Mark a register as tainted with the given tag.

        When sub-register aware, all aliases (e.g. rax/eax/ax/al/ah) are
        also tainted.
        """
        self._propagate_subreg_taint(reg, tag)

    def taint_memory(self, address: int, tag: TaintTag = TaintTag.MEMORY) -> None:
        """Mark a memory address as tainted."""
        self._mem_taint[address] = tag

    def taint_memory_region(
        self,
        address: int,
        size: int,
        tag: TaintTag = TaintTag.MEMORY,
    ) -> None:
        """Mark a contiguous memory region as tainted (B70).

        Taints every byte from *address* to *address + size - 1*,
        modelling multi-byte writes (e.g. ``mov [rdi], rax`` writes 8
        bytes).
        """
        for offset in range(size):
            self._mem_taint[address + offset] = tag

    def is_memory_region_tainted(
        self,
        address: int,
        size: int,
    ) -> bool:
        """Check whether *any* byte in a memory region is tainted (B70)."""
        return any(
            self._mem_taint.get(address + offset, TaintTag.CLEAN) != TaintTag.CLEAN
            for offset in range(size)
        )

    def is_tainted(self, reg: str) -> bool:
        """Check if a register (or any alias) is tainted."""
        return self._collect_taint(reg) != TaintTag.CLEAN

    def get_taint(self, reg: str) -> TaintTag:
        """Get the taint tag for a register (checking aliases)."""
        return self._collect_taint(reg)

    # ── B76: Pointer-alias convenience ──────────────────────────────────

    def bind_pointer(self, reg: str, addr: int) -> None:
        """Record that *reg* holds concrete pointer value *addr*.

        Future queries via :meth:`must_alias` or :meth:`memory_taint_via_reg`
        will use this binding for must-alias detection.
        """
        self._pointer_tracker.bind(reg, addr)

    def must_alias(self, reg_a: str, reg_b: str) -> bool:
        """Return True if *reg_a* and *reg_b* hold the same concrete address."""
        return self._pointer_tracker.must_alias(reg_a, reg_b)

    def memory_taint_via_reg(self, reg: str) -> TaintTag:
        """Look up memory taint at the address held by *reg*.

        If no binding is known, returns CLEAN.
        """
        addr = self._pointer_tracker.resolve(reg)
        if addr is None:
            return TaintTag.CLEAN
        return self._mem_taint.get(addr, TaintTag.CLEAN)

    @property
    def pointer_tracker(self) -> MemoryAliasTracker:
        """Public access to the pointer-alias tracker."""
        return self._pointer_tracker

    def process_instruction(self, insn: Any) -> None:
        """Public API: propagate taint for a single instruction."""
        self._process_instruction(insn)

    @property
    def reg_taint(self) -> Dict[str, TaintTag]:
        """Public read access to register taint map."""
        return self._reg_taint

    @property
    def mem_taint(self) -> Dict[int, TaintTag]:
        """Public read access to memory taint map."""
        return self._mem_taint

    def analyze(self, instructions: list) -> TaintResult:
        """
        Propagate taint through a sequence of lifted instructions.

        Parameters
        ----------
        instructions : list[LiftedInstruction]
            Lifted instruction sequence from :class:`InstructionLifter`.
            If each instruction carries a ``registers`` dict mapping
            register names to concrete values (from an execution trace),
            those values enable resolution of register-indirect memory
            addresses for precise memory-taint propagation.

        Returns
        -------
        TaintResult
        """
        try:
            for insn in instructions:
                self._process_instruction(insn)

            # Build result
            tainted_regs = {
                reg: str(tag) for reg, tag in self._reg_taint.items()
                if tag != TaintTag.CLEAN
            }
            tainted_mem = {
                hex(addr): str(tag) for addr, tag in self._mem_taint.items()
                if tag != TaintTag.CLEAN
            }

            # Serialise flow graph
            flow_graph = {
                src: sorted(dsts) for src, dsts in self._flow_graph.items()
            }

            return TaintResult(
                success=True,
                tainted_registers=tainted_regs,
                tainted_memory=tainted_mem,
                events=[self._event_to_dict(e) for e in self._events],
                taint_flow_graph=flow_graph,
                instructions_analyzed=len(instructions),
            )

        except (ValueError, TypeError, KeyError, IndexError, RuntimeError, AttributeError) as exc:
            logger.exception("Taint analysis failed")
            return TaintResult(success=False, error=str(exc))

    def _process_instruction(self, insn: Any) -> None:
        """Propagate taint for a single instruction, including memory ops and EFLAGS."""
        reads = getattr(insn, "reads", [])
        writes = getattr(insn, "writes", [])
        address = getattr(insn, "address", 0)
        mnemonic = getattr(insn, "mnemonic", "")
        operands = getattr(insn, "operands", "")
        category = getattr(insn, "category", "unknown")
        # Concrete register values from an execution trace (if available)
        reg_values: Dict[str, int] = getattr(insn, "registers", {}) or {}

        mnem_lower = mnemonic.lower()

        # B76/B78: Auto-bind pointer values from concrete register snapshots
        # so that MemoryAliasTracker can detect must-alias relationships
        # during live instruction processing.
        # Filter out volatile / non-pointer registers (rsp, rip, eflags, etc.)
        if reg_values:
            for rname, rval in reg_values.items():
                if isinstance(rval, int) and rname.lower() not in _VOLATILE_REGS:
                    self._pointer_tracker.bind(rname, rval)
        # LEA and MOV-immediate: if the destination gets a concrete value,
        # update the pointer tracker.
        if mnem_lower in ("lea", "mov") and writes and reg_values:
            for w in writes:
                wl = w.lower()
                if wl in _VOLATILE_REGS:
                    continue
                val = reg_values.get(wl)
                if isinstance(val, int):
                    self._pointer_tracker.bind(wl, val)

        # B58: Decrement implicit-flow scope counter.
        if self._implicit_scope_remaining > 0:
            self._implicit_scope_remaining -= 1
            # An unconditional jump ends the scope early (merge point).
            if category == "branch_unconditional":
                self._implicit_scope_remaining = 0
                self._implicit_scope_tag = TaintTag.CLEAN

        # ── EFLAGS-aware reads ─────────────────────────────────────────────
        # If this instruction consumes EFLAGS, add "eflags" to the read set
        # so that tainted flags propagate forward automatically.
        effective_reads = list(reads)
        if is_eflags_consumer(mnem_lower):
            effective_reads.append("eflags")

        # Collect taint from read operands (registers)
        combined_taint = TaintTag.CLEAN
        tainted_sources: List[str] = []

        for reg in effective_reads:
            reg_lower = reg.lower()
            tag = self._collect_taint(reg_lower)
            if tag != TaintTag.CLEAN:
                combined_taint |= tag
                tainted_sources.append(reg_lower)

        # --- Memory taint propagation ---
        # Check if this is a memory read (load) that reads tainted memory
        if category in ("memory_read", "stack_pop") and not tainted_sources:
            # Parse memory operand to check for tainted memory address
            mem_addr = self._extract_memory_address(operands, reads, reg_values)
            if mem_addr is not None:
                mem_tag = self._mem_taint.get(mem_addr, TaintTag.CLEAN)
                if mem_tag != TaintTag.CLEAN:
                    combined_taint |= mem_tag
                    tainted_sources.append(f"mem[{mem_addr:#x}]")

            # ── B51: Alias-oracle fallback for symbolic addresses ───────
            # When concrete resolution succeeds but the address is not in
            # _mem_taint, OR when concrete resolution fails entirely, fall
            # back to the alias oracle to check against all known tainted
            # memory locations (both concrete and symbolic).
            if combined_taint == TaintTag.CLEAN and self._alias_oracle is not None:
                # Use the concrete address if available, else try a symbolic
                # representation from the instruction.
                query_addr = mem_addr
                if query_addr is None:
                    query_addr = getattr(insn, "symbolic_address", None)
                if query_addr is not None:
                    oracle_tag = self._query_memory_taint_via_oracle(query_addr)
                    if oracle_tag != TaintTag.CLEAN:
                        combined_taint |= oracle_tag
                        tainted_sources.append(
                            f"mem_alias[{query_addr:#x}]"
                            if isinstance(query_addr, int)
                            else f"mem_alias[sym]"
                        )

        # Taint from base register used as memory pointer
        for reg in reads:
            reg_lower = reg.lower()
            tag = self._collect_taint(reg_lower)
            if tag != TaintTag.CLEAN and category in ("memory_read", "memory_write"):
                combined_taint |= TaintTag.MEMORY
                if reg_lower not in tainted_sources:
                    tainted_sources.append(reg_lower)

        # Propagate to write operands
        if combined_taint != TaintTag.CLEAN:
            output_tag = combined_taint | TaintTag.COMPUTED

            for reg in writes:
                reg_lower = reg.lower()
                self._propagate_subreg_taint(reg_lower, output_tag)

                for src in tainted_sources:
                    self._events.append(TaintEvent(
                        address=address,
                        instruction=f"{mnemonic} {operands}",
                        event_type="propagate",
                        source=src,
                        destination=reg_lower,
                        tag=output_tag,
                    ))
                    self._flow_graph.setdefault(src, set()).add(reg_lower)

            # Memory write with tainted data → taint the memory location
            if category in ("memory_write", "stack_push"):
                mem_addr = self._extract_memory_address(operands, reads, reg_values)
                if mem_addr is not None:
                    self._mem_taint[mem_addr] = output_tag
                    for src in tainted_sources:
                        self._events.append(TaintEvent(
                            address=address,
                            instruction=f"{mnemonic} {operands}",
                            event_type="propagate",
                            source=src,
                            destination=f"mem[{mem_addr:#x}]",
                            tag=output_tag,
                        ))
                        self._flow_graph.setdefault(src, set()).add(f"mem[{mem_addr:#x}]")
                elif self._alias_oracle is not None:
                    # B51: store to symbolic address — record for future oracle queries
                    sym_addr = getattr(insn, "symbolic_address", None)
                    if sym_addr is not None:
                        self._symbolic_mem_taint[sym_addr] = output_tag
                        for src in tainted_sources:
                            self._events.append(TaintEvent(
                                address=address,
                                instruction=f"{mnemonic} {operands}",
                                event_type="propagate",
                                source=src,
                                destination="mem[sym]",
                                tag=output_tag,
                            ))
                            self._flow_graph.setdefault(src, set()).add("mem[sym]")

            # ── EFLAGS taint: flag-producing instruction ────────────────
            if is_eflags_producer(mnem_lower):
                eflags_tag = combined_taint | TaintTag.COMPUTED
                self._reg_taint["eflags"] = eflags_tag
                for flag in _INDIVIDUAL_FLAGS:
                    self._reg_taint[flag] = eflags_tag
                for src in tainted_sources:
                    self._events.append(TaintEvent(
                        address=address,
                        instruction=f"{mnemonic} {operands}",
                        event_type="propagate",
                        source=src,
                        destination="eflags",
                        tag=eflags_tag,
                    ))
                    self._flow_graph.setdefault(src, set()).add("eflags")

            # Implicit taint for conditional branches
            if category == "branch_conditional":
                for src in tainted_sources:
                    self._events.append(TaintEvent(
                        address=address,
                        instruction=f"{mnemonic} {operands}",
                        event_type="implicit",
                        source=src,
                        destination="control_flow",
                        tag=TaintTag.CONTROL,
                    ))
                # B58: Enter implicit-flow scope — subsequent writes in the
                # dominated region inherit CONTROL taint.
                if self._implicit_flow_depth > 0:
                    self._implicit_scope_remaining = self._implicit_flow_depth
                    self._implicit_scope_tag = combined_taint | TaintTag.CONTROL
        else:
            # B58: Even when the instruction itself has no tainted reads,
            # if we're inside an implicit-flow scope, all writes inherit
            # CONTROL taint to model control-dependent data flow.
            if self._implicit_scope_remaining > 0 and writes:
                implicit_tag = self._implicit_scope_tag
                for reg in writes:
                    reg_lower = reg.lower()
                    self._propagate_subreg_taint(reg_lower, implicit_tag)
                    self._events.append(TaintEvent(
                        address=address,
                        instruction=f"{mnemonic} {operands}",
                        event_type="implicit",
                        source="control_scope",
                        destination=reg_lower,
                        tag=implicit_tag,
                    ))
                    self._flow_graph.setdefault("control_scope", set()).add(reg_lower)
            else:
                # Clean writes clear taint on destination
                for reg in writes:
                    reg_lower = reg.lower()
                    if self._collect_taint(reg_lower) != TaintTag.CLEAN:
                        self._events.append(TaintEvent(
                            address=address,
                            instruction=f"{mnemonic} {operands}",
                            event_type="untaint",
                            source="clean_value",
                            destination=reg_lower,
                            tag=TaintTag.CLEAN,
                        ))
                        self._clear_subreg_taint(reg_lower)

            # ── EFLAGS: clean flag-producer → clear eflags taint ────────
            if is_eflags_producer(mnem_lower):
                for flag in _INDIVIDUAL_FLAGS:
                    if self._reg_taint.get(flag, TaintTag.CLEAN) != TaintTag.CLEAN:
                        self._reg_taint[flag] = TaintTag.CLEAN
                        self._events.append(TaintEvent(
                            address=address,
                            instruction=f"{mnemonic} {operands}",
                            event_type="untaint",
                            source="clean_value",
                            destination=flag,
                            tag=TaintTag.CLEAN,
                        ))

    @staticmethod
    def _extract_memory_address(
        operands: str,
        reads: List[str],
        reg_values: Dict[str, int] | None = None,
    ) -> Optional[int]:
        """
        Extract a concrete memory address from an x86 memory operand.

        Handles:
        - ``[0x401000]`` — direct constant address
        - ``[rax]``, ``[rax+8]``, ``[rax+rbx*4+0x10]`` — register-indirect,
          resolved using concrete *reg_values* from the execution trace.
        - AT&T syntax ``(%rax)`` / ``0x8(%rbx)`` as well.

        Returns ``None`` if the address cannot be resolved.
        """
        if reg_values is None:
            reg_values = {}
        # Normalise register-value keys to lowercase
        rv = {k.lower(): v for k, v in reg_values.items()}

        # --- Intel syntax: [...] ---
        m_intel = _RE_INTEL_MEM.search(operands)
        if m_intel:
            return TaintTracker._resolve_addr_expr(m_intel.group(1).strip(), rv)

        # --- AT&T syntax: disp(%base, %index, scale) or (%reg) ---
        m_att = _RE_ATT_MEM.search(operands)
        if m_att:
            disp_str = m_att.group(1) or "0"
            inner = m_att.group(2).replace("%", "").strip()
            # Rewrite to Intel-like form: base + index*scale + disp
            parts = [p.strip() for p in inner.split(",")]
            expr = parts[0]  # base
            if len(parts) >= 2 and parts[1]:
                scale = parts[2] if len(parts) >= 3 else "1"
                expr += f"+{parts[1]}*{scale}"
            expr += f"+{disp_str}"
            return TaintTracker._resolve_addr_expr(expr, rv)

        return None

    @staticmethod
    def _resolve_addr_expr(expr: str, rv: Dict[str, int]) -> Optional[int]:
        """Evaluate a simple x86 address expression given concrete register values.

        Supports: ``base``, ``base+disp``, ``base+index*scale``,
        ``base+index*scale+disp``, and variations with subtraction.
        """
        expr = expr.strip().lower()
        total = 0
        resolved = True

        # Split on + / - while keeping the sign
        tokens = _RE_ADDR_SPLIT.split(expr)
        for tok in tokens:
            tok = tok.strip()
            if not tok:
                continue

            # Determine sign
            sign = 1
            if tok.startswith("+"):
                tok = tok[1:].strip()
            elif tok.startswith("-"):
                sign = -1
                tok = tok[1:].strip()

            # Check for index*scale or scale*index form (B75: reversed support)
            m_mul = _RE_MUL.fullmatch(tok)
            if m_mul:
                g1, g2 = m_mul.group(1), m_mul.group(2)
                # Determine which is the register and which is the scale
                if g1.isdigit():
                    scale, reg_name = int(g1), g2
                elif g2.isdigit():
                    reg_name, scale = g1, int(g2)
                else:
                    resolved = False
                    continue
                if reg_name in rv:
                    total += sign * rv[reg_name] * scale
                else:
                    resolved = False
                continue

            # Numeric literal (hex or decimal)
            m_num = _RE_NUM.fullmatch(tok)
            if m_num:
                try:
                    val = int(m_num.group(0), 0) if tok.startswith("0x") else int(tok, 0)
                except ValueError:
                    val = int(m_num.group(1), 16)
                total += sign * val
                continue

            # Register name
            if tok in rv:
                total += sign * rv[tok]
            else:
                resolved = False

        return total if resolved else None

    @staticmethod
    def _event_to_dict(event: TaintEvent) -> Dict[str, Any]:
        return {
            "address": event.address,
            "instruction": event.instruction,
            "type": event.event_type,
            "source": event.source,
            "destination": event.destination,
            "tag": str(event.tag),
            "detail": event.detail,
        }

    def get_state(self) -> TaintState:
        """Return current taint state snapshot."""
        return TaintState(
            registers=dict(self._reg_taint),
            memory=dict(self._mem_taint),
            active_tags={t for t in self._reg_taint.values() if t != TaintTag.CLEAN},
        )

    def reset(self) -> None:
        """Clear all taint state."""
        self._reg_taint.clear()
        self._mem_taint.clear()
        self._symbolic_mem_taint.clear()
        self._events.clear()
        self._flow_graph.clear()
        self._byte_taint.clear()
        self._pointer_tracker.clear()
        self._implicit_scope_remaining = 0
        self._implicit_scope_tag = TaintTag.CLEAN
