"""
Dynamic VM Context Register Identification
============================================

Identifies the roles of native registers in a virtualized binary by
analysing concrete execution traces and (optionally) symbolic handler
summaries.  Goes beyond vIP identification to recover the full VM
context layout:

* **vSP** — virtual stack pointer (bidirectional monotonic changes,
  memory base in push/pop patterns)
* **Handler table base** — constant across handlers, used in
  ``[base + index * scale]`` dispatch
* **Key / rolling-key register** — involved in opcode decode
  transforms (XOR/ADD), mutates every iteration
* **Context base pointer** — stable register used as memory base
  for virtual register loads/stores
* **Scratch registers** — high variance, no cross-handler persistence

Usage::

    from dragonslayer.analysis.vm_discovery.context_registers import (
        identify_vm_context,
        VMContextLayout,
        VMContextRegister,
    )

    layout = identify_vm_context(
        trace_records, dispatcher_addresses, boundaries,
        vip_register="rsi",
    )
    print(layout.vsp)        # "rbp"
    print(layout.table_base) # "r12"
"""

from __future__ import annotations

import logging
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Data classes
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class VMContextRegister:
    """One native register with an identified VM role."""
    register: str
    role: str  # "vIP", "vSP", "vHandlerTbl", "vKey", "vContext", "scratch"
    confidence: float = 0.0
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the context register to a JSON-compatible dict."""
        return {
            "register": self.register,
            "role": self.role,
            "confidence": round(self.confidence, 3),
            "evidence": self.evidence,
        }


@dataclass
class VMContextLayout:
    """Full VM context register assignment."""
    registers: List[VMContextRegister] = field(default_factory=list)
    vip_register: str = ""
    bit_width: int = 64

    @property
    def vsp(self) -> Optional[str]:
        """Name of the register assigned the virtual stack pointer role, or ``None``."""
        return self._get_role("vSP")

    @property
    def table_base(self) -> Optional[str]:
        """Name of the register holding the handler table base address, or ``None``."""
        return self._get_role("vHandlerTbl")

    @property
    def key_register(self) -> Optional[str]:
        """Name of the rolling key / decode-transform register, or ``None``."""
        return self._get_role("vKey")

    @property
    def context_base(self) -> Optional[str]:
        """Name of the register pointing to the VM context structure, or ``None``."""
        return self._get_role("vContext")

    @property
    def scratch_registers(self) -> List[str]:
        """List of register names assigned the scratch role."""
        return [r.register for r in self.registers if r.role == "scratch"]

    def _get_role(self, role: str) -> Optional[str]:
        for r in self.registers:
            if r.role == role:
                return r.register
        return None

    def get_register_role(self, reg_name: str) -> Optional[str]:
        """Return the VM role string for *reg_name*, or ``None`` if unassigned."""
        for r in self.registers:
            if r.register == reg_name:
                return r.role
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the full VM context layout to a JSON-compatible dict."""
        return {
            "vip_register": self.vip_register,
            "bit_width": self.bit_width,
            "registers": [r.to_dict() for r in self.registers],
            "roles": {r.register: r.role for r in self.registers},
        }


# ═══════════════════════════════════════════════════════════════════════════
# GP register sets
# ═══════════════════════════════════════════════════════════════════════════

_GP_REGS_64 = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
}
_GP_REGS_32 = {
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp",
}
_SKIP_REGS = {"rsp", "esp", "rip", "eip", "rflags", "eflags"}

# Register alias families: maps any register to its aliases
_REG_FAMILIES = [
    {"rax", "eax", "ax", "al", "ah"},
    {"rbx", "ebx", "bx", "bl", "bh"},
    {"rcx", "ecx", "cx", "cl", "ch"},
    {"rdx", "edx", "dx", "dl", "dh"},
    {"rsi", "esi", "si", "sil"},
    {"rdi", "edi", "di", "dil"},
    {"rbp", "ebp", "bp", "bpl"},
    {"rsp", "esp", "sp", "spl"},
    {"r8", "r8d", "r8w", "r8b"},
    {"r9", "r9d", "r9w", "r9b"},
    {"r10", "r10d", "r10w", "r10b"},
    {"r11", "r11d", "r11w", "r11b"},
    {"r12", "r12d", "r12w", "r12b"},
    {"r13", "r13d", "r13w", "r13b"},
    {"r14", "r14d", "r14w", "r14b"},
    {"r15", "r15d", "r15w", "r15b"},
]

_REG_ALIAS_MAP: Dict[str, Set[str]] = {}
for _family in _REG_FAMILIES:
    for _name in _family:
        _REG_ALIAS_MAP[_name] = _family


def _reg_aliases(reg: str) -> Set[str]:
    """Return all aliases for a register name."""
    return _REG_ALIAS_MAP.get(reg.lower(), {reg.lower()})


# ═══════════════════════════════════════════════════════════════════════════
# Composite orchestrator
# ═══════════════════════════════════════════════════════════════════════════

def identify_vm_context(
    trace_records: Sequence[Any],
    dispatcher_addresses: Sequence[int],
    boundaries: Sequence[Any],
    *,
    vip_register: str = "",
    decode_transforms: Sequence[str] = (),
    symbolic_summaries: Sequence[Any] = (),
    bit_width: int = 64,
) -> VMContextLayout:
    """Identify all VM context registers from trace analysis.

    Runs identification for each role, resolves conflicts (a register
    can only have one role), and returns the full layout.
    """
    if not trace_records:
        return VMContextLayout(vip_register=vip_register, bit_width=bit_width)

    gp_regs = _GP_REGS_64 if bit_width == 64 else _GP_REGS_32
    dispatcher_set = set(dispatcher_addresses)

    # Collect register values at boundaries
    reg_series = _collect_register_series(trace_records, gp_regs)

    # Already-assigned roles
    assigned: Dict[str, VMContextRegister] = {}

    # 1. vIP is given (or skip)
    if vip_register:
        assigned[vip_register] = VMContextRegister(
            register=vip_register, role="vIP", confidence=1.0,
            evidence="provided",
        )

    available = gp_regs - set(assigned) - _SKIP_REGS

    # 2. Identify vSP
    vsp_scores = score_vsp_candidates(
        trace_records, boundaries, reg_series, available, vip_register,
    )
    if vsp_scores:
        best_vsp = max(vsp_scores, key=lambda x: x[1])
        if best_vsp[1] >= 0.2:
            assigned[best_vsp[0]] = VMContextRegister(
                register=best_vsp[0], role="vSP",
                confidence=best_vsp[1], evidence=best_vsp[2],
            )
            available -= {best_vsp[0]}

    # 3. Identify handler table base
    tbl_scores = score_table_base_candidates(
        trace_records, dispatcher_set, boundaries, reg_series, available,
    )
    if tbl_scores:
        best_tbl = max(tbl_scores, key=lambda x: x[1])
        if best_tbl[1] >= 0.3:
            assigned[best_tbl[0]] = VMContextRegister(
                register=best_tbl[0], role="vHandlerTbl",
                confidence=best_tbl[1], evidence=best_tbl[2],
            )
            available -= {best_tbl[0]}

    # 4. Identify key register
    key_scores = score_key_candidates(
        trace_records, dispatcher_set, decode_transforms,
        reg_series, available,
    )
    if key_scores:
        best_key = max(key_scores, key=lambda x: x[1])
        if best_key[1] >= 0.25:
            assigned[best_key[0]] = VMContextRegister(
                register=best_key[0], role="vKey",
                confidence=best_key[1], evidence=best_key[2],
            )
            available -= {best_key[0]}

    # 5. Identify context base pointer
    ctx_scores = score_context_base_candidates(
        trace_records, boundaries, reg_series, available,
    )
    if ctx_scores:
        best_ctx = max(ctx_scores, key=lambda x: x[1])
        if best_ctx[1] >= 0.25:
            assigned[best_ctx[0]] = VMContextRegister(
                register=best_ctx[0], role="vContext",
                confidence=best_ctx[1], evidence=best_ctx[2],
            )
            available -= {best_ctx[0]}

    # 6. Symbolic evidence (if available)
    if symbolic_summaries:
        _apply_symbolic_evidence(assigned, available, symbolic_summaries)

    # 7. Remaining GP registers → scratch
    for reg in sorted(available):
        assigned[reg] = VMContextRegister(
            register=reg, role="scratch", confidence=0.5,
            evidence="unassigned GP register",
        )

    layout = VMContextLayout(
        registers=list(assigned.values()),
        vip_register=vip_register,
        bit_width=bit_width,
    )
    return layout


# ═══════════════════════════════════════════════════════════════════════════
# Register series collection
# ═══════════════════════════════════════════════════════════════════════════

def _collect_register_series(
    trace_records: Sequence[Any],
    gp_regs: Set[str],
) -> Dict[str, List[int]]:
    """Collect time-series of register values from trace records."""
    series: Dict[str, List[int]] = defaultdict(list)
    for rec in trace_records:
        regs = _get_registers(rec)
        for reg in gp_regs:
            val = regs.get(reg)
            if val is not None and isinstance(val, int):
                series[reg].append(val)
    return dict(series)


# ═══════════════════════════════════════════════════════════════════════════
# vSP identification
# ═══════════════════════════════════════════════════════════════════════════

def score_vsp_candidates(
    trace_records: Sequence[Any],
    boundaries: Sequence[Any],
    reg_series: Dict[str, List[int]],
    candidates: Set[str],
    vip_register: str = "",
) -> List[Tuple[str, float, str]]:
    """Score registers as vSP candidates.

    vSP characteristics:
    - Bidirectional monotonic changes (increases for pop, decreases for push)
    - Used as memory base in push/pop handler patterns
    - Changes anti-correlate with vIP (different handler groups)
    - Delta magnitudes are small and consistent (pointer-width aligned)
    """
    results: List[Tuple[str, float, str]] = []

    for reg in candidates:
        vals = reg_series.get(reg, [])
        if len(vals) < 3:
            continue

        score = 0.0
        evidence_parts: List[str] = []

        # Compute deltas
        deltas = [vals[i + 1] - vals[i] for i in range(len(vals) - 1)]
        nonzero = [d for d in deltas if d != 0]

        if not nonzero:
            continue

        # 1. Bidirectional changes: both positive and negative deltas
        has_pos = any(d > 0 for d in nonzero)
        has_neg = any(d < 0 for d in nonzero)
        if has_pos and has_neg:
            score += 0.25
            evidence_parts.append("bidirectional")
        elif has_pos or has_neg:
            score += 0.05  # monotonic only → less likely vSP

        # 2. Pointer-width aligned deltas
        ptr_size = 8 if reg.startswith("r") else 4
        aligned = sum(1 for d in nonzero if abs(d) % ptr_size == 0)
        align_ratio = aligned / len(nonzero) if nonzero else 0.0
        if align_ratio > 0.5:
            score += 0.2
            evidence_parts.append(f"aligned={align_ratio:.1%}")
        elif align_ratio > 0.2:
            score += 0.1

        # 3. Small, consistent delta magnitudes
        abs_deltas = [abs(d) for d in nonzero]
        if abs_deltas:
            median_delta = statistics.median(abs_deltas)
            if ptr_size <= median_delta <= ptr_size * 4:
                score += 0.15
                evidence_parts.append(f"median_delta={median_delta}")
            elif median_delta <= ptr_size * 8:
                score += 0.05

        # 4. Not vIP (vIP is monotonic in one direction)
        if vip_register and reg != vip_register:
            score += 0.05

        # 5. Used in memory operands at boundary transitions
        mem_base_count = _count_memory_base_usage(
            trace_records, boundaries, reg,
        )
        if mem_base_count >= 2:
            score += 0.15
            evidence_parts.append(f"mem_base={mem_base_count}")
        elif mem_base_count >= 1:
            score += 0.08

        # 6. Prior weight for commonly used vSP registers
        if reg in ("rbp", "ebp", "r13", "r13d"):
            score += 0.1
            evidence_parts.append("prior=vSP-likely")

        results.append((reg, min(score, 1.0), "; ".join(evidence_parts)))

    return results


# ═══════════════════════════════════════════════════════════════════════════
# Handler table base identification
# ═══════════════════════════════════════════════════════════════════════════

def score_table_base_candidates(
    trace_records: Sequence[Any],
    dispatcher_set: Set[int],
    boundaries: Sequence[Any],
    reg_series: Dict[str, List[int]],
    candidates: Set[str],
) -> List[Tuple[str, float, str]]:
    """Score registers as handler table base candidates.

    The table base register is:
    - Constant (or nearly so) across the entire trace
    - Present in the dispatch instruction's operand ([base + idx * scale])
    - Read at every dispatcher visit, never written by handlers
    """
    results: List[Tuple[str, float, str]] = []

    for reg in candidates:
        vals = reg_series.get(reg, [])
        if len(vals) < 2:
            continue

        score = 0.0
        evidence_parts: List[str] = []

        # 1. Constancy: how many unique values?
        unique_vals = set(vals)
        constancy = 1.0 / len(unique_vals) if unique_vals else 0.0
        if len(unique_vals) == 1:
            score += 0.35
            evidence_parts.append("constant")
        elif len(unique_vals) <= 3:
            score += 0.15
            evidence_parts.append(f"near-constant ({len(unique_vals)} values)")

        # 2. Value looks like a valid address (large number, page-aligned hint)
        if unique_vals:
            most_common = Counter(vals).most_common(1)[0][0]
            if most_common > 0x10000:
                score += 0.1
                evidence_parts.append(f"addr-like={hex(most_common)}")

        # 3. Used in scaled-index memory operands near dispatcher
        scaled_usage = _count_scaled_index_usage(
            trace_records, dispatcher_set, reg,
        )
        if scaled_usage >= 2:
            score += 0.25
            evidence_parts.append(f"scaled_idx={scaled_usage}")
        elif scaled_usage >= 1:
            score += 0.15

        # 4. Not used as a destination in handler bodies
        write_count = _count_handler_writes(trace_records, boundaries, reg)
        if write_count == 0:
            score += 0.15
            evidence_parts.append("never-written-in-handlers")
        elif write_count <= 2:
            score += 0.05

        # 5. Prior weight
        if reg in ("r12", "r12d", "r13", "r13d", "rbx", "ebx"):
            score += 0.05

        results.append((reg, min(score, 1.0), "; ".join(evidence_parts)))

    return results


# ═══════════════════════════════════════════════════════════════════════════
# Key register identification
# ═══════════════════════════════════════════════════════════════════════════

def score_key_candidates(
    trace_records: Sequence[Any],
    dispatcher_set: Set[int],
    decode_transforms: Sequence[str],
    reg_series: Dict[str, List[int]],
    candidates: Set[str],
) -> List[Tuple[str, float, str]]:
    """Score registers as rolling key register candidates.

    The key register:
    - Appears in XOR/ADD/ROL decode transforms
    - Mutates every dispatcher iteration (but has a pattern)
    - Is different from vIP, vSP, table base
    """
    results: List[Tuple[str, float, str]] = []

    # Extract register names mentioned in decode transforms
    transform_regs = _extract_regs_from_transforms(decode_transforms)

    for reg in candidates:
        vals = reg_series.get(reg, [])
        if len(vals) < 2:
            continue

        score = 0.0
        evidence_parts: List[str] = []

        # 1. Mentioned in decode transforms (alias-aware)
        aliases = _reg_aliases(reg)
        if aliases & transform_regs:
            score += 0.35
            evidence_parts.append("in-decode-transforms")

        # 2. Mutates frequently (not constant)
        unique_vals = set(vals)
        if len(unique_vals) > len(vals) * 0.3:
            score += 0.15
            evidence_parts.append(f"varies ({len(unique_vals)} unique)")
        elif len(unique_vals) > 1:
            score += 0.05

        # 3. Involved in XOR/ADD patterns near dispatcher
        xor_count = _count_xor_involvement(trace_records, dispatcher_set, reg)
        if xor_count >= 2:
            score += 0.2
            evidence_parts.append(f"xor_near_dispatch={xor_count}")
        elif xor_count >= 1:
            score += 0.1

        # 4. Not monotonic (unlike vIP)
        if len(vals) >= 3:
            deltas = [vals[i + 1] - vals[i] for i in range(len(vals) - 1)]
            nonzero = [d for d in deltas if d != 0]
            if nonzero:
                pos_count = sum(1 for d in nonzero if d > 0)
                mono_ratio = max(pos_count, len(nonzero) - pos_count) / len(nonzero)
                if mono_ratio < 0.7:  # not monotonic
                    score += 0.1
                    evidence_parts.append("non-monotonic")

        results.append((reg, min(score, 1.0), "; ".join(evidence_parts)))

    return results


# ═══════════════════════════════════════════════════════════════════════════
# Context base register identification
# ═══════════════════════════════════════════════════════════════════════════

def score_context_base_candidates(
    trace_records: Sequence[Any],
    boundaries: Sequence[Any],
    reg_series: Dict[str, List[int]],
    candidates: Set[str],
) -> List[Tuple[str, float, str]]:
    """Score registers as VM context base pointer candidates.

    The context base:
    - Points to a VM context struct in memory
    - Relatively stable (doesn't change between handlers)
    - Used as memory base for loads/stores of virtual registers
    - Distinct from vSP (which changes push/pop-style)
    """
    results: List[Tuple[str, float, str]] = []

    for reg in candidates:
        vals = reg_series.get(reg, [])
        if len(vals) < 2:
            continue

        score = 0.0
        evidence_parts: List[str] = []

        unique_vals = set(vals)

        # 1. High stability (few unique values)
        if len(unique_vals) == 1:
            score += 0.25
            evidence_parts.append("constant")
        elif len(unique_vals) <= 3:
            score += 0.15
            evidence_parts.append(f"stable ({len(unique_vals)} vals)")

        # 2. Used as memory base in handler bodies (not just dispatcher)
        mem_base = _count_memory_base_usage(trace_records, boundaries, reg)
        if mem_base >= 3:
            score += 0.25
            evidence_parts.append(f"mem_base={mem_base}")
        elif mem_base >= 1:
            score += 0.1

        # 3. Value is address-like
        if unique_vals:
            most_common = Counter(vals).most_common(1)[0][0]
            if most_common > 0x10000:
                score += 0.1
                evidence_parts.append("addr-like")

        # 4. Used with varying displacements (context[offset])
        disp_count = _count_displaced_accesses(trace_records, boundaries, reg)
        if disp_count >= 2:
            score += 0.2
            evidence_parts.append(f"displaced_access={disp_count}")
        elif disp_count >= 1:
            score += 0.1

        # 5. Prior weight
        if reg in ("rdi", "edi", "r14", "r14d"):
            score += 0.1
            evidence_parts.append("prior=vContext-likely")

        results.append((reg, min(score, 1.0), "; ".join(evidence_parts)))

    return results


# ═══════════════════════════════════════════════════════════════════════════
# Symbolic evidence integration
# ═══════════════════════════════════════════════════════════════════════════

def _apply_symbolic_evidence(
    assigned: Dict[str, VMContextRegister],
    available: Set[str],
    symbolic_summaries: Sequence[Any],
) -> None:
    """Refine role assignments using symbolic handler summaries.

    Patterns:
    - vSP: final expression is ``in_{reg} ± ptr_size`` with sign varying
    - Table base: final expression equals input symbol (unchanged)
    - Key: final expression involves XOR/ROL of input
    """
    if not symbolic_summaries:
        return

    unchanged_counts: Counter = Counter()
    self_delta_counts: Counter = Counter()
    bidirectional_regs: Set[str] = set()

    for summary in symbolic_summaries:
        final_regs = _get_final_registers(summary)
        for reg in available:
            expr = final_regs.get(reg, "")
            input_sym = f"in_{reg}"

            if expr == input_sym:
                unchanged_counts[reg] += 1
            elif input_sym in expr:
                # Check for self-delta pattern (in_reg ± const)
                plus_match = re.match(
                    rf'{re.escape(input_sym)}\s*\+\s*(\d+)', expr,
                )
                minus_match = re.match(
                    rf'{re.escape(input_sym)}\s*-\s*(\d+)', expr,
                )
                if plus_match:
                    self_delta_counts[reg] += 1
                elif minus_match:
                    self_delta_counts[reg] -= 1

    # Registers unchanged across all summaries → table base candidate
    total = len(symbolic_summaries) if symbolic_summaries else 1
    for reg in list(available):
        if reg in assigned:
            continue

        ratio_unchanged = unchanged_counts.get(reg, 0) / total
        if ratio_unchanged > 0.8 and reg not in assigned:
            # Boost table base or context base
            if not any(r.role == "vHandlerTbl" for r in assigned.values()):
                assigned[reg] = VMContextRegister(
                    register=reg, role="vHandlerTbl",
                    confidence=ratio_unchanged * 0.8,
                    evidence=f"symbolic: unchanged in {ratio_unchanged:.0%} of handlers",
                )
                available.discard(reg)


# ═══════════════════════════════════════════════════════════════════════════
# Scoring helpers
# ═══════════════════════════════════════════════════════════════════════════

def _count_memory_base_usage(
    trace_records: Sequence[Any],
    boundaries: Sequence[Any],
    reg: str,
) -> int:
    """Count how many boundaries use *reg* as a memory base."""
    count = 0
    boundary_ranges: List[Tuple[int, int]] = []
    for b in boundaries:
        s = _get_val(b, "trace_start", 0)
        e = _get_val(b, "trace_end", 0)
        if e > s:
            boundary_ranges.append((s, e))

    reg_pattern = re.compile(r'\[' + re.escape(reg) + r'[\s+\-\]]', re.IGNORECASE)

    for start, end in boundary_ranges[:20]:  # sample first 20
        for idx in range(start, min(end, len(trace_records))):
            disasm = _get_disassembly(trace_records[idx])
            if reg_pattern.search(disasm):
                count += 1
                break  # one per boundary is enough
    return count


def _count_scaled_index_usage(
    trace_records: Sequence[Any],
    dispatcher_set: Set[int],
    reg: str,
) -> int:
    """Count occurrences of *reg* in scaled-index memory operands near dispatcher."""
    count = 0
    pattern = re.compile(
        re.escape(reg) + r'\s*\+\s*\w+\s*\*\s*\d+', re.IGNORECASE,
    )
    for rec in trace_records:
        addr = _get_val(rec, "address", 0)
        if dispatcher_set and addr not in dispatcher_set:
            continue
        disasm = _get_disassembly(rec)
        if pattern.search(disasm):
            count += 1
    return count


def _count_handler_writes(
    trace_records: Sequence[Any],
    boundaries: Sequence[Any],
    reg: str,
) -> int:
    """Count how many times *reg* appears as a write destination in handlers."""
    count = 0
    boundary_ranges: List[Tuple[int, int]] = []
    for b in boundaries:
        s = _get_val(b, "trace_start", 0)
        e = _get_val(b, "trace_end", 0)
        if e > s:
            boundary_ranges.append((s, e))

    for start, end in boundary_ranges[:20]:
        for idx in range(start, min(end, len(trace_records))):
            disasm = _get_disassembly(trace_records[idx])
            parts = disasm.strip().split(None, 1)
            if len(parts) < 2:
                continue
            operands = parts[1]
            ops = [o.strip().lower() for o in operands.split(",")]
            if ops and reg.lower() in ops[0].split():
                count += 1
    return count


def _count_xor_involvement(
    trace_records: Sequence[Any],
    dispatcher_set: Set[int],
    reg: str,
) -> int:
    """Count XOR/ADD/ROL instructions involving *reg* near dispatcher."""
    count = 0
    _decode_mnem = {"xor", "add", "not", "rol", "ror", "sub"}
    for rec in trace_records:
        addr = _get_val(rec, "address", 0)
        # Near dispatcher: within 5 addresses of any dispatcher addr
        near = False
        if not dispatcher_set:
            near = True
        else:
            for d_addr in dispatcher_set:
                if abs(addr - d_addr) <= 32:
                    near = True
                    break
        if not near:
            continue

        disasm = _get_disassembly(rec)
        parts = disasm.strip().split(None, 1)
        if not parts:
            continue
        mnem = parts[0].lower()
        if mnem in _decode_mnem:
            disasm_lower = disasm.lower()
            if any(a in disasm_lower for a in _reg_aliases(reg)):
                count += 1
    return count


def _count_displaced_accesses(
    trace_records: Sequence[Any],
    boundaries: Sequence[Any],
    reg: str,
) -> int:
    """Count memory accesses using *reg* with varying displacements."""
    displacements: Set[str] = set()
    disp_pattern = re.compile(
        r'\[' + re.escape(reg) + r'\s*([+\-]\s*(?:0x)?[0-9a-fA-F]+)\]',
        re.IGNORECASE,
    )

    boundary_ranges: List[Tuple[int, int]] = []
    for b in boundaries:
        s = _get_val(b, "trace_start", 0)
        e = _get_val(b, "trace_end", 0)
        if e > s:
            boundary_ranges.append((s, e))

    for start, end in boundary_ranges[:30]:
        for idx in range(start, min(end, len(trace_records))):
            disasm = _get_disassembly(trace_records[idx])
            m = disp_pattern.search(disasm)
            if m:
                displacements.add(m.group(1).strip())

    return len(displacements)


def _extract_regs_from_transforms(
    decode_transforms: Sequence[str],
) -> Set[str]:
    """Extract register names mentioned in decode transform strings."""
    regs: Set[str] = set()
    all_gp = _GP_REGS_64 | _GP_REGS_32
    for t in decode_transforms:
        words = re.findall(r'\b([a-zA-Z][a-zA-Z0-9]*)\b', t.lower())
        for w in words:
            if w in all_gp:
                regs.add(w)
    return regs


# ═══════════════════════════════════════════════════════════════════════════
# Accessor helpers
# ═══════════════════════════════════════════════════════════════════════════

def _get_registers(rec: Any) -> Dict[str, int]:
    if isinstance(rec, dict):
        return rec.get("registers", {})
    return getattr(rec, "registers", {})


def _get_disassembly(rec: Any) -> str:
    if isinstance(rec, dict):
        return rec.get("disassembly", "")
    return getattr(rec, "disassembly", "")


def _get_val(obj: Any, attr: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return getattr(obj, attr, default)


def _get_final_registers(summary: Any) -> Dict[str, str]:
    if isinstance(summary, dict):
        return summary.get("final_registers", {})
    return getattr(summary, "final_registers", {})
