"""
vIP-Based Handler Boundary Identification
==========================================

Analyses an :class:`~..trace_ingestion.ExecutionTrace` to:

1. **Identify the vIP register** — the native register that acts as the
   virtual instruction pointer, advancing through the VM bytecode.
2. **Segment the trace** into per-handler execution slices based on
   dispatcher returns (the moment control returns to the dispatcher and
   the vIP has changed, a new handler begins).
3. **Produce :class:`HandlerBoundary` records** consumable by the
   bytecode extractor and the dispatcher enrichment path.

Usage::

    from dragonslayer.analysis.vm_discovery.handler_boundaries import (
        identify_vip_register,
        segment_trace,
        HandlerBoundary,
    )

    vip = identify_vip_register(trace, dispatcher_addresses)
    boundaries = segment_trace(trace, vip, dispatcher_addresses)
"""

from __future__ import annotations

import logging
import re as _re
import statistics
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from dragonslayer.analysis.symbolic_execution.executor import HandlerSymbolicSummary
from dragonslayer.analysis.trace_ingestion import (
    ExecutionTrace,
    HandlerMarker,
    TraceInstruction,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data-classes
# ---------------------------------------------------------------------------


@dataclass
class VIPCandidate:
    """Scoring record for a single register suspected of being the vIP."""

    name: str
    score: float = 0.0
    change_count: int = 0
    monotonic_ratio: float = 0.0
    aligned_ratio: float = 0.0
    dispatcher_correlation: float = 0.0
    symbolic_score: float = 0.0
    detail: str = ""


@dataclass
class HandlerSlice:
    """A contiguous slice of trace instructions belonging to one handler
    execution."""

    start_index: int
    end_index: int  # exclusive
    instructions: list[TraceInstruction] = field(default_factory=list)

    @property
    def address_range(self) -> tuple[int, int]:
        """``(first_address, last_address)`` of instructions in this slice."""
        if not self.instructions:
            return (0, 0)
        return (self.instructions[0].address, self.instructions[-1].address)


@dataclass
class HandlerBoundary:
    """Describes one VM handler invocation observed in a trace.

    Attributes:
        vip_value: The virtual instruction pointer value when this handler
            was dispatched.
        handler_address: Native address where the handler begins.
        trace_start: Index into ``ExecutionTrace.instructions``.
        trace_end: Exclusive end index.
        instruction_count: Number of native instructions in the handler.
        category: Optional category label (arithmetic, memory, …).
        vip_delta: Change in vIP after this handler completes (i.e. the
            width of the VM bytecode consumed).
        handler_id: Opaque handler identifier (matches ``HandlerMarker``
            ids when available).
    """

    vip_value: int
    handler_address: int
    trace_start: int
    trace_end: int
    instruction_count: int
    category: str = ""
    vip_delta: int = 0
    handler_id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialise the handler boundary to a JSON-compatible dict."""
        return {
            "vip_value": self.vip_value,
            "handler_address": hex(self.handler_address),
            "trace_start": self.trace_start,
            "trace_end": self.trace_end,
            "instruction_count": self.instruction_count,
            "category": self.category,
            "vip_delta": self.vip_delta,
            "handler_id": self.handler_id,
        }


@dataclass
class SegmentationResult:
    """Output of :func:`segment_trace`."""

    vip_register: str
    boundaries: list[HandlerBoundary] = field(default_factory=list)
    dispatcher_visits: int = 0
    unique_handlers: int = 0
    bytecode_width_mode: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialise the segmentation result to a JSON-compatible dict."""
        return {
            "vip_register": self.vip_register,
            "boundary_count": len(self.boundaries),
            "dispatcher_visits": self.dispatcher_visits,
            "unique_handlers": self.unique_handlers,
            "bytecode_width_mode": self.bytecode_width_mode,
            "boundaries": [b.to_dict() for b in self.boundaries],
        }


# ---------------------------------------------------------------------------
# vIP register identification
# ---------------------------------------------------------------------------

# Registers commonly used as vIP in known VM protectors.
_VIP_LIKELY = {"esi", "rsi", "edi", "rdi", "ebp", "rbp", "ebx", "rbx"}
_GP_REGS_32 = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}
_GP_REGS_64 = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}


def identify_vip_register(
    trace: ExecutionTrace,
    dispatcher_addresses: Sequence[int] = (),
    *,
    candidates: Sequence[str] | None = None,
    symbolic_summaries: Sequence[HandlerSymbolicSummary] | None = None,
) -> VIPCandidate | None:
    """Heuristically identify which native register acts as the vIP.

    Algorithm overview:

    1. For each general-purpose register visible in the trace, compute
       how many times its value **changes monotonically** across
       consecutive steps where the instruction address is inside the
       dispatcher (i.e. the dispatcher reads the next vIP).
    2. Score registers by:
       - **Monotonic-advance ratio** (values increase/decrease steadily)
       - **Alignment** (vIP often changes by fixed amounts: 1, 2, 4, 8)
       - **Dispatcher-correlation** (changes occur near dispatcher addr)
       - **Prior weight** (known vIP registers get a bonus)
       - **Symbolic self-advance** (optional; from handler summaries)
    3. Return the :class:`VIPCandidate` with the highest score, or
       ``None`` if the trace has insufficient register data.

    Args:
        trace: An ExecutionTrace with register snapshots.
        dispatcher_addresses: Known dispatcher native addresses.
        candidates: Optional list of register names to consider.
        symbolic_summaries: Optional handler symbolic summaries from
            :meth:`SymbolicExecutor.execute_handler`.  When provided,
            the symbolic self-advance score is blended into the
            composite (weight 0.30).
    """
    if not trace.instructions:
        return None

    # Determine which registers to evaluate.
    all_regs: set[str] = set()
    for ti in trace.instructions:
        if ti.registers:
            all_regs.update(ti.registers.keys())
    if not all_regs:
        return None

    gp_regs = all_regs & (_GP_REGS_32 | _GP_REGS_64)
    # Remove stack pointer — never the vIP.
    gp_regs -= {"esp", "rsp"}

    if candidates:
        gp_regs = gp_regs & set(candidates)
    if not gp_regs:
        return None

    disp_set = set(dispatcher_addresses)

    # Registers used as the *base* of a memory operand at a dispatcher
    # address — i.e. the pointer dereferenced to fetch the opcode.  The vIP
    # is by definition such a pointer; a data register (accumulator) is not.
    # This disambiguates the vIP from a register that merely happens to
    # advance monotonically (e.g. an accumulator in a loop-free program, or
    # one that out-scores a non-monotonic vIP across a virtual loop).
    fetch_bases = _fetch_base_registers(trace.instructions, disp_set)

    # Pre-compute symbolic scores if summaries are provided.
    sym_scores: dict[str, float] = {}
    if symbolic_summaries:
        sym_scores = score_vip_from_symbolic(
            symbolic_summaries, candidates=candidates,
        )

    results: list[VIPCandidate] = []
    for reg in sorted(gp_regs):
        cand = _score_register(
            trace.instructions, reg, disp_set,
            symbolic_bonus=sym_scores.get(reg.lower(), 0.0),
            is_fetch_base=reg.lower() in fetch_bases,
        )
        if cand is not None:
            results.append(cand)

    if not results:
        return None

    results.sort(key=lambda c: c.score, reverse=True)
    best = results[0]
    if best.score < 0.1:
        logger.debug("No register scored above threshold; best=%s (%.3f)",
                      best.name, best.score)
        return None
    logger.info("vIP register identified: %s (score=%.3f)", best.name,
                best.score)
    return best


_MEM_OPERAND_RE = _re.compile(r"\[([^\]]+)\]")
_REG_TOKEN_RE = _re.compile(r"[a-z][a-z0-9]+")


def _fetch_base_registers(
    instructions: list[TraceInstruction],
    dispatcher_addrs: set[int],
) -> set[str]:
    """Registers used as a memory *base* at any dispatcher address.

    Parses ``[...]`` memory operands of instructions executed at a dispatcher
    address and returns the base registers (the first additive term that is
    not a scaled index like ``rax*8``).  These are the pointers the
    dispatcher dereferences — the vIP is one of them.
    """
    bases: set[str] = set()
    if not dispatcher_addrs:
        return bases
    for ti in instructions:
        if ti.address not in dispatcher_addrs:
            continue
        disasm = (ti.disassembly or "").lower()
        for inner in _MEM_OPERAND_RE.findall(disasm):
            for term in inner.split("+"):
                term = term.strip()
                if "*" in term:          # scaled index (e.g. rax*8), not base
                    continue
                m = _REG_TOKEN_RE.match(term)
                if m:
                    bases.add(m.group(0))
                    break  # first non-index term is the base
    return bases


def _score_register(
    instructions: list[TraceInstruction],
    reg: str,
    dispatcher_addrs: set[int],
    *,
    symbolic_bonus: float = 0.0,
    is_fetch_base: bool = False,
) -> VIPCandidate | None:
    """Score a single register as vIP candidate."""

    values: list[tuple[int, int]] = []  # (trace_index, value)
    for idx, ti in enumerate(instructions):
        if reg in (ti.registers or {}):
            values.append((idx, ti.registers[reg]))

    if len(values) < 3:
        return None

    # ---- monotonic ratio ------------------------------------------------
    diffs = [values[i + 1][1] - values[i][1] for i in range(len(values) - 1)]
    non_zero = [d for d in diffs if d != 0]
    if not non_zero:
        return VIPCandidate(name=reg, detail="constant")

    pos = sum(1 for d in non_zero if d > 0)
    neg = sum(1 for d in non_zero if d < 0)
    mono_ratio = max(pos, neg) / len(non_zero)

    # ---- change count ---------------------------------------------------
    change_count = len(non_zero)

    # ---- alignment (common bytecode widths) -----------------------------
    abs_diffs = [abs(d) for d in non_zero]
    common_widths = {1, 2, 3, 4, 5, 6, 8}
    aligned = sum(1 for d in abs_diffs if d in common_widths)
    aligned_ratio = aligned / len(abs_diffs) if abs_diffs else 0.0

    # ---- dispatcher correlation -----------------------------------------
    disp_corr = 0.0
    if dispatcher_addrs and change_count > 0:
        near_disp = 0
        for i in range(len(values) - 1):
            if diffs[i] != 0:
                trace_idx = values[i + 1][0]
                # Check if any instruction within ±3 steps is at a dispatcher addr.
                for offset in range(-3, 4):
                    check = trace_idx + offset
                    if (
                        0 <= check < len(instructions)
                        and instructions[check].address in dispatcher_addrs
                    ):
                        near_disp += 1
                        break
        disp_corr = near_disp / change_count

    # ---- prior weight ---------------------------------------------------
    prior = 1.2 if reg.lower() in _VIP_LIKELY else 1.0

    # ---- composite score ------------------------------------------------
    # When symbolic evidence is available, blend it in (weight 0.30)
    # and scale the trace-based factors down proportionally.
    if symbolic_bonus > 0:
        score = (
            0.25 * mono_ratio
            + 0.18 * aligned_ratio
            + 0.17 * disp_corr
            + 0.10 * min(change_count / max(len(instructions) * 0.1, 1), 1.0)
            + 0.30 * symbolic_bonus
        ) * prior
    else:
        score = (
            0.35 * mono_ratio
            + 0.25 * aligned_ratio
            + 0.25 * disp_corr
            + 0.15 * min(change_count / max(len(instructions) * 0.1, 1), 1.0)
        ) * prior

    # The register dereferenced to fetch the opcode at the dispatcher is the
    # vIP (a pointer), not an accumulator.  Additive bonus so it only *raises*
    # a fetch pointer — decisive when a non-monotonic vIP (virtual loop) would
    # otherwise lose to a monotonically-advancing data register.
    if is_fetch_base:
        score += 0.30

    return VIPCandidate(
        name=reg,
        score=round(score, 4),
        change_count=change_count,
        monotonic_ratio=round(mono_ratio, 4),
        aligned_ratio=round(aligned_ratio, 4),
        dispatcher_correlation=round(disp_corr, 4),
        symbolic_score=round(symbolic_bonus, 4),
        detail=f"diffs_mode={_safe_mode(abs_diffs)}",
    )


def _safe_mode(values: list[int]) -> int:
    """Return the statistical mode, or 0 on failure."""
    if not values:
        return 0
    try:
        return statistics.mode(values)
    except statistics.StatisticsError:
        counter = Counter(values)
        return counter.most_common(1)[0][0]


# ---------------------------------------------------------------------------
# Symbolic vIP identification
# ---------------------------------------------------------------------------

# Pattern to extract ``in_{register}`` symbolic input names from
# HandlerSymbolicSummary.final_registers expressions.
_IN_REG_RE = _re.compile(r"\bin_(\w+)\b")


def score_vip_from_symbolic(
    summaries: Sequence[HandlerSymbolicSummary],
    *,
    candidates: Sequence[str] | None = None,
) -> dict[str, float]:
    """Score registers as vIP candidates using symbolic handler summaries.

    For each handler summary, the function inspects *final_registers* for
    registers whose final expression references exactly one ``in_{reg}``
    input symbol via an arithmetic advance pattern (e.g. ``in_rsi + 4``).
    The intuition is that the vIP register is typically the **only** input
    symbol that appears in its own output expression as a simple additive
    update (``vIP_out = vIP_in + delta``).

    Additionally, if a register's final expression appears inside other
    registers' expressions (suggesting it's used as a memory address or
    branch target), it gets a bonus.

    Args:
        summaries: One or more :class:`HandlerSymbolicSummary` from
            symbolic execution of handlers.
        candidates: If given, only score these register names.

    Returns:
        A dict mapping register name → [0.0, 1.0] score.
    """
    if not summaries:
        return {}

    # Counters across all summaries.
    self_advance_count: dict[str, int] = defaultdict(int)
    total_appearances: dict[str, int] = defaultdict(int)
    referenced_by_others: dict[str, int] = defaultdict(int)
    handler_count = 0

    for summary in summaries:
        if summary.error or not summary.final_registers:
            continue
        handler_count += 1

        # Collect all in_{reg} mentions per output register.
        reg_inputs: dict[str, set[str]] = {}
        for out_reg, expr_str in summary.final_registers.items():
            mentions = set(_IN_REG_RE.findall(expr_str))
            reg_inputs[out_reg] = mentions
            for m in mentions:
                total_appearances[m] += 1

        # Check self-advance: out_reg expression mentions in_{out_reg}
        # and ideally not many other in_ symbols (simple update).
        for out_reg, mentions in reg_inputs.items():
            canonical = out_reg.lower()
            if canonical in mentions and len(mentions) <= 2:
                self_advance_count[canonical] += 1

        # Check cross-reference: does in_{reg} appear in other regs'
        # expressions?  That suggests it's used as a pointer/index.
        for out_reg, mentions in reg_inputs.items():
            canonical = out_reg.lower()
            for m in mentions:
                if m != canonical:
                    referenced_by_others[m] += 1

    if handler_count == 0:
        return {}

    # Build scores.
    all_regs = set(self_advance_count) | set(total_appearances)
    if candidates:
        all_regs &= {c.lower() for c in candidates}

    scores: dict[str, float] = {}
    for reg in all_regs:
        # Self-advance ratio: how often does this register update itself?
        sa = self_advance_count.get(reg, 0) / handler_count

        # Cross-reference ratio: how often do other regs depend on this one?
        cr = min(referenced_by_others.get(reg, 0) / max(handler_count, 1), 1.0)

        # Combine: self-advance is the strongest signal, cross-ref is secondary.
        score = 0.60 * sa + 0.40 * cr
        scores[reg] = round(score, 4)

    return scores


# ---------------------------------------------------------------------------
# Trace segmentation
# ---------------------------------------------------------------------------

def segment_trace(
    trace: ExecutionTrace,
    vip: VIPCandidate,
    dispatcher_addresses: Sequence[int] = (),
    *,
    min_handler_insns: int = 2,
) -> SegmentationResult:
    """Split an execution trace into per-handler slices.

    The segmentation strategy:

    1. Walk the trace linearly looking for instructions whose address
       matches a known dispatcher address.  When we enter the dispatcher,
       read the vIP register.
    2. When we *leave* the dispatcher (next instruction address is not in
       the dispatcher set), we have entered a handler.  Record the
       current vIP value and the handler start index.
    3. When we return to the dispatcher we close the current handler
       slice.
    4. If no dispatcher addresses are known, fall back to detecting
       vIP register changes as handler boundaries (less precise but
       still useful for purely trace-based analysis).

    Args:
        trace: Execution trace to segment.
        vip: The identified vIP register.
        dispatcher_addresses: Native addresses belonging to the dispatcher.
        min_handler_insns: Minimum number of instructions for a valid
            handler (filters noise).

    Returns:
        A :class:`SegmentationResult` with the handler boundary list.
    """
    if not trace.instructions:
        return SegmentationResult(vip_register=vip.name)

    disp_set = set(dispatcher_addresses)

    if disp_set:
        boundaries = _segment_by_dispatcher(
            trace.instructions, vip.name, disp_set, min_handler_insns,
        )
    else:
        boundaries = _segment_by_vip_changes(
            trace.instructions, vip.name, min_handler_insns,
        )

    # Enrich with existing handler markers.
    _apply_handler_markers(boundaries, trace.handlers)

    # Compute bytecode width mode.
    deltas = [b.vip_delta for b in boundaries if b.vip_delta != 0]
    bw_mode = _safe_mode([abs(d) for d in deltas]) if deltas else 0

    unique = len({b.handler_address for b in boundaries})

    return SegmentationResult(
        vip_register=vip.name,
        boundaries=boundaries,
        dispatcher_visits=len(boundaries) + 1,  # N handlers → N+1 visits
        unique_handlers=unique,
        bytecode_width_mode=bw_mode,
    )


def _segment_by_dispatcher(
    instructions: list[TraceInstruction],
    vip_reg: str,
    disp_set: set[int],
    min_insns: int,
) -> list[HandlerBoundary]:
    """Segment using dispatcher address knowledge."""

    boundaries: list[HandlerBoundary] = []
    in_dispatcher = False
    current_vip: int | None = None
    handler_start: int | None = None
    prev_vip: int | None = None

    for idx, ti in enumerate(instructions):
        at_disp = ti.address in disp_set

        if at_disp:
            # Read vIP whenever we are in the dispatcher.
            if vip_reg in (ti.registers or {}):
                current_vip = ti.registers[vip_reg]

            if not in_dispatcher and handler_start is not None:
                # We just returned to the dispatcher — close the handler.
                handler_insns = instructions[handler_start:idx]
                if len(handler_insns) >= min_insns:
                    delta = 0
                    if prev_vip is not None and current_vip is not None:
                        delta = current_vip - prev_vip
                    boundaries.append(HandlerBoundary(
                        vip_value=prev_vip or 0,
                        handler_address=handler_insns[0].address,
                        trace_start=handler_start,
                        trace_end=idx,
                        instruction_count=len(handler_insns),
                        vip_delta=delta,
                    ))
                handler_start = None

            in_dispatcher = True
        else:
            if in_dispatcher:
                # Leaving the dispatcher — entering a handler.
                prev_vip = current_vip
                handler_start = idx
            in_dispatcher = False

    # Close a trailing handler if trace ends inside one.
    if handler_start is not None:
        handler_insns = instructions[handler_start:]
        if len(handler_insns) >= min_insns:
            boundaries.append(HandlerBoundary(
                vip_value=prev_vip or 0,
                handler_address=handler_insns[0].address,
                trace_start=handler_start,
                trace_end=len(instructions),
                instruction_count=len(handler_insns),
                vip_delta=0,
            ))

    return boundaries


def _segment_by_vip_changes(
    instructions: list[TraceInstruction],
    vip_reg: str,
    min_insns: int,
) -> list[HandlerBoundary]:
    """Fallback segmentation when dispatcher addresses are unknown.

    Cuts the trace at every point where the vIP register changes.  Each
    segment between two consecutive vIP changes is treated as a handler.
    """

    boundaries: list[HandlerBoundary] = []
    prev_vip: int | None = None
    seg_start: int = 0

    for idx, ti in enumerate(instructions):
        vip_val = (ti.registers or {}).get(vip_reg)
        if vip_val is None:
            continue

        if prev_vip is not None and vip_val != prev_vip:
            # vIP changed — close previous segment.
            seg_insns = instructions[seg_start:idx]
            if len(seg_insns) >= min_insns:
                boundaries.append(HandlerBoundary(
                    vip_value=prev_vip,
                    handler_address=seg_insns[0].address,
                    trace_start=seg_start,
                    trace_end=idx,
                    instruction_count=len(seg_insns),
                    vip_delta=vip_val - prev_vip,
                ))
            seg_start = idx

        prev_vip = vip_val

    # Final segment.
    if prev_vip is not None:
        seg_insns = instructions[seg_start:]
        if len(seg_insns) >= min_insns:
            boundaries.append(HandlerBoundary(
                vip_value=prev_vip,
                handler_address=seg_insns[0].address,
                trace_start=seg_start,
                trace_end=len(instructions),
                instruction_count=len(seg_insns),
                vip_delta=0,
            ))

    return boundaries


def _apply_handler_markers(
    boundaries: list[HandlerBoundary],
    markers: list[HandlerMarker],
) -> None:
    """Enrich boundaries with handler markers (id/category) when the
    marker address falls within the boundary address range."""

    if not markers:
        return

    marker_by_addr: dict[int, HandlerMarker] = {
        m.address: m for m in markers
    }

    for boundary in boundaries:
        m = marker_by_addr.get(boundary.handler_address)
        if m is not None:
            boundary.handler_id = m.handler_id
            if m.handler_type:
                boundary.category = m.handler_type
