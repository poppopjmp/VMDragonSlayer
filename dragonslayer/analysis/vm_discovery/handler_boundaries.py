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
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Sequence, Tuple

from dragonslayer.analysis.trace_ingestion import (
    ExecutionTrace,
    TraceInstruction,
    HandlerMarker,
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
    detail: str = ""


@dataclass
class HandlerSlice:
    """A contiguous slice of trace instructions belonging to one handler
    execution."""

    start_index: int
    end_index: int  # exclusive
    instructions: List[TraceInstruction] = field(default_factory=list)

    @property
    def address_range(self) -> Tuple[int, int]:
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
    handler_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
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
    boundaries: List[HandlerBoundary] = field(default_factory=list)
    dispatcher_visits: int = 0
    unique_handlers: int = 0
    bytecode_width_mode: int = 0

    def to_dict(self) -> Dict[str, Any]:
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
    candidates: Optional[Sequence[str]] = None,
) -> Optional[VIPCandidate]:
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
    3. Return the :class:`VIPCandidate` with the highest score, or
       ``None`` if the trace has insufficient register data.

    Args:
        trace: An ExecutionTrace with register snapshots.
        dispatcher_addresses: Known dispatcher native addresses.
        candidates: Optional list of register names to consider.
    """
    if not trace.instructions:
        return None

    # Determine which registers to evaluate.
    all_regs: Set[str] = set()
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

    results: List[VIPCandidate] = []
    for reg in sorted(gp_regs):
        cand = _score_register(trace.instructions, reg, disp_set)
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


def _score_register(
    instructions: List[TraceInstruction],
    reg: str,
    dispatcher_addrs: Set[int],
) -> Optional[VIPCandidate]:
    """Score a single register as vIP candidate."""

    values: List[Tuple[int, int]] = []  # (trace_index, value)
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
                    if 0 <= check < len(instructions):
                        if instructions[check].address in dispatcher_addrs:
                            near_disp += 1
                            break
        disp_corr = near_disp / change_count

    # ---- prior weight ---------------------------------------------------
    prior = 1.2 if reg.lower() in _VIP_LIKELY else 1.0

    # ---- composite score ------------------------------------------------
    score = (
        0.35 * mono_ratio
        + 0.25 * aligned_ratio
        + 0.25 * disp_corr
        + 0.15 * min(change_count / max(len(instructions) * 0.1, 1), 1.0)
    ) * prior

    return VIPCandidate(
        name=reg,
        score=round(score, 4),
        change_count=change_count,
        monotonic_ratio=round(mono_ratio, 4),
        aligned_ratio=round(aligned_ratio, 4),
        dispatcher_correlation=round(disp_corr, 4),
        detail=f"diffs_mode={_safe_mode(abs_diffs)}",
    )


def _safe_mode(values: List[int]) -> int:
    """Return the statistical mode, or 0 on failure."""
    if not values:
        return 0
    try:
        return statistics.mode(values)
    except statistics.StatisticsError:
        counter = Counter(values)
        return counter.most_common(1)[0][0]


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
    instructions: List[TraceInstruction],
    vip_reg: str,
    disp_set: Set[int],
    min_insns: int,
) -> List[HandlerBoundary]:
    """Segment using dispatcher address knowledge."""

    boundaries: List[HandlerBoundary] = []
    in_dispatcher = False
    current_vip: Optional[int] = None
    handler_start: Optional[int] = None
    prev_vip: Optional[int] = None

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
    instructions: List[TraceInstruction],
    vip_reg: str,
    min_insns: int,
) -> List[HandlerBoundary]:
    """Fallback segmentation when dispatcher addresses are unknown.

    Cuts the trace at every point where the vIP register changes.  Each
    segment between two consecutive vIP changes is treated as a handler.
    """

    boundaries: List[HandlerBoundary] = []
    prev_vip: Optional[int] = None
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
    boundaries: List[HandlerBoundary],
    markers: List[HandlerMarker],
) -> None:
    """Enrich boundaries with handler markers (id/category) when the
    marker address falls within the boundary address range."""

    if not markers:
        return

    marker_by_addr: Dict[int, HandlerMarker] = {
        m.address: m for m in markers
    }

    for boundary in boundaries:
        m = marker_by_addr.get(boundary.handler_address)
        if m is not None:
            boundary.handler_id = m.handler_id
            if m.handler_type:
                boundary.category = m.handler_type
