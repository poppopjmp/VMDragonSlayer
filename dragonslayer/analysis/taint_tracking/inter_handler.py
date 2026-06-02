"""
Inter-Handler Data-Flow Analysis (B46)
=======================================

Builds per-handler def/use summaries from symbolic execution results
and propagates taint across handler boundaries via fixed-point
iteration.  Enables slicing queries such as "which handlers
contribute to the final value of vSP?" and inter-handler dependency
graphs.

This module bridges the symbolic execution module (per-handler
:class:`HandlerSymbolicSummary`) with the taint tracking module,
enabling cross-handler taint propagation without re-executing the
full instruction stream.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any


# Late import to avoid circular dependency
def _get_taint_tag() -> Any:
    from .tracker import TaintTag
    return TaintTag

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class HandlerTaintSummary:
    """Per-handler summary of register/memory defs and uses.

    Attributes
    ----------
    handler_id : int
        Handler address or index.
    defs : set of str
        Registers (canonical names) defined (written) by this handler.
    uses : set of str
        Registers read by this handler *before* any local def.
    memory_defs : set of str
        Memory regions written (e.g. ``"stack"``, ``"vm_context"``).
    memory_uses : set of str
        Memory regions read.
    taint_in : set of str
        Tainted registers at handler entry (populated by propagation).
    taint_out : set of str
        Tainted registers at handler exit (populated by propagation).
    kill : set of str
        Registers unconditionally overwritten (kill set for reaching-defs).
    """
    handler_id: int = 0
    defs: set[str] = field(default_factory=set)
    uses: set[str] = field(default_factory=set)
    memory_defs: set[str] = field(default_factory=set)
    memory_uses: set[str] = field(default_factory=set)
    taint_in: set[str] = field(default_factory=set)
    taint_out: set[str] = field(default_factory=set)
    kill: set[str] = field(default_factory=set)

    # B55: Tag-aware fields — map register → TaintTag (IntFlag)
    tag_in: dict[str, Any] = field(default_factory=dict)
    tag_out: dict[str, Any] = field(default_factory=dict)
    # Transfer function: input_reg → set of output_regs it influences
    transfer: dict[str, set[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise the handler taint summary to a JSON-compatible dict."""
        return {
            "handler_id": self.handler_id,
            "defs": sorted(self.defs),
            "uses": sorted(self.uses),
            "memory_defs": sorted(self.memory_defs),
            "memory_uses": sorted(self.memory_uses),
            "taint_in": sorted(self.taint_in),
            "taint_out": sorted(self.taint_out),
            "kill": sorted(self.kill),
            "tag_in": {k: int(v) for k, v in self.tag_in.items()},
            "tag_out": {k: int(v) for k, v in self.tag_out.items()},
        }


@dataclass
class InterHandlerFlowEdge:
    """An edge in the inter-handler data-flow graph.

    Represents the fact that *register* is live from *source* to *target*.
    """
    source: int  # handler_id
    target: int  # handler_id
    register: str
    via_memory: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialise the flow edge to a JSON-compatible dict."""
        return {
            "source": self.source,
            "target": self.target,
            "register": self.register,
            "via_memory": self.via_memory,
        }


@dataclass
class InterHandlerFlowResult:
    """Complete inter-handler data-flow analysis result."""
    summaries: list[HandlerTaintSummary] = field(default_factory=list)
    edges: list[InterHandlerFlowEdge] = field(default_factory=list)
    iterations: int = 0
    converged: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialise the inter-handler flow result to a JSON-compatible dict."""
        return {
            "summary_count": len(self.summaries),
            "summaries": [s.to_dict() for s in self.summaries],
            "edge_count": len(self.edges),
            "edges": [e.to_dict() for e in self.edges],
            "iterations": self.iterations,
            "converged": self.converged,
        }


# ---------------------------------------------------------------------------
# Canonical register normalisation
# ---------------------------------------------------------------------------

_CANONICAL_GP = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
}

_SUBREG_TO_CANONICAL: dict[str, str] = {}


def _build_subreg_map() -> None:
    """Populate _SUBREG_TO_CANONICAL lazily."""
    if _SUBREG_TO_CANONICAL:
        return
    for canon in _CANONICAL_GP:
        _SUBREG_TO_CANONICAL[canon] = canon
    # 32-bit versions
    for c in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"):
        _SUBREG_TO_CANONICAL["e" + c[1:]] = c
    for i in range(8, 16):
        _SUBREG_TO_CANONICAL[f"r{i}d"] = f"r{i}"
    # 16-bit
    _SUBREG_TO_CANONICAL["ax"] = "rax"
    _SUBREG_TO_CANONICAL["bx"] = "rbx"
    _SUBREG_TO_CANONICAL["cx"] = "rcx"
    _SUBREG_TO_CANONICAL["dx"] = "rdx"
    _SUBREG_TO_CANONICAL["si"] = "rsi"
    _SUBREG_TO_CANONICAL["di"] = "rdi"
    _SUBREG_TO_CANONICAL["bp"] = "rbp"
    _SUBREG_TO_CANONICAL["sp"] = "rsp"
    # 8-bit
    for name, canon in [("al", "rax"), ("ah", "rax"), ("bl", "rbx"),
                         ("bh", "rbx"), ("cl", "rcx"), ("ch", "rcx"),
                         ("dl", "rdx"), ("dh", "rdx"), ("sil", "rsi"),
                         ("dil", "rdi"), ("bpl", "rbp"), ("spl", "rsp")]:
        _SUBREG_TO_CANONICAL[name] = canon
    for i in range(8, 16):
        _SUBREG_TO_CANONICAL[f"r{i}b"] = f"r{i}"
        _SUBREG_TO_CANONICAL[f"r{i}w"] = f"r{i}"


def canonicalize_reg(name: str) -> str:
    """Map any x86-64 register name to its canonical 64-bit form."""
    _build_subreg_map()
    return _SUBREG_TO_CANONICAL.get(name.lower(), name.lower())


# ---------------------------------------------------------------------------
# Summary builder
# ---------------------------------------------------------------------------

def build_handler_summary(
    handler_id: int,
    *,
    symbolic_summary: dict[str, Any] | None = None,
    instructions: list | None = None,
) -> HandlerTaintSummary:
    """Build a :class:`HandlerTaintSummary` from a symbolic summary or
    raw instruction list.

    Parameters
    ----------
    handler_id : int
        Handler address or ordinal.
    symbolic_summary : dict or None
        Output of :meth:`HandlerSymbolicSummary.to_dict` (preferred).
    instructions : list or None
        Fallback: list of instruction dicts with ``reads``/``writes``.
    """
    summary = HandlerTaintSummary(handler_id=handler_id)

    if symbolic_summary is not None:
        _extract_from_symbolic(summary, symbolic_summary)
    elif instructions is not None:
        _extract_from_instructions(summary, instructions)

    # Kill set = defs that are unconditional (all defs for now).
    summary.kill = set(summary.defs)

    # B55: Build default transfer function (uses → defs)
    # Conservative: every use influences every def
    if summary.uses and summary.defs:
        for use_reg in summary.uses:
            summary.transfer[use_reg] = set(summary.defs)

    return summary


def _extract_from_symbolic(
    out: HandlerTaintSummary,
    sym: dict[str, Any],
) -> None:
    """Extract defs/uses from a HandlerSymbolicSummary dict."""
    # Final registers that differ from their initial symbol → defs
    for reg, _expr_str in sym.get("final_registers", {}).items():
        canon = canonicalize_reg(reg)
        if canon in _CANONICAL_GP:
            out.defs.add(canon)
    for reg, _expr_str in sym.get("simplified_registers", {}).items():
        canon = canonicalize_reg(reg)
        if canon in _CANONICAL_GP:
            out.defs.add(canon)

    # Input symbols referenced → uses
    for sym_name in sym.get("input_symbols", {}):
        # Symbol names are like "init_rax" → extract register
        if sym_name.startswith("init_"):
            canon = canonicalize_reg(sym_name[5:])
            if canon in _CANONICAL_GP:
                out.uses.add(canon)

    # Memory effects
    effects = sym.get("memory_effects", {})
    for entry in effects.get("loads", []):
        region = entry.get("region")
        if region:
            out.memory_uses.add(region)
    for entry in effects.get("stores", []):
        region = entry.get("region")
        if region:
            out.memory_defs.add(region)


def _extract_from_instructions(
    out: HandlerTaintSummary,
    instructions: list,
) -> None:
    """Extract defs/uses from raw instruction dicts (fallback path)."""
    local_defs: set[str] = set()
    for insn in instructions:
        reads = insn.get("reads", [])
        writes = insn.get("writes", [])
        if hasattr(insn, "reads"):
            reads = insn.reads
        if hasattr(insn, "writes"):
            writes = insn.writes

        for r in reads:
            canon = canonicalize_reg(r)
            if canon in _CANONICAL_GP and canon not in local_defs:
                out.uses.add(canon)
        for w in writes:
            canon = canonicalize_reg(w)
            if canon in _CANONICAL_GP:
                out.defs.add(canon)
                local_defs.add(canon)


# ---------------------------------------------------------------------------
# Inter-handler data-flow engine
# ---------------------------------------------------------------------------

class InterHandlerDataFlow:
    """Fixed-point inter-handler taint propagation.

    Given an ordered list of :class:`HandlerTaintSummary` (in
    execution order), propagates taint forward: a register tainted
    at handler *i*'s exit is tainted at handler *i+1*'s entry unless
    handler *i+1* kills it.

    Usage::

        flow = InterHandlerDataFlow()
        result = flow.propagate(summaries, initial_taint={"rsi", "rbp"})
    """

    MAX_ITERATIONS = 50

    def propagate(
        self,
        summaries: list[HandlerTaintSummary],
        *,
        initial_taint: set[str] | None = None,
    ) -> InterHandlerFlowResult:
        """Run fixed-point taint propagation across the handler chain.

        Parameters
        ----------
        summaries : list of HandlerTaintSummary
            Ordered handler summaries.
        initial_taint : set of str or None
            Registers tainted at the very start (e.g. VM context regs).

        Returns
        -------
        InterHandlerFlowResult
        """
        if not summaries:
            return InterHandlerFlowResult(converged=True)

        # Initialise taint_in for the first handler.
        if initial_taint:
            summaries[0].taint_in = set(initial_taint)

        converged = False
        iterations = 0

        for _ in range(self.MAX_ITERATIONS):
            iterations += 1
            changed = False

            for idx, s in enumerate(summaries):
                # taint_out = (taint_in - kill) | {defs that use tainted inputs}
                new_out = set(s.taint_in) - s.kill
                # Defs that consume a tainted use propagate taint forward.
                tainted_uses = s.uses & s.taint_in
                if tainted_uses:
                    new_out |= s.defs  # conservative: if any input tainted, output tainted

                if new_out != s.taint_out:
                    s.taint_out = new_out
                    changed = True

                # Propagate to next handler's taint_in.
                if idx + 1 < len(summaries):
                    next_in = set(summaries[idx + 1].taint_in) | new_out
                    if next_in != summaries[idx + 1].taint_in:
                        summaries[idx + 1].taint_in = next_in
                        changed = True

            if not changed:
                converged = True
                break

        # Build flow edges.
        edges = self._build_edges(summaries)

        return InterHandlerFlowResult(
            summaries=summaries,
            edges=edges,
            iterations=iterations,
            converged=converged,
        )

    @staticmethod
    def _build_edges(
        summaries: list[HandlerTaintSummary],
    ) -> list[InterHandlerFlowEdge]:
        """Build inter-handler flow edges from propagation results."""
        edges: list[InterHandlerFlowEdge] = []
        for i in range(len(summaries) - 1):
            src = summaries[i]
            dst = summaries[i + 1]
            # A register flows from src to dst if:
            # - src defines it AND dst uses it AND it's in dst.taint_in
            live_regs = src.defs & dst.uses & dst.taint_in
            for reg in sorted(live_regs):
                edges.append(InterHandlerFlowEdge(
                    source=src.handler_id,
                    target=dst.handler_id,
                    register=reg,
                ))
            # Memory-mediated flow: src writes a region that dst reads.
            shared_regions = src.memory_defs & dst.memory_uses
            for region in sorted(shared_regions):
                edges.append(InterHandlerFlowEdge(
                    source=src.handler_id,
                    target=dst.handler_id,
                    register=f"mem:{region}",
                    via_memory=True,
                ))
        return edges

    def compute_taint_slice(
        self,
        summaries: list[HandlerTaintSummary],
        target_reg: str,
    ) -> list[int]:
        """Backward slice: find all handler IDs that contribute to *target_reg*.

        Walks the summary chain backwards from the last handler to the
        first, collecting handlers whose defs reach the target register.

        Parameters
        ----------
        summaries : list of HandlerTaintSummary
            Already-propagated summaries.
        target_reg : str
            Canonical register name to slice for.

        Returns
        -------
        list of int
            Handler IDs (in reverse order) that contribute to *target_reg*.
        """
        target = canonicalize_reg(target_reg)
        needed: set[str] = {target}
        contributing: list[int] = []

        for s in reversed(summaries):
            if s.defs & needed:
                contributing.append(s.handler_id)
                # The handler's uses become new requirements.
                needed = (needed - s.defs) | s.uses

        return contributing

    def backward_propagate(
        self,
        summaries: list[HandlerTaintSummary],
        *,
        target_reg: str,
        target_tag: Any | None = None,
    ) -> dict[str, Any]:
        """Backward tag-aware taint propagation (B55).

        Starting from *target_reg* (optionally limited to *target_tag*)
        at the last handler, propagate demands backward through the
        handler chain using each summary's transfer function.

        Parameters
        ----------
        summaries : list of HandlerTaintSummary
            Ordered summaries (already forward-propagated or not).
        target_reg : str
            Canonical register to trace backward.
        target_tag : TaintTag or None
            If given, restrict to this specific tag combination.

        Returns
        -------
        dict
            ``{"required_inputs": {reg: tag, ...},
               "contributing_handlers": [handler_id, ...],
               "demand_chain": [(handler_id, {reg: tag}), ...]}``
        """
        TaintTag = _get_taint_tag()
        target = canonicalize_reg(target_reg)

        if target_tag is None:
            target_tag = TaintTag.COMPUTED | TaintTag.INPUT

        # demand: registers whose taint we need to explain
        demand: dict[str, Any] = {target: target_tag}
        contributing: list[int] = []
        demand_chain: list[tuple] = []

        for s in reversed(summaries):
            produced = s.defs & set(demand.keys())
            if not produced:
                continue

            contributing.append(s.handler_id)
            snapshot: dict[str, Any] = {}

            new_demand: dict[str, Any] = {}
            for d_reg in produced:
                d_tag = demand.pop(d_reg)
                # This handler defines d_reg; its inputs (uses) caused it
                for u_reg in s.uses:
                    # If transfer function is available, use it
                    if u_reg in s.transfer and d_reg in s.transfer[u_reg]:
                        combined = new_demand.get(u_reg, TaintTag.CLEAN) | d_tag
                        new_demand[u_reg] = combined
                    elif not s.transfer:
                        # No transfer info → conservative: propagate to all uses
                        combined = new_demand.get(u_reg, TaintTag.CLEAN) | d_tag
                        new_demand[u_reg] = combined
                snapshot = dict(new_demand)

            demand.update(new_demand)
            if snapshot:
                demand_chain.append((s.handler_id, snapshot))

        return {
            "required_inputs": dict(demand),
            "contributing_handlers": contributing,
            "demand_chain": demand_chain,
        }

    def get_live_registers(
        self,
        summaries: list[HandlerTaintSummary],
        handler_idx: int,
    ) -> set[str]:
        """Return the set of registers live at the entry of handler *handler_idx*.

        A register is live at handler *i* if it is used by handler *i*
        or is live at handler *i+1* and not killed by handler *i*.
        """
        if not summaries:
            return set()

        # Backward pass to compute liveness.
        n = len(summaries)
        live_out: list[set[str]] = [set() for _ in range(n)]
        live_in: list[set[str]] = [set() for _ in range(n)]

        for i in range(n - 1, -1, -1):
            if i < n - 1:
                live_out[i] = set(live_in[i + 1])
            live_in[i] = summaries[i].uses | (live_out[i] - summaries[i].kill)

        if 0 <= handler_idx < n:
            return live_in[handler_idx]
        return set()


# ---------------------------------------------------------------------------
# Composable summary chaining (B55)
# ---------------------------------------------------------------------------

def compose_summaries(
    summaries: list[HandlerTaintSummary],
    *,
    initial_tags: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compose a chain of handler summaries into a single input→output tag map.

    Walks the summary chain forward, propagating ``TaintTag`` values
    through each handler's transfer function.  The result is a mapping
    from initial input registers to the tags they contribute at the end
    of the chain.

    Parameters
    ----------
    summaries : list of HandlerTaintSummary
        Ordered handler summaries.
    initial_tags : dict or None
        ``{register: TaintTag}`` at the chain entry.  If *None*, each
        input register gets ``TaintTag.INPUT``.

    Returns
    -------
    dict
        ``{"input_tags": {reg: tag}, "output_tags": {reg: tag},
           "composed_transfer": {in_reg: set_of_out_regs}}``
    """
    TaintTag = _get_taint_tag()

    if not summaries:
        return {"input_tags": {}, "output_tags": {}, "composed_transfer": {}}

    # Determine initial input tags
    if initial_tags is None:
        # Use the first handler's uses as inputs
        tags: dict[str, Any] = dict.fromkeys(summaries[0].uses, TaintTag.INPUT)
    else:
        tags = dict(initial_tags)

    input_tags = dict(tags)
    # Track which original inputs flow to which outputs
    composed_transfer: dict[str, set[str]] = {
        reg: {reg} for reg in tags
    }
    # Reverse map: current register → set of original inputs that reached it
    origin_map: dict[str, set[str]] = {
        reg: {reg} for reg in tags
    }

    for s in summaries:
        # New output tags after this handler
        new_tags: dict[str, Any] = {}
        new_origin: dict[str, set[str]] = {}

        # Pass-through: registers not killed
        for reg, tag in tags.items():
            if reg not in s.kill:
                new_tags[reg] = tag
                new_origin[reg] = set(origin_map.get(reg, set()))

        # Defs: combine tags from tainted uses
        for d_reg in s.defs:
            combined = TaintTag.CLEAN
            contributing_origins: set[str] = set()
            for u_reg in s.uses:
                if u_reg in tags:
                    # Check transfer function
                    if s.transfer and u_reg in s.transfer:
                        if d_reg in s.transfer[u_reg]:
                            combined |= tags[u_reg] | TaintTag.COMPUTED
                            contributing_origins.update(
                                origin_map.get(u_reg, set())
                            )
                    elif not s.transfer:
                        combined |= tags[u_reg] | TaintTag.COMPUTED
                        contributing_origins.update(
                            origin_map.get(u_reg, set())
                        )
            if combined != TaintTag.CLEAN:
                new_tags[d_reg] = combined
                new_origin[d_reg] = contributing_origins
                for orig_input in contributing_origins:
                    composed_transfer.setdefault(orig_input, set()).add(d_reg)

        tags = new_tags
        origin_map = new_origin

    return {
        "input_tags": {k: int(v) for k, v in input_tags.items()},
        "output_tags": {k: int(v) for k, v in tags.items()},
        "composed_transfer": {
            k: sorted(v) for k, v in composed_transfer.items()
        },
    }
