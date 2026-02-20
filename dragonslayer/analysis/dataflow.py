"""
Cross-Handler Data-Flow Analysis
=================================

Builds a global def-use graph across VM handler boundaries by
abstractly interpreting the VM stack machine.  The graph tracks
which handler *defines* each value and which handlers *use* it.

Key results:

* **Reaching definitions** — for each handler's input, which prior
  handler produced it.
* **Dead variables** — values defined but never consumed.
* **Phi-nodes** — merge points where the same stack slot could
  hold values from different control-flow paths.
* **Live ranges** — per-variable live range (define → last use).

Usage::

    from dragonslayer.analysis.dataflow import compute_data_flow

    result = compute_data_flow(opcode_table, boundaries)
    print(result.dead_variables)
    print(result.reaching_defs)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from dragonslayer.analysis.handler_semantics import (
    SemanticOpcodeTable,
    OpcodeTableEntry,
    VMOperation,
)
from dragonslayer.analysis.vm_discovery.handler_boundaries import (
    HandlerBoundary,
)

logger = logging.getLogger(__name__)

try:
    import networkx as nx
    _NX = True
except ImportError:
    nx = None  # type: ignore[assignment]
    _NX = False


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class VarDef:
    """A single variable definition."""
    name: str
    handler_index: int   # index in the boundary list
    handler_addr: int
    operation: str
    width: int = 0       # operand width (bytes)


@dataclass
class VarUse:
    """A single variable use."""
    name: str
    handler_index: int
    handler_addr: int
    operation: str        # consuming operation


@dataclass
class LiveRange:
    """Live range of a variable: [def_index, last_use_index]."""
    name: str
    def_index: int        # handler index where defined
    last_use_index: int   # handler index of last use (-1 if dead)


@dataclass
class PhiNode:
    """A phi-node at a merge point."""
    target_var: str
    handler_index: int    # the handler where the phi is needed
    sources: List[str]    # variable names from each predecessor


@dataclass
class DataFlowResult:
    """Result of cross-handler data-flow analysis."""

    definitions: List[VarDef] = field(default_factory=list)
    """All variable definitions across handlers."""

    uses: List[VarUse] = field(default_factory=list)
    """All variable uses across handlers."""

    reaching_defs: Dict[str, VarDef] = field(default_factory=dict)
    """For each variable name used, the VarDef that reaches it."""

    dead_variables: List[str] = field(default_factory=list)
    """Variables that were defined but never used."""

    live_ranges: List[LiveRange] = field(default_factory=list)
    """Live range for each defined variable."""

    phi_nodes: List[PhiNode] = field(default_factory=list)
    """Phi-nodes at control-flow merge points."""

    def_use_edges: List[Tuple[str, str, int, int]] = field(default_factory=list)
    """(def_var, use_var, def_handler_idx, use_handler_idx) edges."""

    handler_count: int = 0
    """Number of handlers analysed."""

    def summary(self) -> Dict[str, Any]:
        return {
            "handler_count": self.handler_count,
            "total_defs": len(self.definitions),
            "total_uses": len(self.uses),
            "dead_variable_count": len(self.dead_variables),
            "live_range_count": len(self.live_ranges),
            "phi_node_count": len(self.phi_nodes),
            "def_use_edge_count": len(self.def_use_edges),
        }


# ---------------------------------------------------------------------------
# VM-stack operations classified by I/O pattern
# ---------------------------------------------------------------------------

# Binary ops: pop 2, push 1
_BINARY_OPS = {
    VMOperation.ADD, VMOperation.SUB, VMOperation.MUL, VMOperation.DIV,
    VMOperation.AND, VMOperation.OR, VMOperation.XOR,
    VMOperation.SHL, VMOperation.SHR, VMOperation.ROL, VMOperation.ROR,
}

# Unary ops: pop 1, push 1
_UNARY_OPS = {VMOperation.NOT, VMOperation.NEG}

# Comparison ops: pop 2, produce flags (no stack push)
_CMP_OPS = {VMOperation.CMP, VMOperation.TEST}

# Operation → (pops, pushes, produces_flags)
_OP_PROFILE: Dict[str, Tuple[int, int, bool]] = {}

for _op in _BINARY_OPS:
    _OP_PROFILE[_op] = (2, 1, False)
for _op in _UNARY_OPS:
    _OP_PROFILE[_op] = (1, 1, False)
for _op in _CMP_OPS:
    _OP_PROFILE[_op] = (2, 0, True)

_OP_PROFILE[VMOperation.PUSH] = (0, 1, False)
_OP_PROFILE[VMOperation.POP]  = (1, 0, False)   # pop removes from stack
_OP_PROFILE[VMOperation.LOAD] = (1, 1, False)    # pop addr, push value
_OP_PROFILE[VMOperation.STORE] = (2, 0, False)   # pop value + addr
_OP_PROFILE[VMOperation.JMP]  = (0, 0, False)
_OP_PROFILE[VMOperation.JCC]  = (0, 0, False)
_OP_PROFILE[VMOperation.CALL] = (1, 0, False)    # pop target
_OP_PROFILE[VMOperation.RET]  = (0, 0, False)
_OP_PROFILE[VMOperation.NOP]  = (0, 0, False)

# Op → name prefix (mirrors pseudocode._DefUseNamer)
_OP_PREFIX: Dict[str, str] = {
    VMOperation.ADD: "sum", VMOperation.SUB: "diff",
    VMOperation.MUL: "prod", VMOperation.DIV: "quot",
    VMOperation.AND: "band", VMOperation.OR: "bor",
    VMOperation.XOR: "bxor", VMOperation.NOT: "bnot",
    VMOperation.NEG: "neg", VMOperation.SHL: "shl",
    VMOperation.SHR: "shr", VMOperation.ROL: "rol",
    VMOperation.ROR: "ror", VMOperation.LOAD: "ld",
    VMOperation.POP: "stk", VMOperation.PUSH: "val",
    VMOperation.CMP: "cmp", VMOperation.TEST: "tst",
}


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

class _StackTracker:
    """Abstract stack for tracking variable names across handlers."""

    def __init__(self) -> None:
        self._stack: List[str] = []
        self._counters: Dict[str, int] = {}

    def _next_name(self, op: str) -> str:
        prefix = _OP_PREFIX.get(op, "v")
        idx = self._counters.get(prefix, 0)
        self._counters[prefix] = idx + 1
        return f"{prefix}_{idx}"

    def push(self, name: str) -> None:
        self._stack.append(name)

    def pop(self) -> str:
        if self._stack:
            return self._stack.pop()
        idx = self._counters.get("arg", 0)
        self._counters["arg"] = idx + 1
        return f"arg_{idx}"

    def peek(self) -> str:
        return self._stack[-1] if self._stack else "???"

    @property
    def depth(self) -> int:
        return len(self._stack)

    def snapshot(self) -> List[str]:
        return list(self._stack)


def compute_data_flow(
    opcode_table: SemanticOpcodeTable,
    boundaries: List[HandlerBoundary],
    handler_cfg: Any = None,
) -> DataFlowResult:
    """Compute cross-handler data-flow analysis.

    Parameters
    ----------
    opcode_table : SemanticOpcodeTable
        Semantic information for each handler.
    boundaries : list[HandlerBoundary]
        Handler boundaries in execution order.
    handler_cfg : networkx.DiGraph, optional
        Handler-level control-flow graph.  When provided, phi-nodes
        are inserted at merge points.

    Returns
    -------
    DataFlowResult
        Complete data-flow analysis result.
    """
    result = DataFlowResult(handler_count=len(boundaries))
    tracker = _StackTracker()

    # Track where each variable is defined
    def_map: Dict[str, VarDef] = {}
    # Track uses of each variable
    use_map: Dict[str, List[VarUse]] = {}

    for i, boundary in enumerate(boundaries):
        entry = opcode_table.lookup_handler(boundary.handler_address)
        if entry is None:
            continue

        op = entry.semantic.operation
        ow = entry.semantic.operand_width
        profile = _OP_PROFILE.get(op)
        if profile is None:
            continue

        pops, pushes, produces_flags = profile

        # Record uses (pops from stack)
        consumed: List[str] = []
        for _ in range(pops):
            name = tracker.pop()
            consumed.append(name)
            use = VarUse(
                name=name,
                handler_index=i,
                handler_addr=boundary.handler_address,
                operation=op,
            )
            result.uses.append(use)
            use_map.setdefault(name, []).append(use)

        # Record definitions (pushes to stack)
        for _ in range(pushes):
            name = tracker._next_name(op)
            vdef = VarDef(
                name=name,
                handler_index=i,
                handler_addr=boundary.handler_address,
                operation=op,
                width=ow,
            )
            result.definitions.append(vdef)
            def_map[name] = vdef
            tracker.push(name)

            # Build def→use edges for consumed operands
            for consumed_name in consumed:
                result.def_use_edges.append((
                    consumed_name, name, 
                    def_map[consumed_name].handler_index if consumed_name in def_map else -1,
                    i,
                ))

        # CMP/TEST: record flag production
        if produces_flags:
            fname = tracker._next_name(op)
            fdef = VarDef(
                name=fname,
                handler_index=i,
                handler_addr=boundary.handler_address,
                operation=op,
                width=ow,
            )
            result.definitions.append(fdef)
            def_map[fname] = fdef

    # Compute reaching definitions
    result.reaching_defs = dict(def_map)

    # Compute dead variables (defined but never used)
    defined_names = {d.name for d in result.definitions}
    used_names = {u.name for u in result.uses}
    result.dead_variables = sorted(defined_names - used_names)

    # Compute live ranges
    for d in result.definitions:
        last_use_idx = -1
        for u in use_map.get(d.name, []):
            if u.handler_index > last_use_idx:
                last_use_idx = u.handler_index
        result.live_ranges.append(LiveRange(
            name=d.name,
            def_index=d.handler_index,
            last_use_index=last_use_idx,
        ))

    # Phi-node insertion (requires CFG)
    if handler_cfg is not None and _NX:
        result.phi_nodes = _compute_phi_nodes(
            handler_cfg, boundaries, def_map, opcode_table,
        )

    return result


# ---------------------------------------------------------------------------
# Standalone helpers (B51)
# ---------------------------------------------------------------------------

def compute_live_ranges(result: DataFlowResult) -> List[LiveRange]:
    """Compute live ranges from an existing :class:`DataFlowResult`.

    Builds an index of uses per variable name and returns a
    :class:`LiveRange` for every definition.  If a variable is
    never used, ``last_use_index`` is ``-1`` (dead).

    This deliberately mirrors the inline computation inside
    :func:`compute_data_flow` but is available as a reusable export.
    """
    use_map: Dict[str, int] = {}  # var_name → max handler index
    for u in result.uses:
        cur = use_map.get(u.name, -1)
        if u.handler_index > cur:
            use_map[u.name] = u.handler_index

    ranges: List[LiveRange] = []
    for d in result.definitions:
        ranges.append(LiveRange(
            name=d.name,
            def_index=d.handler_index,
            last_use_index=use_map.get(d.name, -1),
        ))
    return ranges


def backward_slice(
    result: DataFlowResult,
    target_var: str,
    *,
    boundary_index: Optional[int] = None,
) -> "BackwardSliceResult":
    """Backward slice on the fine-grained def-use graph.

    Starting from *target_var*, walks ``result.def_use_edges`` in
    reverse, collecting every variable (and its defining handler)
    that transitively contributes to *target_var*.

    Parameters
    ----------
    result : DataFlowResult
        The data-flow result containing ``def_use_edges`` and ``reaching_defs``.
    target_var : str
        Variable name to slice backward from.
    boundary_index : int, optional
        If provided, only consider edges whose use-handler index is
        ``<= boundary_index`` (restricts the slice to a region).

    Returns
    -------
    BackwardSliceResult
        The slice result with contributing variables, handler indices,
        and the subgraph edges.
    """
    # Build reverse adjacency: produced_var → [(consumed_var, def_idx, use_idx), ...]
    rev_adj: Dict[str, List[Tuple[str, int, int]]] = {}
    for consumed, produced, def_idx, use_idx in result.def_use_edges:
        if boundary_index is not None and use_idx > boundary_index:
            continue
        rev_adj.setdefault(produced, []).append((consumed, def_idx, use_idx))

    visited: Set[str] = set()
    handler_indices: Set[int] = set()
    slice_edges: List[Tuple[str, str, int, int]] = []
    worklist: List[str] = [target_var]

    while worklist:
        var = worklist.pop()
        if var in visited:
            continue
        visited.add(var)

        # Record the defining handler
        vdef = result.reaching_defs.get(var)
        if vdef is not None:
            handler_indices.add(vdef.handler_index)

        for consumed, def_idx, use_idx in rev_adj.get(var, []):
            slice_edges.append((consumed, var, def_idx, use_idx))
            if consumed not in visited:
                worklist.append(consumed)

    return BackwardSliceResult(
        target=target_var,
        contributing_vars=sorted(visited),
        handler_indices=sorted(handler_indices),
        edges=slice_edges,
    )


@dataclass
class BackwardSliceResult:
    """Result of a backward slice on the def-use graph."""

    target: str
    """Variable that was sliced on."""

    contributing_vars: List[str]
    """All variable names in the slice (including the target)."""

    handler_indices: List[int]
    """Handler indices that participate in the slice."""

    edges: List[Tuple[str, str, int, int]]
    """Subset of def-use edges in the slice."""

    def summary(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "contributing_count": len(self.contributing_vars),
            "handler_count": len(self.handler_indices),
            "edge_count": len(self.edges),
        }


def _compute_phi_nodes(
    cfg: Any,
    boundaries: List[HandlerBoundary],
    def_map: Dict[str, VarDef],
    opcode_table: SemanticOpcodeTable,
) -> List[PhiNode]:
    """Insert phi-nodes at merge points in the handler CFG.

    A phi-node is needed at handler H if:
    - H has multiple predecessors P1, P2, ...
    - Different variables could be on the stack at the merge point
    """
    phi_nodes: List[PhiNode] = []
    if not _NX or cfg is None:
        return phi_nodes

    try:
        for node in cfg.nodes():
            preds = list(cfg.predecessors(node))
            if len(preds) < 2:
                continue

            # Collect reaching definitions from each predecessor path
            pred_defs: Dict[int, Set[str]] = {}
            for p in preds:
                defs_from_p: Set[str] = set()
                for d in def_map.values():
                    if d.handler_index <= p:
                        defs_from_p.add(d.name)
                pred_defs[p] = defs_from_p

            # Variables that differ between predecessors need phi-nodes
            all_defs = set()
            for ds in pred_defs.values():
                all_defs |= ds
            for var in all_defs:
                present_in = [p for p, ds in pred_defs.items() if var in ds]
                if len(present_in) > 0 and len(present_in) < len(preds):
                    phi_nodes.append(PhiNode(
                        target_var=var,
                        handler_index=node if isinstance(node, int) else 0,
                        sources=[var] * len(preds),
                    ))
    except Exception:
        pass

    return phi_nodes


# ---------------------------------------------------------------------------
# Utility: eliminate dead variables from pseudocode text
# ---------------------------------------------------------------------------

def eliminate_dead_vars(
    pseudocode_text: str,
    dead_variables: List[str],
) -> str:
    """Remove lines that only define dead variables.

    A simple textual pass: remove lines where the only assignment
    target is a dead variable and the RHS has no side effects.
    """
    if not dead_variables:
        return pseudocode_text

    dead_set = set(dead_variables)
    lines = pseudocode_text.split("\n")
    result: List[str] = []

    for line in lines:
        stripped = line.strip()
        # Skip empty / comment lines — keep them
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            result.append(line)
            continue

        # Check for simple assignment: "dead_var = ..."
        if "=" in stripped and not stripped.startswith("*"):
            lhs = stripped.split("=", 1)[0].strip().rstrip()
            # Remove type qualifiers
            for prefix in ("uint8_t", "uint16_t", "uint32_t", "uint64_t"):
                if lhs.startswith(prefix):
                    lhs = lhs[len(prefix):].strip()
            if lhs in dead_set:
                # Check RHS has no side effects (no function calls, no stores)
                rhs = stripped.split("=", 1)[1].strip()
                if "(" not in rhs and "*" not in rhs:
                    continue  # eliminate this line

        result.append(line)

    return "\n".join(result)
