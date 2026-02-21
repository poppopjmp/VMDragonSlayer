"""
Control-Flow Graph Reconstruction
==================================

Builds a :class:`networkx.DiGraph`-based control-flow graph (CFG) from
an :class:`~..trace_ingestion.ExecutionTrace` and, optionally, from
:class:`~..vm_discovery.handler_boundaries.HandlerBoundary` records.

Two granularity levels:

* **Instruction-level CFG** — one node per unique native address,
  edges from observed sequential and branch transitions.
* **Handler-level CFG** — one node per handler boundary, edges
  from the order in which handlers execute.

Usage::

    from dragonslayer.analysis.cfg import build_instruction_cfg, build_handler_cfg

    icfg = build_instruction_cfg(trace)
    hcfg = build_handler_cfg(boundaries)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, TypedDict

try:
    import networkx as nx
    NX_AVAILABLE = True
except ImportError:  # pragma: no cover
    nx = None  # type: ignore[assignment]
    NX_AVAILABLE = False

from dragonslayer.analysis.trace_ingestion import (
    ExecutionTrace,
    TraceInstruction,
    TraceControlFlow,
)
from dragonslayer.analysis.vm_discovery.handler_boundaries import (
    HandlerBoundary,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data-classes
# ---------------------------------------------------------------------------


@dataclass
class BasicBlock:
    """A maximal straight-line sequence of instructions (no branches
    in / out except at the edges)."""

    start_address: int
    end_address: int
    instruction_count: int = 0
    addresses: List[int] = field(default_factory=list)

    @property
    def size(self) -> int:
        if self.end_address >= self.start_address:
            return self.end_address - self.start_address
        return 0


class CFGStatsDict(TypedDict):
    """Serialised shape of :meth:`CFGStats.to_dict`."""

    node_count: int
    edge_count: int
    back_edge_count: int
    loop_count: int
    strongly_connected_components: int
    entry_points: List[str]
    exit_points: List[str]


@dataclass
class CFGStats:
    """Summary statistics for a reconstructed CFG.

    Attributes:
        node_count: Number of nodes (basic blocks or instructions).
        edge_count: Number of edges in the CFG.
        back_edge_count: Number of back-edges (loop indicators).
        loop_count: Number of natural loops detected.
        strongly_connected_components: Count of SCCs.
        entry_points: Addresses of CFG entry nodes.
        exit_points: Addresses of CFG exit nodes.
    """

    node_count: int = 0
    edge_count: int = 0
    back_edge_count: int = 0
    loop_count: int = 0
    strongly_connected_components: int = 0
    entry_points: List[int] = field(default_factory=list)
    exit_points: List[int] = field(default_factory=list)

    def to_dict(self) -> CFGStatsDict:
        return {
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "back_edge_count": self.back_edge_count,
            "loop_count": self.loop_count,
            "strongly_connected_components": self.strongly_connected_components,
            "entry_points": [hex(a) for a in self.entry_points],
            "exit_points": [hex(a) for a in self.exit_points],
        }


# ---------------------------------------------------------------------------
# Instruction-level CFG
# ---------------------------------------------------------------------------

def build_instruction_cfg(
    trace: ExecutionTrace,
    *,
    include_fallthrough: bool = True,
) -> "nx.DiGraph":
    """Build an instruction-level CFG from an execution trace.

    Nodes are unique instruction addresses.  Edges are observed
    transitions (sequential fall-through and explicit control-flow
    records).

    Args:
        trace: The execution trace to analyse.
        include_fallthrough: If ``True``, add an edge between every pair
            of consecutively-executed instructions (the "fall-through"
            edge).

    Returns:
        A ``networkx.DiGraph`` where each node has attributes
        ``address``, ``size``, ``disassembly`` and each edge has a
        ``type`` attribute (``"fallthrough"``, ``"call"``, ``"jmp"``,
        etc.).
    """
    if not NX_AVAILABLE:
        raise RuntimeError("networkx is required for CFG reconstruction")

    G: nx.DiGraph = nx.DiGraph()

    # ---- nodes from instructions ----------------------------------------
    seen: Dict[int, TraceInstruction] = {}
    for ti in trace.instructions:
        if ti.address not in seen:
            seen[ti.address] = ti
            G.add_node(
                ti.address,
                address=ti.address,
                size=ti.size,
                disassembly=ti.disassembly,
            )

    # ---- fall-through edges ---------------------------------------------
    if include_fallthrough and len(trace.instructions) > 1:
        for i in range(len(trace.instructions) - 1):
            src = trace.instructions[i].address
            dst = trace.instructions[i + 1].address
            if src != dst:
                if G.has_edge(src, dst):
                    G[src][dst]["weight"] = G[src][dst].get("weight", 1) + 1
                else:
                    G.add_edge(src, dst, type="fallthrough", weight=1)

    # ---- explicit control-flow edges ------------------------------------
    for cf in trace.control_flow:
        if not G.has_node(cf.source):
            G.add_node(cf.source, address=cf.source, size=0, disassembly="")
        if not G.has_node(cf.target):
            G.add_node(cf.target, address=cf.target, size=0, disassembly="")
        if G.has_edge(cf.source, cf.target):
            G[cf.source][cf.target]["type"] = cf.type
        else:
            G.add_edge(cf.source, cf.target, type=cf.type, weight=1)

    return G


# ---------------------------------------------------------------------------
# Basic-block recovery
# ---------------------------------------------------------------------------

def extract_basic_blocks(G: "nx.DiGraph") -> List[BasicBlock]:
    """Extract basic blocks from an instruction-level CFG.

    A basic block starts at a node that is an entry point, a branch
    target (in-degree > 1 or has a non-fallthrough incoming edge), or
    the successor of a branching node (out-degree > 1).
    """
    if not NX_AVAILABLE:
        raise RuntimeError("networkx is required")

    # Identify block leaders.
    leaders: Set[int] = set()
    nodes = sorted(G.nodes)
    if nodes:
        leaders.add(nodes[0])

    for node in nodes:
        # Branch target → leader
        if G.in_degree(node) > 1:
            leaders.add(node)
        for _, _, data in G.in_edges(node, data=True):
            if data.get("type") not in ("fallthrough", None):
                leaders.add(node)
                break
        # Successor of branching node → leader
        if G.out_degree(node) > 1:
            for succ in G.successors(node):
                leaders.add(succ)

    # Build blocks by sorting leaders and grouping nodes.
    sorted_leaders = sorted(leaders)
    blocks: List[BasicBlock] = []
    all_nodes_sorted = sorted(G.nodes)

    for i, leader in enumerate(sorted_leaders):
        end_addr = sorted_leaders[i + 1] if i + 1 < len(sorted_leaders) else (
            all_nodes_sorted[-1] + 1 if all_nodes_sorted else leader
        )
        addrs = [n for n in all_nodes_sorted if leader <= n < end_addr]
        if addrs:
            blocks.append(BasicBlock(
                start_address=addrs[0],
                end_address=addrs[-1],
                instruction_count=len(addrs),
                addresses=addrs,
            ))

    return blocks


# ---------------------------------------------------------------------------
# Handler-level CFG
# ---------------------------------------------------------------------------

def build_handler_cfg(
    boundaries: List[HandlerBoundary],
) -> "nx.DiGraph":
    """Build a handler-level CFG from segmentation boundaries.

    Each node represents one handler invocation (keyed by index).
    Edges connect consecutive handler invocations (execution order).
    """
    if not NX_AVAILABLE:
        raise RuntimeError("networkx is required for CFG reconstruction")

    G: nx.DiGraph = nx.DiGraph()

    for i, b in enumerate(boundaries):
        G.add_node(i, **{
            "vip_value": b.vip_value,
            "handler_address": b.handler_address,
            "instruction_count": b.instruction_count,
            "category": b.category,
            "vip_delta": b.vip_delta,
        })

    for i in range(len(boundaries) - 1):
        G.add_edge(i, i + 1, type="sequential")

    # Detect back-edges (repeated handler addresses → potential loops).
    addr_first: Dict[int, int] = {}
    for i, b in enumerate(boundaries):
        if b.handler_address in addr_first:
            first_idx = addr_first[b.handler_address]
            if not G.has_edge(i, first_idx):
                G.add_edge(i, first_idx, type="back_edge")
        else:
            addr_first[b.handler_address] = i

    return G


# ---------------------------------------------------------------------------
# CFG analysis helpers
# ---------------------------------------------------------------------------

def analyse_cfg(G: "nx.DiGraph") -> CFGStats:
    """Compute summary statistics for a CFG."""
    if not NX_AVAILABLE:
        raise RuntimeError("networkx is required")

    stats = CFGStats(
        node_count=G.number_of_nodes(),
        edge_count=G.number_of_edges(),
    )

    # Entry points: in-degree 0.
    stats.entry_points = sorted(
        n for n in G.nodes if G.in_degree(n) == 0
    )
    # Exit points: out-degree 0.
    stats.exit_points = sorted(
        n for n in G.nodes if G.out_degree(n) == 0
    )

    # Back-edges.
    stats.back_edge_count = sum(
        1 for _, _, d in G.edges(data=True) if d.get("type") == "back_edge"
    )

    # Strongly connected components.
    sccs = list(nx.strongly_connected_components(G))
    stats.strongly_connected_components = len(sccs)
    stats.loop_count = sum(1 for scc in sccs if len(scc) > 1)

    return stats


def find_dominators(
    G: "nx.DiGraph",
    entry: Optional[int] = None,
) -> Dict[int, int]:
    """Return the immediate dominator map {node: idom}.

    If *entry* is ``None``, the first entry point (in-degree 0) is used.
    """
    if not NX_AVAILABLE:
        raise RuntimeError("networkx is required")
    if G.number_of_nodes() == 0:
        return {}
    if entry is None:
        entries = [n for n in G.nodes if G.in_degree(n) == 0]
        if not entries:
            entry = min(G.nodes)
        else:
            entry = min(entries)
    return nx.immediate_dominators(G, entry)
