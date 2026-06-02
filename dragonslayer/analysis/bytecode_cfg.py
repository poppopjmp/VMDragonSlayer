"""
Bytecode Walker & Handler-Level CFG Reconstruction
====================================================

Given a *VM opcode table* (mapping opcode values → handler semantics) and
an execution trace / segmented boundaries, this module reconstructs the
**handler-level control-flow graph (CFG)** of the virtualised function.

This is the missing piece between "we know what each handler does" and
"we can emit structured pseudocode."

Architecture
------------

The bytecode stream is either:

1. **Extracted from the execution trace** — each handler boundary tells us
   which opcode byte was fetched and which handler was dispatched, so we
   can replay the stream in execution order and detect branches.
2. **Read from memory** — if we have the raw bytecode bytes and the
   handler dispatch table, we can disassemble the bytecode statically
   (required for complete coverage including paths not taken).

Both paths produce an ordered list of :class:`VMInstruction` objects.
From there we identify basic-block leaders (targets of jumps, successors
of conditional branches) and build a :class:`networkx.DiGraph` of
:class:`HandlerBasicBlock` nodes.

Usage::

    from dragonslayer.analysis.bytecode_cfg import (
        build_handler_cfg,
        walk_trace_bytecode,
        VMInstruction,
        HandlerCFG,
    )

    cfg = build_handler_cfg(opcode_table, boundaries, trace)
    print(cfg.summary())

    # Pass the CFG into pseudocode emission:
    from dragonslayer.analysis.pseudocode import emit_pseudocode
    result = emit_pseudocode(opcode_table, boundaries, cfg.graph,
                             style="c_like")
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from dragonslayer.analysis.handler_semantics import (
    OpcodeTableEntry,
    SemanticOpcodeTable,
    VMOperation,
)
from dragonslayer.analysis.vm_discovery.handler_boundaries import (
    HandlerBoundary,
)

logger = logging.getLogger(__name__)

try:
    import networkx as nx

    NX_AVAILABLE = True
except ImportError:  # pragma: no cover
    nx = None
    NX_AVAILABLE = False

_GRAPH_ERRORS: tuple[type[Exception], ...] = (
    ValueError, TypeError, KeyError, AttributeError, RuntimeError,
)
if NX_AVAILABLE:
    _GRAPH_ERRORS = (*_GRAPH_ERRORS, nx.NetworkXError)


# ---------------------------------------------------------------------------
# Data-classes
# ---------------------------------------------------------------------------


@dataclass
class VMInstruction:
    """One decoded VM instruction in the bytecode stream.

    Combines the opcode byte, its handler semantic, and the virtual
    address (vIP value) where this instruction lives.
    """

    vip: int
    """Virtual instruction pointer value (address in the bytecode stream)."""

    opcode: int
    """Raw opcode byte/word fetched from the bytecode."""

    handler_address: int
    """Native address of the handler that processes this opcode."""

    operation: str = VMOperation.UNKNOWN
    """Semantic operation (from :class:`VMOperation`)."""

    vip_delta: int = 1
    """Bytes consumed by this VM instruction (advance of vIP)."""

    operand_bytes: bytes = b""
    """Raw operand bytes that follow the opcode (if known)."""

    boundary_index: int = -1
    """Index into the original boundaries list (-1 = not from trace)."""

    confidence: float = 0.0
    """Classification confidence."""

    def is_branch(self) -> bool:
        """Return ``True`` if this instruction is a branch (jump/conditional)."""
        return self.operation in {VMOperation.JMP, VMOperation.JCC}

    def is_unconditional_jump(self) -> bool:
        """Return ``True`` for unconditional jumps."""
        return self.operation == VMOperation.JMP

    def is_conditional_jump(self) -> bool:
        """Return ``True`` for conditional branches."""
        return self.operation == VMOperation.JCC

    def is_call(self) -> bool:
        """Return ``True`` for VM CALL instructions."""
        return self.operation == VMOperation.CALL

    def is_return(self) -> bool:
        """Return ``True`` for VM RET instructions."""
        return self.operation == VMOperation.RET

    def is_terminator(self) -> bool:
        """Return ``True`` if this instruction is a block terminator."""
        return self.is_branch() or self.is_return()

    def fallthrough_vip(self) -> int:
        """vIP of the next sequential instruction."""
        return self.vip + self.vip_delta

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-safe dict.

        Returns:
            Dict with keys ``vip``, ``opcode``, ``handler_address``,
            ``operation``, ``vip_delta``, ``is_branch``.
        """
        return {
            "vip": self.vip,
            "opcode": self.opcode,
            "handler_address": hex(self.handler_address),
            "operation": self.operation,
            "vip_delta": self.vip_delta,
            "is_branch": self.is_branch(),
        }


@dataclass
class HandlerBasicBlock:
    """A basic block in the handler-level CFG.

    Contains a contiguous run of VM instructions with no internal
    branches — only the last instruction can be a branch/return.
    """

    block_id: int
    """Unique block identifier."""

    start_vip: int
    """vIP of the first instruction in this block."""

    instructions: list[VMInstruction] = field(default_factory=list)
    """Instructions in this block, in execution order."""

    is_entry: bool = False
    """True if this is the function entry block."""

    is_exit: bool = False
    """True if this block ends with RET or unreachable."""

    def end_vip(self) -> int:
        """vIP of the last instruction in this block."""
        if self.instructions:
            return self.instructions[-1].vip
        return self.start_vip

    def terminator(self) -> VMInstruction | None:
        """The last instruction (may or may not be a terminator)."""
        return self.instructions[-1] if self.instructions else None

    @property
    def instruction_count(self) -> int:
        """Number of VM instructions in this block."""
        return len(self.instructions)

    def operations_list(self) -> list[str]:
        """List of operation names in this block."""
        return [i.operation for i in self.instructions]

    def to_dict(self) -> dict[str, Any]:
        """Serialise this block to a JSON-safe dict.

        Returns:
            Dict with keys ``block_id``, ``start_vip``, ``end_vip``,
            ``instruction_count``, ``is_entry``, ``is_exit``, ``operations``.
        """
        return {
            "block_id": self.block_id,
            "start_vip": self.start_vip,
            "end_vip": self.end_vip(),
            "instruction_count": self.instruction_count,
            "is_entry": self.is_entry,
            "is_exit": self.is_exit,
            "operations": self.operations_list(),
        }


@dataclass
class CFGEdge:
    """An edge in the handler-level CFG."""

    source_block: int
    target_block: int
    edge_type: str = "fallthrough"
    """One of: 'fallthrough', 'jump', 'branch_taken', 'branch_not_taken', 'back_edge'."""

    def to_dict(self) -> dict[str, Any]:
        """Serialise this edge to a JSON-safe dict.

        Returns:
            Dict with keys ``source``, ``target``, ``type``.
        """
        return {
            "source": self.source_block,
            "target": self.target_block,
            "type": self.edge_type,
        }


@dataclass
class HandlerCFG:
    """Complete handler-level control-flow graph.

    Wraps a list of basic blocks, a list of edges, and
    (optionally) a networkx DiGraph for structured analysis.
    """

    blocks: list[HandlerBasicBlock] = field(default_factory=list)
    edges: list[CFGEdge] = field(default_factory=list)
    graph: Any = None  # networkx.DiGraph when available
    entry_block_id: int = 0
    vm_instructions: list[VMInstruction] = field(default_factory=list)
    loop_tree: LoopTree | None = None

    @property
    def block_count(self) -> int:
        """Number of basic blocks in the CFG."""
        return len(self.blocks)

    @property
    def edge_count(self) -> int:
        """Number of edges in the CFG."""
        return len(self.edges)

    def find_block(self, block_id: int) -> HandlerBasicBlock | None:
        """Return the block with *block_id*, or ``None``."""
        for b in self.blocks:
            if b.block_id == block_id:
                return b
        return None

    def find_block_by_vip(self, vip: int) -> HandlerBasicBlock | None:
        """Return the block starting at *vip*, or ``None``."""
        for b in self.blocks:
            if b.start_vip == vip:
                return b
        return None

    def back_edges(self) -> list[CFGEdge]:
        """Return all back-edges (loop indicators)."""
        return [e for e in self.edges if e.edge_type == "back_edge"]

    def loop_headers(self) -> set[int]:
        """Block IDs that are targets of back-edges (loop headers)."""
        return {e.target_block for e in self.edges if e.edge_type == "back_edge"}

    def exit_blocks(self) -> list[HandlerBasicBlock]:
        """Return blocks marked as exits."""
        return [b for b in self.blocks if b.is_exit]

    def topological_order(self) -> list[int]:
        """Block IDs in topological order (ignoring back-edges).

        Falls back to the natural block order if networkx is unavailable
        or the graph has no DAG structure.
        """
        if self.graph is not None and NX_AVAILABLE:
            # Remove back-edges for topo sort.
            dag = self.graph.copy()
            for e in self.back_edges():
                if dag.has_edge(e.source_block, e.target_block):
                    dag.remove_edge(e.source_block, e.target_block)
            try:
                return list(nx.topological_sort(dag))
            except _GRAPH_ERRORS:
                pass
        return [b.block_id for b in self.blocks]

    def summary(self) -> str:
        """Return a one-line human-readable summary of the CFG."""
        n_loops = len(self.loop_headers())
        n_exits = len(self.exit_blocks())
        total_insns = sum(b.instruction_count for b in self.blocks)
        depth_str = ""
        if self.loop_tree:
            depth_str = f", max loop depth {self.loop_tree.max_depth}"
        return (
            f"HandlerCFG: {self.block_count} blocks, "
            f"{self.edge_count} edges, {total_insns} instructions, "
            f"{n_loops} loops, {n_exits} exits{depth_str}"
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialise the complete CFG to a JSON-safe dict.

        Returns:
            Dict with ``block_count``, ``edge_count``, ``entry_block_id``,
            ``loop_count``, ``exit_count``, ``blocks``, ``edges``, and
            optionally ``loop_tree``.
        """
        result: dict[str, Any] = {
            "block_count": self.block_count,
            "edge_count": self.edge_count,
            "entry_block_id": self.entry_block_id,
            "loop_count": len(self.loop_headers()),
            "exit_count": len(self.exit_blocks()),
            "blocks": [b.to_dict() for b in self.blocks],
            "edges": [e.to_dict() for e in self.edges],
        }
        if self.loop_tree:
            result["loop_tree"] = self.loop_tree.to_dict()
        return result


# ---------------------------------------------------------------------------
# Step 1 — Instruction stream from trace boundaries
# ---------------------------------------------------------------------------


def walk_trace_bytecode(
    opcode_table: SemanticOpcodeTable,
    boundaries: Sequence[HandlerBoundary],
) -> list[VMInstruction]:
    """Walk handler boundaries in execution order and produce VM instructions.

    Each boundary gives us (vip_value, handler_address, vip_delta).
    We look up the handler in the opcode table to determine the
    semantic operation and opcode value.

    Args:
        opcode_table: Semantic opcode table from handler analysis.
        boundaries: Handler boundaries in execution order.

    Returns:
        Ordered list of :class:`VMInstruction`.
    """
    # Build reverse lookup: handler_address → OpcodeTableEntry.
    handler_map: dict[int, OpcodeTableEntry] = {}
    for te in opcode_table.entries:
        handler_map[te.handler_address] = te

    instructions: list[VMInstruction] = []
    for idx, boundary in enumerate(boundaries):
        entry = handler_map.get(boundary.handler_address)

        if entry is not None:
            insn = VMInstruction(
                vip=boundary.vip_value,
                opcode=entry.opcode,
                handler_address=boundary.handler_address,
                operation=entry.semantic.operation,
                vip_delta=boundary.vip_delta if boundary.vip_delta != 0 else entry.vip_delta,
                boundary_index=idx,
                confidence=entry.semantic.confidence,
            )
        else:
            # Unknown handler — create an UNKNOWN instruction.
            insn = VMInstruction(
                vip=boundary.vip_value,
                opcode=-1,
                handler_address=boundary.handler_address,
                operation=VMOperation.UNKNOWN,
                vip_delta=boundary.vip_delta if boundary.vip_delta != 0 else 1,
                boundary_index=idx,
            )

        instructions.append(insn)

    return instructions


# ---------------------------------------------------------------------------
# Step 2 — Basic-block identification
# ---------------------------------------------------------------------------


def _identify_leaders(instructions: list[VMInstruction]) -> set[int]:
    """Identify basic-block leader positions (indices into *instructions*).

    A leader is:
    1. The first instruction (index 0).
    2. Any target of a branch.
    3. Any instruction immediately after a branch/return.
    """
    leaders: set[int] = set()
    if not instructions:
        return leaders

    leaders.add(0)

    # Build vip → index map for branch targets.
    vip_to_idx: dict[int, int] = {}
    for i, insn in enumerate(instructions):
        if insn.vip not in vip_to_idx:
            vip_to_idx[insn.vip] = i

    for i, insn in enumerate(instructions):
        # The instruction after a terminator starts a new block.
        if (insn.is_terminator() or insn.is_call()) and i + 1 < len(instructions):
            leaders.add(i + 1)

        if insn.is_branch():
            # Try to resolve the branch target vIP.
            # For JMP/JCC from trace, the actual target is the *next*
            # executed instruction's vip (for taken branches).  For untaken
            # branches, the fallthrough is the next sequential vip.
            #
            # In execution-trace replay:
            # - Unconditional jump: next instruction in trace IS the target.
            # - Conditional branch (taken): next instruction IS the target.
            # - Conditional branch (not taken): next instruction is fallthrough.
            #
            # We mark both the fallthrough and the actual next instruction
            # as leaders.
            if i + 1 < len(instructions):
                leaders.add(i + 1)

            # If we can compute the target vip:
            target_vip = insn.vip + insn.vip_delta
            if target_vip in vip_to_idx:
                leaders.add(vip_to_idx[target_vip])

    return leaders


def _partition_into_blocks(
    instructions: list[VMInstruction],
    leaders: set[int],
) -> list[HandlerBasicBlock]:
    """Partition instructions into basic blocks based on leaders."""
    if not instructions:
        return []

    sorted_leaders = sorted(leaders)
    blocks: list[HandlerBasicBlock] = []

    for block_idx, leader_pos in enumerate(sorted_leaders):
        # Block extends from this leader to just before the next leader.
        next_leader = (
            sorted_leaders[block_idx + 1]
            if block_idx + 1 < len(sorted_leaders)
            else len(instructions)
        )

        block_insns = instructions[leader_pos:next_leader]
        if not block_insns:
            continue

        block = HandlerBasicBlock(
            block_id=block_idx,
            start_vip=block_insns[0].vip,
            instructions=block_insns,
            is_entry=(block_idx == 0),
        )

        # Mark exit blocks.
        term = block.terminator()
        if term is not None and term.is_return():
            block.is_exit = True

        blocks.append(block)

    # If the last block doesn't end with a terminator, mark it as exit.
    if blocks and not blocks[-1].is_exit:
        term = blocks[-1].terminator()
        if term is None or not term.is_branch():
            blocks[-1].is_exit = True

    return blocks


# ---------------------------------------------------------------------------
# Step 3 — Edge construction
# ---------------------------------------------------------------------------


def _build_edges(
    blocks: list[HandlerBasicBlock],
    instructions: list[VMInstruction],
) -> list[CFGEdge]:
    """Build control-flow edges between basic blocks.

    For each block, the terminator determines edges:
    - Fallthrough: non-terminator or conditional branch → next block.
    - Jump: unconditional jump → target block.
    - Branch taken/not taken: conditional branch → target / fallthrough.

    Back-edges are detected by checking if the target block appears
    *before* the source block in the block list (dominance
    approximation).
    """
    if not blocks:
        return []

    edges: list[CFGEdge] = []

    # Map vip → block_id for target resolution.
    vip_to_block: dict[int, int] = {}
    for block in blocks:
        vip_to_block[block.start_vip] = block.block_id

    # Map block_id → block for fast lookup.
    {b.block_id: b for b in blocks}

    # Natural ordering: block_id → position in list.
    block_order: dict[int, int] = {b.block_id: i for i, b in enumerate(blocks)}

    for pos, block in enumerate(blocks):
        term = block.terminator()
        if term is None:
            continue

        next_block_id: int | None = None
        if pos + 1 < len(blocks):
            next_block_id = blocks[pos + 1].block_id

        if term.is_return():
            # Exit block — no outgoing edges.
            continue

        elif term.is_unconditional_jump():
            # Unconditional jump — single edge to target.
            target_vip = term.fallthrough_vip()
            target_id = vip_to_block.get(target_vip)

            # In trace replay, the jump target is the next executed block.
            if target_id is None and next_block_id is not None:
                target_id = next_block_id

            if target_id is not None:
                edge_type = "jump"
                if block_order.get(target_id, 999999) <= block_order.get(block.block_id, 0):
                    edge_type = "back_edge"
                edges.append(CFGEdge(block.block_id, target_id, edge_type))

        elif term.is_conditional_jump():
            # Conditional branch — two edges:
            # 1. Branch taken → target (resolved from vip_delta or next trace insn)
            # 2. Branch not taken → fallthrough (next sequential block)

            target_vip = term.fallthrough_vip()
            target_id = vip_to_block.get(target_vip)

            # In trace replay, we see the taken path; the not-taken path
            # leads to the sequential fallthrough.
            if next_block_id is not None:
                # The next block in trace is the path actually taken.
                taken_id = next_block_id

                # The computed target_vip is the fallthrough for this trace.
                # But we also want to model the branch_not_taken edge.
                if target_id is not None and target_id != taken_id:
                    # taken_id = actual next, target_id = computed other path
                    edges.append(CFGEdge(block.block_id, taken_id, "branch_taken"))
                    edge_type = "branch_not_taken"
                    if block_order.get(target_id, 999999) <= block_order.get(block.block_id, 0):
                        edge_type = "back_edge"
                    edges.append(CFGEdge(block.block_id, target_id, edge_type))
                else:
                    # Can't resolve both paths — just use taken edge.
                    edges.append(CFGEdge(block.block_id, taken_id, "branch_taken"))
                    # Add fallthrough edge to the computed target if different.
                    if target_id is not None and target_id != taken_id:
                        edges.append(CFGEdge(block.block_id, target_id, "branch_not_taken"))

            elif target_id is not None:
                edges.append(CFGEdge(block.block_id, target_id, "jump"))

        else:
            # Non-terminator last instruction → fallthrough to next block.
            if next_block_id is not None:
                edges.append(CFGEdge(block.block_id, next_block_id, "fallthrough"))

    return edges


# ---------------------------------------------------------------------------
# Step 4 — Build networkx DiGraph
# ---------------------------------------------------------------------------


def _build_nx_graph(
    blocks: list[HandlerBasicBlock],
    edges: list[CFGEdge],
) -> Any:
    """Build a networkx DiGraph from blocks and edges.

    Returns ``None`` if networkx is not installed.
    """
    if not NX_AVAILABLE or nx is None:
        return None

    G = nx.DiGraph()

    for block in blocks:
        G.add_node(
            block.block_id,
            start_vip=block.start_vip,
            instruction_count=block.instruction_count,
            is_entry=block.is_entry,
            is_exit=block.is_exit,
        )

    for edge in edges:
        G.add_edge(
            edge.source_block,
            edge.target_block,
            type=edge.edge_type,
        )

    return G


# ---------------------------------------------------------------------------
# Step 5 — Dominance & Loop Detection
# ---------------------------------------------------------------------------


def detect_natural_loops(
    blocks: list[HandlerBasicBlock],
    edges: list[CFGEdge],
    graph: Any = None,
) -> list[dict[str, Any]]:
    """Detect natural loops from back-edges.

    For each back-edge ``source → target``, the loop body is the set of
    blocks from which ``target`` dominates and can reach ``source``
    without leaving the loop.

    Returns a list of dicts with keys:
    - ``header``: block_id of the loop header
    - ``back_edge_source``: block_id of the back-edge source
    - ``body``: set of block_ids in the loop body
    """
    back_edges_list = [e for e in edges if e.edge_type == "back_edge"]
    if not back_edges_list:
        return []

    loops: list[dict[str, Any]] = []

    if graph is not None and NX_AVAILABLE:
        # Use networkx dominance for accurate loop body.
        try:
            entry = min(b.block_id for b in blocks if b.is_entry)
            nx.immediate_dominators(graph, entry)

            for be in back_edges_list:
                header = be.target_block
                body = {header}

                # Walk predecessors from back-edge source up to header.
                worklist = [be.source_block]
                while worklist:
                    node = worklist.pop()
                    if node in body:
                        continue
                    body.add(node)
                    for pred in graph.predecessors(node):
                        if pred not in body:
                            worklist.append(pred)

                loops.append({
                    "header": header,
                    "back_edge_source": be.source_block,
                    "body": body,
                })
        except _GRAPH_ERRORS:
            pass

    if not loops and back_edges_list:
        # Fallback: simple body approximation.
        {b.block_id: b for b in blocks}
        for be in back_edges_list:
            header = be.target_block
            # All blocks between header and source (inclusive) in order.
            block_ids = [b.block_id for b in blocks]
            try:
                h_idx = block_ids.index(header)
                s_idx = block_ids.index(be.source_block)
                body = set(block_ids[h_idx:s_idx + 1])
            except ValueError:
                body = {header, be.source_block}

            loops.append({
                "header": header,
                "back_edge_source": be.source_block,
                "body": body,
            })

    return loops


# ---------------------------------------------------------------------------
# Step 5b — Loop Tree (nesting hierarchy)
# ---------------------------------------------------------------------------


@dataclass
class NaturalLoop:
    """A single natural loop in the CFG."""

    header: int
    """Block-id of the loop header (dominator / back-edge target)."""

    back_edge_sources: list[int] = field(default_factory=list)
    """Block-ids that branch back to ``header``."""

    body: set[int] = field(default_factory=set)
    """All block-ids belonging to this loop (including ``header``)."""

    parent: NaturalLoop | None = field(default=None, repr=False)
    """Enclosing loop (``None`` for outermost / root loops)."""

    children: list[NaturalLoop] = field(default_factory=list)
    """Immediately nested child loops."""

    @property
    def nesting_depth(self) -> int:
        """0 for outermost loops, +1 for each level of nesting."""
        depth = 0
        cur = self.parent
        while cur is not None:
            depth += 1
            cur = cur.parent
        return depth

    @property
    def is_innermost(self) -> bool:
        """Return ``True`` if this loop has no nested children."""
        return len(self.children) == 0

    def __contains__(self, block_id: int) -> bool:
        return block_id in self.body

    def to_dict(self) -> dict[str, Any]:
        """Serialise this natural loop to a JSON-safe dict.

        Returns:
            Dict with ``header``, ``back_edge_sources``, ``body``,
            ``nesting_depth``, and ``children`` (header ids).
        """
        return {
            "header": self.header,
            "back_edge_sources": self.back_edge_sources,
            "body": sorted(self.body),
            "nesting_depth": self.nesting_depth,
            "children": [c.header for c in self.children],
        }


class LoopTree:
    """Hierarchical representation of all natural loops in the CFG.

    Builds a nesting forest from the flat list returned by
    :func:`detect_natural_loops`.  Two loops are in a parent/child
    relationship when the child's body is a strict subset of the
    parent's body.  Loops with identical headers are merged.
    """

    def __init__(self, loops: list[dict[str, Any]] | None = None) -> None:
        self._loops_by_header: dict[int, NaturalLoop] = {}
        self.roots: list[NaturalLoop] = []
        if loops:
            self._build(loops)

    # -- construction -------------------------------------------------------

    def _build(self, raw_loops: list[dict[str, Any]]) -> None:
        """Merge duplicate headers & compute nesting."""
        # 1. Merge raw dicts into NaturalLoop objects by header
        for raw in raw_loops:
            hdr = raw["header"]
            if hdr in self._loops_by_header:
                nl = self._loops_by_header[hdr]
                nl.body |= raw.get("body", set())
                src = raw.get("back_edge_source")
                if src is not None and src not in nl.back_edge_sources:
                    nl.back_edge_sources.append(src)
            else:
                nl = NaturalLoop(
                    header=hdr,
                    back_edge_sources=[raw["back_edge_source"]]
                    if "back_edge_source" in raw
                    else [],
                    body=set(raw.get("body", set())),
                )
                self._loops_by_header[hdr] = nl

        all_loops = list(self._loops_by_header.values())

        # 2. Sort by body size descending so outer loops come first
        all_loops.sort(key=lambda lp: len(lp.body), reverse=True)

        # 3. Build nesting: child's body ⊂ parent's body
        for i, inner in enumerate(all_loops):
            best_parent: NaturalLoop | None = None
            best_size = float("inf")
            for j, outer in enumerate(all_loops):
                if i == j:
                    continue
                # strict subset
                if inner.body < outer.body and len(outer.body) < best_size:
                    best_parent = outer
                    best_size = len(outer.body)
            if best_parent is not None:
                inner.parent = best_parent
                best_parent.children.append(inner)

        self.roots = [lp for lp in all_loops if lp.parent is None]

    # -- queries ------------------------------------------------------------

    @property
    def all_loops(self) -> list[NaturalLoop]:
        """Return a flat list of every :class:`NaturalLoop`."""
        return list(self._loops_by_header.values())

    @property
    def loop_count(self) -> int:
        """Total number of distinct natural loops."""
        return len(self._loops_by_header)

    @property
    def max_depth(self) -> int:
        """Maximum nesting depth across all loops (0 if no loops)."""
        if not self._loops_by_header:
            return 0
        return max(lp.nesting_depth for lp in self._loops_by_header.values())

    def get_loop(self, header: int) -> NaturalLoop | None:
        """Return the loop with *header*, or ``None``."""
        return self._loops_by_header.get(header)

    def innermost_loops(self) -> list[NaturalLoop]:
        """Return all leaf (innermost) loops."""
        return [lp for lp in self._loops_by_header.values() if lp.is_innermost]

    def loop_for_block(self, block_id: int) -> NaturalLoop | None:
        """Return the *innermost* loop containing ``block_id``."""
        best: NaturalLoop | None = None
        best_size = float("inf")
        for lp in self._loops_by_header.values():
            if block_id in lp.body and len(lp.body) < best_size:
                best = lp
                best_size = len(lp.body)
        return best

    def is_reducible(self) -> bool:
        """Check if all loops have a single header (natural loops).

        Always ``True`` after construction from
        :func:`detect_natural_loops` which produces natural loops by
        definition, but useful as a guard after manual edits.
        """
        return all(lp.header in lp.body for lp in self._loops_by_header.values())

    def to_dict(self) -> dict[str, Any]:
        """Serialise the full loop tree to a JSON-safe dict.

        Returns:
            Dict with ``loop_count``, ``max_depth``, ``reducible``, ``loops``.
        """
        return {
            "loop_count": self.loop_count,
            "max_depth": self.max_depth,
            "reducible": self.is_reducible(),
            "loops": [lp.to_dict() for lp in self._loops_by_header.values()],
        }

    def __len__(self) -> int:
        return self.loop_count

    def __bool__(self) -> bool:
        return self.loop_count > 0


def build_loop_tree(
    blocks: list[HandlerBasicBlock],
    edges: list[CFGEdge],
    graph: Any = None,
) -> LoopTree:
    """Build a :class:`LoopTree` from the CFG. Convenience wrapper."""
    flat = detect_natural_loops(blocks, edges, graph)
    return LoopTree(flat)


# ---------------------------------------------------------------------------
# Public API — build_handler_cfg
# ---------------------------------------------------------------------------


def build_handler_cfg(
    opcode_table: SemanticOpcodeTable,
    boundaries: Sequence[HandlerBoundary],
    trace: Any = None,
) -> HandlerCFG:
    """Build the handler-level CFG from the opcode table and boundaries.

    This is the main entry point.  Steps:

    1. Walk the trace bytecode to produce :class:`VMInstruction` objects.
    2. Identify basic-block leaders.
    3. Partition instructions into :class:`HandlerBasicBlock`.
    4. Build control-flow edges.
    5. Detect natural loops.
    6. Construct a networkx DiGraph (if available).

    Args:
        opcode_table: Semantic opcode table from handler analysis.
        boundaries: Handler boundaries in execution order.
        trace: Optional execution trace (unused currently, reserved for
            future bytecode-from-memory extraction).

    Returns:
        A :class:`HandlerCFG` containing blocks, edges, and a
        networkx graph.
    """
    # Step 1: Walk
    vm_insns = walk_trace_bytecode(opcode_table, boundaries)

    if not vm_insns:
        return HandlerCFG()

    # Step 2–3: Leaders + partition
    leaders = _identify_leaders(vm_insns)
    blocks = _partition_into_blocks(vm_insns, leaders)

    if not blocks:
        return HandlerCFG(vm_instructions=vm_insns)

    # Step 4: Edges
    edges = _build_edges(blocks, vm_insns)

    # Step 5: Build graph
    graph = _build_nx_graph(blocks, edges)

    # Step 6: Annotate back-edges for loop detection
    loops = detect_natural_loops(blocks, edges, graph)
    lt: LoopTree | None = None
    if loops:
        logger.debug(
            "Detected %d natural loops in handler CFG", len(loops),
        )
        lt = LoopTree(loops)

    cfg = HandlerCFG(
        blocks=blocks,
        edges=edges,
        graph=graph,
        entry_block_id=blocks[0].block_id,
        vm_instructions=vm_insns,
        loop_tree=lt,
    )

    return cfg


# ---------------------------------------------------------------------------
# Static bytecode walker (with optional rolling-key decryption)
# ---------------------------------------------------------------------------


def walk_static_bytecode(
    bytecode: bytes,
    opcode_table: SemanticOpcodeTable,
    start_vip: int = 0,
    *,
    max_instructions: int = 10000,
    decryptor: Any = None,
) -> list[VMInstruction]:
    """Disassemble raw VM bytecode statically.

    This walks the bytecode from *start_vip* and decodes each opcode
    using the opcode table.  No execution trace is required — this is
    purely a static disassembly of the VM program.

    When a *decryptor*
    (:class:`~dragonslayer.analysis.bytecode_decrypt.BytecodeDecryptor`)
    is provided, each opcode byte is decrypted via the rolling-key
    transform **before** lookup in the opcode table.  Operand bytes
    after the opcode are NOT encrypted in standard VMProtect and are
    left unchanged.

    Args:
        bytecode: Raw VM bytecode bytes.
        opcode_table: Semantic opcode table mapping opcodes → handlers.
        start_vip: Starting virtual address.
        max_instructions: Safety limit.
        decryptor: Optional ``BytecodeDecryptor`` for encrypted bytecodes.

    Returns:
        Ordered list of :class:`VMInstruction`.
    """
    if not bytecode:
        return []

    # Build opcode → entry lookup.
    opcode_map: dict[int, OpcodeTableEntry] = {}
    for te in opcode_table.entries:
        opcode_map[te.opcode] = te

    # Determine opcode width from the table entries.
    max_opcode = max(opcode_map.keys(), default=0)
    opcode_width = 2 if max_opcode > 255 else 1

    # Rolling-key state (when decryptor is provided).
    has_decrypt = decryptor is not None and hasattr(decryptor, "decrypt_single")
    rolling_key: int = 0
    if has_decrypt:
        rolling_key = getattr(decryptor, "initial_key", 0)
        # Ensure opcode widths agree.
        dec_width = getattr(decryptor, "opcode_width", opcode_width)
        if dec_width != opcode_width:
            logger.debug(
                "Decryptor opcode_width=%d != table-inferred width=%d; "
                "using decryptor's width.", dec_width, opcode_width,
            )
            opcode_width = dec_width

    instructions: list[VMInstruction] = []
    offset = 0
    visited_offsets: set[int] = set()

    while offset < len(bytecode) and len(instructions) < max_instructions:
        if offset in visited_offsets:
            # Avoid infinite loops in static disassembly.
            break
        visited_offsets.add(offset)

        # Read raw (possibly encrypted) opcode.
        if opcode_width == 1 and offset < len(bytecode):
            raw_opcode = bytecode[offset]
        elif opcode_width == 2 and offset + 1 < len(bytecode):
            raw_opcode = int.from_bytes(
                bytecode[offset:offset + 2], byteorder="little",
            )
        else:
            break

        # Decrypt opcode if a rolling-key decryptor is active.
        if has_decrypt:
            opcode_val, rolling_key = decryptor.decrypt_single(
                raw_opcode, rolling_key,
            )
        else:
            opcode_val = raw_opcode

        entry = opcode_map.get(opcode_val)
        vip = start_vip + offset

        if entry is not None:
            delta = entry.vip_delta if entry.vip_delta > 0 else opcode_width
            # Extract any operand bytes after the opcode (NOT encrypted).
            operand_start = offset + opcode_width
            operand_end = offset + delta
            operand_bytes = bytecode[operand_start:operand_end] if operand_end > operand_start else b""

            insn = VMInstruction(
                vip=vip,
                opcode=opcode_val,
                handler_address=entry.handler_address,
                operation=entry.semantic.operation,
                vip_delta=delta,
                operand_bytes=operand_bytes,
                confidence=entry.semantic.confidence,
            )
        else:
            # Unknown opcode — assume 1-byte advance.
            insn = VMInstruction(
                vip=vip,
                opcode=opcode_val,
                handler_address=0,
                operation=VMOperation.UNKNOWN,
                vip_delta=opcode_width,
            )

        instructions.append(insn)
        offset += insn.vip_delta

        # Stop at return instructions.
        if insn.is_return():
            break

    return instructions


def build_static_cfg(
    bytecode: bytes,
    opcode_table: SemanticOpcodeTable,
    start_vip: int = 0,
    *,
    max_instructions: int = 10000,
    decryptor: Any = None,
) -> HandlerCFG:
    """Build a handler-level CFG from raw bytecode (static disassembly).

    Same as :func:`build_handler_cfg` but works from raw bytes instead
    of an execution trace.  Pass a *decryptor*
    (:class:`~dragonslayer.analysis.bytecode_decrypt.BytecodeDecryptor`)
    to transparently handle VMProtect's rolling-key opcode encryption.
    """
    vm_insns = walk_static_bytecode(
        bytecode, opcode_table, start_vip,
        max_instructions=max_instructions,
        decryptor=decryptor,
    )

    if not vm_insns:
        return HandlerCFG()

    leaders = _identify_leaders(vm_insns)
    blocks = _partition_into_blocks(vm_insns, leaders)

    if not blocks:
        return HandlerCFG(vm_instructions=vm_insns)

    edges = _build_edges(blocks, vm_insns)
    graph = _build_nx_graph(blocks, edges)
    loops = detect_natural_loops(blocks, edges, graph)
    lt: LoopTree | None = None
    if loops:
        lt = LoopTree(loops)

    return HandlerCFG(
        blocks=blocks,
        edges=edges,
        graph=graph,
        entry_block_id=blocks[0].block_id if blocks else 0,
        vm_instructions=vm_insns,
        loop_tree=lt,
    )
