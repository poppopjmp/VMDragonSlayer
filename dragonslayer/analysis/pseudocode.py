"""
Pseudocode Emission
====================

Converts a :class:`~..handler_semantics.SemanticOpcodeTable` and
(optionally) a handler-level CFG into human-readable pseudocode that
represents the devirtualised VM program.

Three output levels:

1. **Linear listing** — one line per VM instruction, no control-flow
   reconstruction.  Fast, always available.
2. **Structured pseudocode** — uses the handler-level CFG to emit
   ``if/else``, ``while``, and ``goto`` constructs.
3. **C-like output** — wraps the above in a function with typed
   variables.

Usage::

    from dragonslayer.analysis.pseudocode import (
        emit_pseudocode,
        emit_linear,
        PseudocodeResult,
    )

    result = emit_pseudocode(opcode_table, boundaries, handler_cfg)
    print(result.text)
"""

from __future__ import annotations

import contextlib
import logging
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
except ImportError:
    nx = None  # type: ignore[assignment]
    NX_AVAILABLE = False

_GRAPH_ERRORS: tuple[type[Exception], ...] = (
    ValueError, TypeError, KeyError, AttributeError, IndexError, RuntimeError,
    ImportError,
)
if NX_AVAILABLE:
    _GRAPH_ERRORS = (*_GRAPH_ERRORS, nx.NetworkXError)

# ---------------------------------------------------------------------------
# Data-classes
# ---------------------------------------------------------------------------


@dataclass
class PseudocodeResult:
    """Output of pseudocode emission."""

    text: str = ""
    line_count: int = 0
    style: str = "linear"   # "linear" | "structured" | "c_like"
    warnings: list[str] = field(default_factory=list)
    var_widths: dict[str, int] = field(default_factory=dict)
    """Mapping of SSA variable name → operand width in bytes."""

    def to_dict(self) -> dict[str, Any]:
        """Serialise pseudocode metadata and text to a JSON-compatible dict."""
        return {
            "line_count": self.line_count,
            "style": self.style,
            "warning_count": len(self.warnings),
            "text": self.text,
        }


# ---------------------------------------------------------------------------
# Operation → pseudocode templates
# ---------------------------------------------------------------------------

# Each template uses {dst}, {src}, {src2}, {imm}, {label} placeholders.
_OP_TEMPLATES: dict[str, str] = {
    VMOperation.ADD:   "{dst} = {src} + {src2}",
    VMOperation.SUB:   "{dst} = {src} - {src2}",
    VMOperation.MUL:   "{dst} = {src} * {src2}",
    VMOperation.DIV:   "{dst} = {src} / {src2}",
    VMOperation.AND:   "{dst} = {src} & {src2}",
    VMOperation.OR:    "{dst} = {src} | {src2}",
    VMOperation.XOR:   "{dst} = {src} ^ {src2}",
    VMOperation.NOT:   "{dst} = ~{src}",
    VMOperation.NEG:   "{dst} = -{src}",
    VMOperation.SHL:   "{dst} = {src} << {src2}",
    VMOperation.SHR:   "{dst} = {src} >> {src2}",
    VMOperation.ROL:   "{dst} = ROL({src}, {src2})",
    VMOperation.ROR:   "{dst} = ROR({src}, {src2})",
    VMOperation.LOAD:  "{dst} = *({src})",
    VMOperation.STORE: "*({dst}) = {src}",
    VMOperation.PUSH:  "push({src})",
    VMOperation.POP:   "{dst} = pop()",
    VMOperation.CMP:   "flags = cmp({src}, {src2})",
    VMOperation.TEST:  "flags = test({src}, {src2})",
    VMOperation.JMP:   "goto {label}",
    VMOperation.JCC:   "if (flags) goto {label}",
    VMOperation.CALL:  "call({src})",
    VMOperation.RET:   "return",
    VMOperation.NOP:   "nop",
    VMOperation.UNKNOWN: "/* unknown handler 0x{handler_addr:X} */",
}

# Width-qualified load/store templates (used when operand_width is known).
# Maps operand_width in bytes → C-style pointer cast.
_WIDTH_CAST: dict[int, str] = {
    1: "BYTE",
    2: "WORD",
    4: "DWORD",
    8: "QWORD",
}

# Width → C type name for variable declarations.
_WIDTH_TYPE: dict[int, str] = {
    1: "uint8_t",
    2: "uint16_t",
    4: "uint32_t",
    8: "uint64_t",
}


# ---------------------------------------------------------------------------
# Linear emission
# ---------------------------------------------------------------------------

def emit_linear(
    opcode_table: SemanticOpcodeTable,
    boundaries: list[HandlerBoundary],
) -> PseudocodeResult:
    """Emit a linear pseudocode listing (no control-flow structuring).

    Uses def-use chain tracking to name variables by the handler that
    produced them, rather than sequential numbering.
    """
    lines: list[str] = []
    warnings: list[str] = []
    namer = _DefUseNamer()

    for i, boundary in enumerate(boundaries):
        entry = opcode_table.lookup_handler(boundary.handler_address)
        if entry is None:
            line = f"/* vIP={boundary.vip_value:#x} unknown handler 0x{boundary.handler_address:X} */"
            warnings.append(f"No semantic entry for handler 0x{boundary.handler_address:X}")
        else:
            line = _format_instruction_ssa(entry, boundary, i, namer)

        addr_prefix = f"  {boundary.vip_value:#010x}:  "
        lines.append(addr_prefix + line)

    text = "\n".join(lines)
    return PseudocodeResult(
        text=text,
        line_count=len(lines),
        style="linear",
        warnings=warnings,
        var_widths=namer.all_var_widths(),
    )


# Operations that produce a destination variable.
_PRODUCES_RESULT = {
    VMOperation.ADD, VMOperation.SUB, VMOperation.MUL, VMOperation.DIV,
    VMOperation.AND, VMOperation.OR, VMOperation.XOR,
    VMOperation.NOT, VMOperation.NEG,
    VMOperation.SHL, VMOperation.SHR, VMOperation.ROL, VMOperation.ROR,
    VMOperation.LOAD, VMOperation.POP,
}


def _format_instruction(
    entry: OpcodeTableEntry,
    boundary: HandlerBoundary,
    index: int,
    var_counter: int,
) -> str:
    """Format one pseudocode line (legacy sequential naming)."""
    op = entry.semantic.operation
    template = _OP_TEMPLATES.get(op, f"/* {op} */")

    dst = f"v{var_counter}"
    src = f"v{max(var_counter - 1, 0)}"
    src2 = f"v{max(var_counter - 2, 0)}"
    imm = f"0x{entry.vip_delta:X}" if entry.vip_delta else "0"
    label = f"loc_{boundary.vip_value + entry.vip_delta:#x}" if entry.vip_delta else "loc_next"

    try:
        return template.format(
            dst=dst, src=src, src2=src2, imm=imm, label=label,
            handler_addr=entry.handler_address,
        )
    except (KeyError, IndexError):
        return f"/* {op} (format error) */"


# ---------------------------------------------------------------------------
# Def-Use chain variable naming
# ---------------------------------------------------------------------------

class _DefUseNamer:
    """Track def-use chains for SSA-style pseudocode variable naming.

    Instead of sequential v0/v1/v2, variables are named by their
    semantic role and handler origin:

    * ``val_add_0`` — result of the first ADD handler
    * ``mem_load_3`` — result of the fourth LOAD handler
    * ``stk_pop_1`` — result of the second POP handler

    The operand stack models a VM stack machine: PUSH/POP handlers push
    and pop values, and binary ops consume two operands and push one
    result.
    """

    _OP_PREFIX: dict[str, str] = {
        VMOperation.ADD: "sum", VMOperation.SUB: "diff",
        VMOperation.MUL: "prod", VMOperation.DIV: "quot",
        VMOperation.AND: "band", VMOperation.OR: "bor",
        VMOperation.XOR: "bxor", VMOperation.NOT: "bnot",
        VMOperation.NEG: "neg", VMOperation.SHL: "shl",
        VMOperation.SHR: "shr", VMOperation.ROL: "rol",
        VMOperation.ROR: "ror", VMOperation.LOAD: "ld",
        VMOperation.POP: "stk", VMOperation.CMP: "cmp",
        VMOperation.TEST: "tst",
    }

    def __init__(self) -> None:
        self._counters: dict[str, int] = {}
        self._stack: list[str] = []  # simulated VM stack of variable names
        self._last_def: str | None = None
        # Track width (bytes) per variable name.
        self._var_widths: dict[str, int] = {}

    def _next_name(self, op: str) -> str:
        prefix = self._OP_PREFIX.get(op, "v")
        idx = self._counters.get(prefix, 0)
        self._counters[prefix] = idx + 1
        return f"{prefix}_{idx}"

    def push(self, name: str) -> None:
        self._stack.append(name)

    def pop(self) -> str:
        if self._stack:
            return self._stack.pop()
        # Fallback: unnamed stack slot
        idx = self._counters.get("arg", 0)
        self._counters["arg"] = idx + 1
        return f"arg_{idx}"

    def peek(self) -> str:
        return self._stack[-1] if self._stack else "???"

    def define(self, op: str, *, width: int = 0) -> str:
        """Create a new SSA variable for the result of *op*.

        If *width* is non-zero, record the operand width in bytes.
        """
        name = self._next_name(op)
        self._last_def = name
        if width > 0:
            self._var_widths[name] = width
        return name

    def var_width(self, name: str) -> int:
        """Return the recorded width for *name*, or 0 if unknown."""
        return self._var_widths.get(name, 0)

    def all_var_widths(self) -> dict[str, int]:
        """Return a copy of ``{var_name: width_bytes}``."""
        return dict(self._var_widths)

    def consume_binary(self, op: str, *, width: int = 0) -> tuple[str, str, str]:
        """Pop two operands, define result. Returns (dst, src2, src1)."""
        src2 = self.pop()
        src1 = self.pop()
        dst = self.define(op, width=width)
        self.push(dst)
        return dst, src1, src2

    def consume_unary(self, op: str, *, width: int = 0) -> tuple[str, str]:
        """Pop one operand, define result. Returns (dst, src)."""
        src = self.pop()
        dst = self.define(op, width=width)
        self.push(dst)
        return dst, src


# Binary operations that consume two stack operands and produce one result.
_BINARY_OPS = {
    VMOperation.ADD, VMOperation.SUB, VMOperation.MUL, VMOperation.DIV,
    VMOperation.AND, VMOperation.OR, VMOperation.XOR,
    VMOperation.SHL, VMOperation.SHR, VMOperation.ROL, VMOperation.ROR,
}

# Unary operations that consume one stack operand and produce one result.
_UNARY_OPS = {VMOperation.NOT, VMOperation.NEG}

# Comparison operations that consume two operands but produce flags.
_CMP_OPS = {VMOperation.CMP, VMOperation.TEST}


def _format_instruction_ssa(
    entry: OpcodeTableEntry,
    boundary: HandlerBoundary,
    index: int,
    namer: _DefUseNamer,
) -> str:
    """Format one pseudocode line using SSA def-use chain naming.

    When *entry.semantic.operand_width* is set (1/2/4/8 bytes), LOAD and
    STORE operations emit width-qualified pointer casts (e.g.
    ``*(DWORD*)(addr)``), and variables receive per-width type
    declarations in the C-like output.
    """
    op = entry.semantic.operation
    ow = entry.semantic.operand_width  # bytes: 0/1/2/4/8
    template = _OP_TEMPLATES.get(op, f"/* {op} */")

    imm = f"0x{entry.vip_delta:X}" if entry.vip_delta else "0"
    label = f"loc_{boundary.vip_value + entry.vip_delta:#x}" if entry.vip_delta else "loc_next"

    # Model VM stack operations
    if op in _BINARY_OPS:
        dst, src, src2 = namer.consume_binary(op, width=ow)
    elif op in _UNARY_OPS:
        dst, src = namer.consume_unary(op, width=ow)
        src2 = "0"
    elif op in _CMP_OPS:
        src2 = namer.pop()
        src = namer.pop()
        dst = "flags"
    elif op == VMOperation.PUSH:
        # PUSH puts a value on the stack — name it by the immediate/address
        name = namer.define(op, width=ow)
        namer.push(name)
        src = imm if imm != "0" else name
        dst = name
        src2 = "0"
    elif op == VMOperation.POP:
        name = namer.pop()
        dst = name
        src = name
        src2 = "0"
    elif op == VMOperation.LOAD:
        # Memory load: src is address (pop), result is loaded value
        addr_var = namer.pop() if namer._stack else "addr"
        dst = namer.define(op, width=ow)
        namer.push(dst)
        src = addr_var
        src2 = "0"
        # Width-qualified load: ld_0 = *(DWORD*)(addr_var)
        cast = _WIDTH_CAST.get(ow)
        if cast:
            return f"{dst} = *({cast}*)({src})"
        return template.format(
            dst=dst, src=src, src2=src2, imm=imm, label=label,
            handler_addr=entry.handler_address,
        )
    elif op == VMOperation.STORE:
        # Memory store: pop value and address
        val = namer.pop()
        addr_var = namer.pop() if namer._stack else "addr"
        dst = addr_var
        src = val
        src2 = "0"
        # Width-qualified store: *(DWORD*)(addr_var) = val
        cast = _WIDTH_CAST.get(ow)
        if cast:
            return f"*({cast}*)({dst}) = {src}"
        return template.format(
            dst=dst, src=src, src2=src2, imm=imm, label=label,
            handler_addr=entry.handler_address,
        )
    elif op in (VMOperation.JMP, VMOperation.JCC):
        dst = "pc"
        src = namer.peek() if namer._stack else "0"
        src2 = "0"
    elif op == VMOperation.CALL:
        src = namer.pop() if namer._stack else "target"
        dst = "retval"
        src2 = "0"
    elif op == VMOperation.RET:
        dst = ""
        src = ""
        src2 = ""
    else:
        # NOP / UNKNOWN
        dst = ""
        src = ""
        src2 = ""

    try:
        return template.format(
            dst=dst, src=src, src2=src2, imm=imm, label=label,
            handler_addr=entry.handler_address,
        )
    except (KeyError, IndexError):
        return f"/* {op} (format error) */"


# ---------------------------------------------------------------------------
# Structured emission (with CFG)
# ---------------------------------------------------------------------------

def emit_structured(
    opcode_table: SemanticOpcodeTable,
    boundaries: list[HandlerBoundary],
    handler_cfg: Any = None,
) -> PseudocodeResult:
    """Emit structured pseudocode using handler-level CFG.

    Falls back to :func:`emit_linear` if no CFG is provided or
    networkx is unavailable.
    """
    if handler_cfg is None or not NX_AVAILABLE:
        return emit_linear(opcode_table, boundaries)

    lines: list[str] = []
    warnings: list[str] = []
    namer = _DefUseNamer()
    open_loops = 0  # track how many while(true){ we've opened

    # Detect back-edges (loops).
    # Graph nodes can be handler addresses OR boundary indices — detect both.
    back_edge_target_indices: set[int] = set()
    back_edge_target_addrs: set[int] = set()
    if NX_AVAILABLE and handler_cfg is not None:
        try:
            for _u, v, data in handler_cfg.edges(data=True):
                if data.get("type") == "back_edge":
                    back_edge_target_indices.add(v)
                    back_edge_target_addrs.add(v)
        except _GRAPH_ERRORS:
            pass

    # Map boundary index to handler address for back-edge matching
    {i: b.handler_address for i, b in enumerate(boundaries)}

    for i, boundary in enumerate(boundaries):
        entry = opcode_table.lookup_handler(boundary.handler_address)

        # Emit loop header if this handler is a back-edge target.
        is_loop_target = (
            i in back_edge_target_indices
            or boundary.handler_address in back_edge_target_addrs
        )
        if is_loop_target:
            lines.append(f"  loop_{boundary.vip_value:#x}:")
            lines.append("  while (true) {")
            open_loops += 1

        if entry is None:
            line = f"/* vIP={boundary.vip_value:#x} unknown */"
            warnings.append(f"No entry for 0x{boundary.handler_address:X}")
        else:
            op = entry.semantic.operation

            # Structured control-flow.
            if op == VMOperation.JCC:
                lines.append("    if (flags) {")
                lines.append(f"      goto loc_{boundary.vip_value + entry.vip_delta:#x};")
                lines.append("    }")
                continue
            elif op == VMOperation.JMP:
                target_vip = boundary.vip_value + entry.vip_delta
                lines.append(f"    goto loc_{target_vip:#x};")
                continue
            elif op == VMOperation.RET:
                lines.append("    return;")
                continue

            line = _format_instruction_ssa(entry, boundary, i, namer)

        addr_prefix = f"    /* {boundary.vip_value:#x} */  "
        lines.append(addr_prefix + line)

    # Close any open loops — one closing brace per opened loop.
    for _ in range(open_loops):
        lines.append("  }")

    text = "\n".join(lines)
    return PseudocodeResult(
        text=text,
        line_count=len(lines),
        style="structured",
        warnings=warnings,
        var_widths=namer.all_var_widths(),
    )


# ═══════════════════════════════════════════════════════════════════════════
# Cifuentes-style structural analysis  (Batch 30)
# ═══════════════════════════════════════════════════════════════════════════
#
# The algorithm:
#  1. Walk blocks in reverse post-order (topological on the acyclic part).
#  2. Classify each block's outgoing edges → region type:
#     - Two conditional edges → if-then or if-then-else
#     - Single jump to a loop header → while / do-while
#     - Fallthrough only → sequence
#     - Multiple targets from a handler table → switch/case
#  3. Emit nested pseudocode via recursive region expansion.
#
# Key references:
#  - C. Cifuentes, "Reverse Compilation Techniques", Diss. QUT, 1994
#  - Van Emmerik & Cifuentes, "A Decompilation Framework", IR'2004
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class StructuredBlock:
    """A block within a structured region tree."""
    block_id: int = 0
    lines: list[str] = field(default_factory=list)
    is_loop_header: bool = False
    is_exit: bool = False


@dataclass
class StructuredRegion:
    """A structured control-flow region.

    ``kind`` is one of: ``"sequence"``, ``"if_then"``, ``"if_then_else"``,
    ``"while_loop"``, ``"do_while"``, ``"switch"``, ``"block"``.
    """
    kind: str = "block"
    condition: str = ""
    children: list[Any] = field(default_factory=list)   # StructuredRegion | StructuredBlock
    case_labels: list[str] = field(default_factory=list)  # switch/case


def _block_lines(
    block: Any,
    opcode_table: SemanticOpcodeTable,
    boundaries: list[HandlerBoundary],
    namer: _DefUseNamer,
    boundary_map: dict[int, int],
) -> list[str]:
    """Emit pseudocode lines for a single basic block.

    *boundary_map* maps ``handler_address → boundary index``.
    """
    lines: list[str] = []
    instructions = getattr(block, "instructions", [])
    for vm_insn in instructions:
        handler_addr = getattr(vm_insn, "handler_address", 0)
        bnd_idx = boundary_map.get(handler_addr)
        entry = opcode_table.lookup_handler(handler_addr)
        if entry is None:
            vip = getattr(vm_insn, "vip", 0)
            lines.append(f"/* vIP={vip:#x}  handler=0x{handler_addr:x} unknown */")
            continue
        op = entry.semantic.operation
        # Skip terminators — they'll be expressed structurally
        if op in (VMOperation.JMP, VMOperation.JCC, VMOperation.RET):
            continue
        if bnd_idx is not None:
            bnd = boundaries[bnd_idx]
            line = _format_instruction_ssa(entry, bnd, bnd_idx, namer)
        else:
            # Synthesise a boundary-like object
            vip = getattr(vm_insn, "vip", 0)
            fake_bnd = HandlerBoundary(
                handler_address=handler_addr,
                vip_value=vip,
                trace_index=0,
            )
            line = _format_instruction_ssa(entry, fake_bnd, 0, namer)
        lines.append(line)
    return lines


def _classify_block_outedges(
    block_id: int,
    cfg: Any,
) -> dict[str, Any]:
    """Classify the outgoing edges of *block_id*.

    Returns a dict with keys:
      ``edge_type`` → one of "unconditional", "conditional", "multi", "none"
      ``targets``   → list of (target_block_id, edge_type_string)
    """
    edges = []
    for e in getattr(cfg, "edges", []):
        src = getattr(e, "source_block", None)
        if src == block_id:
            tgt = getattr(e, "target_block", None)
            etype = getattr(e, "edge_type", "fallthrough")
            edges.append((tgt, etype))

    if not edges:
        return {"edge_type": "none", "targets": []}
    if len(edges) == 1:
        return {"edge_type": "unconditional", "targets": edges}

    # Two edges: one taken, one not-taken → conditional
    taken = [t for t in edges if t[1] in ("branch_taken", "jump")]
    not_taken = [t for t in edges if t[1] in ("branch_not_taken", "fallthrough")]
    if taken and not_taken:
        return {"edge_type": "conditional", "targets": edges,
                "taken": taken[0][0], "not_taken": not_taken[0][0]}

    # Multi-way → switch
    if len(edges) > 2:
        return {"edge_type": "multi", "targets": edges}

    # Default: conditional between any 2
    return {"edge_type": "conditional", "targets": edges,
            "taken": edges[0][0], "not_taken": edges[1][0]}


def _compute_immediate_postdominator(
    cfg_graph: Any,
    block_id: int,
    exit_ids: set,
) -> int | None:
    """Find the immediate post-dominator of *block_id*.

    Uses reverse-graph BFS convergence: if both branches of a conditional
    reach a common block, that is the immediate post-dominator (join point).
    Returns ``None`` if we cannot determine one.
    """
    if not NX_AVAILABLE or cfg_graph is None:
        return None

    # Build the reverse graph
    try:
        cfg_graph.reverse()
    except _GRAPH_ERRORS:
        return None

    # Find all exits (sinks in the forward graph)
    if not exit_ids:
        exit_ids = {n for n in cfg_graph.nodes() if cfg_graph.out_degree(n) == 0}
    if not exit_ids:
        return None

    # Compute dominators on the reverse graph from a virtual exit
    # Simpler approach: BFS from block_id on the forward graph, find
    # the first node where all paths converge.
    successors = list(cfg_graph.successors(block_id))
    if len(successors) < 2:
        return successors[0] if successors else None

    # BFS reachability from each successor
    from collections import deque

    def _reachable(start: int) -> set:
        visited: set[int] = set()
        q: deque[int] = deque([start])
        while q:
            n = q.popleft()
            if n in visited:
                continue
            visited.add(n)
            for s in cfg_graph.successors(n):
                if s != block_id:  # skip back to loop header
                    q.append(s)
        return visited

    reach_sets = [_reachable(s) | {s} for s in successors]
    # Intersection of reachable sets → common nodes
    common = reach_sets[0]
    for rs in reach_sets[1:]:
        common = common & rs
    if not common:
        return None

    # Among common nodes, pick the one closest to the block (shortest path)
    try:
        lengths = nx.single_source_shortest_path_length(cfg_graph, block_id)
        best = min(common, key=lambda n: lengths.get(n, 10**9))
        return best
    except _GRAPH_ERRORS:
        return min(common) if common else None


# ---------------------------------------------------------------------------
# Irreducible CFG detection & node-splitting  (Batch 35)
# ---------------------------------------------------------------------------

def is_reducible(cfg_graph: Any, entry: int | None = None) -> bool:
    """Test whether *cfg_graph* is reducible using the T1/T2 algorithm.

    A CFG is reducible iff repeated application of T1 (self-loop removal)
    and T2 (single-predecessor node collapse) reduces it to a single node.

    Returns ``True`` for reducible graphs and ``False`` for irreducible ones.
    If networkx is unavailable returns ``True`` (optimistic fallback).
    """
    if not NX_AVAILABLE or cfg_graph is None:
        return True

    g = cfg_graph.copy()

    changed = True
    while changed and len(g) > 1:
        changed = False

        # T1: remove self-loops
        self_loops = list(nx.selfloop_edges(g))
        if self_loops:
            g.remove_edges_from(self_loops)
            changed = True

        # T2: collapse nodes with exactly one predecessor (in-degree 1)
        to_remove: list[Any] = []
        for node in list(g.nodes()):
            if g.in_degree(node) == 1:
                pred = next(iter(g.predecessors(node)))
                if pred == node:
                    continue  # self-loop, handled by T1
                # Redirect all successors of node → pred
                for succ in list(g.successors(node)):
                    if succ != node and not g.has_edge(pred, succ):
                        g.add_edge(pred, succ)
                to_remove.append(node)

        if to_remove:
            g.remove_nodes_from(to_remove)
            changed = True

    return len(g) <= 1


def find_irreducible_sccs(
    cfg_graph: Any,
    entry: int | None = None,
) -> list[set]:
    """Return the strongly-connected components that make the CFG irreducible.

    An SCC is irreducible if it has multiple entry nodes (nodes reachable
    from outside the SCC by different paths).  Returns a list of sets of
    node IDs.  Empty list means the CFG is reducible.
    """
    if not NX_AVAILABLE or cfg_graph is None:
        return []

    irreducible: list[set] = []
    for scc_nodes in nx.strongly_connected_components(cfg_graph):
        if len(scc_nodes) <= 1:
            continue
        # Count entries: nodes that have a predecessor outside the SCC
        entries = set()
        for node in scc_nodes:
            for pred in cfg_graph.predecessors(node):
                if pred not in scc_nodes:
                    entries.add(node)
                    break
        if len(entries) > 1:
            irreducible.append(scc_nodes)

    return irreducible


def split_irreducible_scc(
    cfg_graph: Any,
    scc_nodes: set,
) -> Any:
    """Apply node-splitting to make an irreducible SCC reducible.

    Picks the SCC entry with the fewest in-edges from outside the SCC,
    duplicates it, and reconnects external predecessors to the clone.
    Returns a new graph.

    This is the classic technique from Janssen & Corporaal (1997):
    *"Making graphs reducible with controlled node splitting"*.
    """
    if not NX_AVAILABLE:
        return cfg_graph

    g = cfg_graph.copy()

    # Find entries: nodes with predecessors outside the SCC
    entries: list[Any] = []
    for node in scc_nodes:
        for pred in g.predecessors(node):
            if pred not in scc_nodes:
                entries.append(node)
                break

    if len(entries) <= 1:
        return g  # Already reducible

    # Pick the entry with the fewest external predecessors to split
    def _ext_pred_count(n: Any) -> int:
        return sum(1 for p in g.predecessors(n) if p not in scc_nodes)

    # Split the entry with the minimum external predecessors (but not the main entry)
    target = min(entries[1:], key=_ext_pred_count)

    # Create a clone node ID
    clone_id = max((n for n in g.nodes() if isinstance(n, int)), default=0) + 1

    # Add the clone with the same successor edges
    g.add_node(clone_id)
    for succ in list(g.successors(target)):
        g.add_edge(clone_id, succ)

    # Redirect external predecessors to the clone
    for pred in list(g.predecessors(target)):
        if pred not in scc_nodes:
            g.add_edge(pred, clone_id)
            g.remove_edge(pred, target)

    return g


def make_reducible(cfg_graph: Any, entry: int | None = None) -> Any:
    """Iteratively split nodes until the CFG becomes reducible.

    Returns a (possibly modified) copy of *cfg_graph*.  Limits to 10
    splitting rounds to avoid infinite loops on pathological graphs.
    """
    if not NX_AVAILABLE or cfg_graph is None:
        return cfg_graph

    g = cfg_graph.copy()
    for _ in range(10):
        sccs = find_irreducible_sccs(g, entry)
        if not sccs:
            break
        for scc in sccs:
            g = split_irreducible_scc(g, scc)
    return g


def structure_cfg(
    cfg: Any,
    opcode_table: SemanticOpcodeTable,
    boundaries: list[HandlerBoundary],
) -> StructuredRegion:
    """Perform Cifuentes-style structural analysis on a HandlerCFG.

    Returns a :class:`StructuredRegion` tree that can be emitted as
    nested pseudocode by :func:`emit_region`.
    """
    namer = _DefUseNamer()

    # Build boundary lookup
    boundary_map: dict[int, int] = {}
    for idx, bnd in enumerate(boundaries):
        boundary_map[bnd.handler_address] = idx

    # Get blocks and topo order
    blocks_by_id: dict[int, Any] = {}
    for b in getattr(cfg, "blocks", []):
        bid = getattr(b, "block_id", id(b))
        blocks_by_id[bid] = b

    topo: list[int] = []
    try:
        topo = cfg.topological_order()
    except _GRAPH_ERRORS:
        topo = sorted(blocks_by_id.keys())

    # Loop headers
    loop_headers: set[int] = set()
    with contextlib.suppress(_GRAPH_ERRORS):
        loop_headers = set(cfg.loop_headers())

    # Natural loops: header → body set
    loop_bodies: dict[int, set[int]] = {}
    try:
        from dragonslayer.analysis.bytecode_cfg import detect_natural_loops
        loops = detect_natural_loops(cfg)
        for lp in loops:
            hdr = lp.get("header") if isinstance(lp, dict) else getattr(lp, "header", None)
            body = lp.get("body") if isinstance(lp, dict) else getattr(lp, "body", set())
            if hdr is not None:
                loop_bodies[hdr] = set(body)
    except _GRAPH_ERRORS:
        pass

    # Exit blocks
    exit_ids: set[int] = set()
    try:
        exit_ids = set(cfg.exit_blocks())
    except _GRAPH_ERRORS:
        for bid, blk in blocks_by_id.items():
            if getattr(blk, "is_exit", False):
                exit_ids.add(bid)

    cfg_graph = getattr(cfg, "graph", None)

    # --- Irreducible CFG handling (B35) ---
    # If the CFG graph is irreducible, apply node-splitting to make it
    # amenable to Cifuentes structural analysis.
    if cfg_graph is not None and not is_reducible(cfg_graph):
        logger.info("Irreducible CFG detected — applying node splitting")
        cfg_graph = make_reducible(cfg_graph)

    # Track which blocks have been emitted
    emitted: set[int] = set()

    def _structure_block(bid: int) -> StructuredRegion:
        """Recursively structure from block *bid*."""
        if bid in emitted or bid not in blocks_by_id:
            return StructuredRegion(kind="block", children=[
                StructuredBlock(block_id=bid, lines=[f"goto block_{bid};"])
            ])
        emitted.add(bid)

        blk = blocks_by_id[bid]
        blk_lines = _block_lines(blk, opcode_table, boundaries, namer, boundary_map)
        sblk = StructuredBlock(
            block_id=bid,
            lines=blk_lines,
            is_loop_header=bid in loop_headers,
            is_exit=bid in exit_ids,
        )

        # Check if block is a loop header
        if bid in loop_headers and bid in loop_bodies:
            body_ids = loop_bodies[bid] - {bid}
            # Build loop body by structuring body blocks in topo order
            body_children = []
            body_topo = [b for b in topo if b in body_ids and b not in emitted]

            # Get loop condition from the terminator
            term = getattr(blk, "terminator", lambda: None)()
            cond = "true"
            if term is not None:
                top = getattr(term, "operation", None)
                if top is not None and str(top) in ("VMOperation.JCC", "JCC"):
                    cond = "flags"

            for child_bid in body_topo:
                body_children.append(_structure_block(child_bid))

            loop_region = StructuredRegion(
                kind="while_loop",
                condition=cond,
                children=[
                    StructuredRegion(kind="block", children=[sblk]),
                ] + body_children,
            )
            return loop_region

        # Classify outgoing edges
        out_info = _classify_block_outedges(bid, cfg)
        edge_type = out_info["edge_type"]

        if edge_type == "none":
            # Exit block (ret)
            term = getattr(blk, "terminator", lambda: None)()
            if term is not None:
                top = getattr(term, "operation", None)
                if top is not None and "RET" in str(top):
                    blk_lines.append("return;")
            return StructuredRegion(kind="block", children=[sblk])

        if edge_type == "unconditional":
            tgt = out_info["targets"][0][0]
            child = _structure_block(tgt)
            return StructuredRegion(kind="sequence", children=[
                StructuredRegion(kind="block", children=[sblk]),
                child,
            ])

        if edge_type == "conditional":
            taken_id = out_info.get("taken")
            not_taken_id = out_info.get("not_taken")

            # Find immediate post-dominator (join point)
            ipdom = _compute_immediate_postdominator(cfg_graph, bid, exit_ids)

            # Determine if this is if-then or if-then-else
            if taken_id == ipdom:
                # if (!cond) { not_taken_body } -- "if-then" on not-taken side
                not_taken_region = _structure_block(not_taken_id) if not_taken_id and not_taken_id not in emitted else None
                children = [StructuredRegion(kind="block", children=[sblk])]
                if not_taken_region:
                    children.append(StructuredRegion(
                        kind="if_then",
                        condition="!flags",
                        children=[not_taken_region],
                    ))
                if ipdom and ipdom not in emitted:
                    children.append(_structure_block(ipdom))
                return StructuredRegion(kind="sequence", children=children)

            elif not_taken_id == ipdom:
                # if (cond) { taken_body }
                taken_region = _structure_block(taken_id) if taken_id and taken_id not in emitted else None
                children = [StructuredRegion(kind="block", children=[sblk])]
                if taken_region:
                    children.append(StructuredRegion(
                        kind="if_then",
                        condition="flags",
                        children=[taken_region],
                    ))
                if ipdom and ipdom not in emitted:
                    children.append(_structure_block(ipdom))
                return StructuredRegion(kind="sequence", children=children)

            else:
                # if-then-else: both branches before the join
                taken_region = _structure_block(taken_id) if taken_id and taken_id not in emitted else None
                not_taken_region = _structure_block(not_taken_id) if not_taken_id and not_taken_id not in emitted else None
                children = [StructuredRegion(kind="block", children=[sblk])]
                if_else = StructuredRegion(
                    kind="if_then_else",
                    condition="flags",
                    children=[
                        taken_region or StructuredRegion(kind="block"),
                        not_taken_region or StructuredRegion(kind="block"),
                    ],
                )
                children.append(if_else)
                if ipdom and ipdom not in emitted:
                    children.append(_structure_block(ipdom))
                return StructuredRegion(kind="sequence", children=children)

        if edge_type == "multi":
            # Switch/case
            cases = []
            case_labels = []
            for tgt, _etype in out_info["targets"]:
                case_labels.append(f"case_{tgt}")
                cases.append(_structure_block(tgt) if tgt not in emitted else
                             StructuredRegion(kind="block", children=[
                                 StructuredBlock(block_id=tgt, lines=[f"goto block_{tgt};"])
                             ]))
            return StructuredRegion(
                kind="switch",
                condition="opcode",
                children=[StructuredRegion(kind="block", children=[sblk])] + cases,
                case_labels=case_labels,
            )

        # Fallback
        return StructuredRegion(kind="block", children=[sblk])

    # Start structuring from the entry block
    entry_bid = getattr(cfg, "entry_block_id", None)
    if entry_bid is None and topo:
        entry_bid = topo[0]

    if entry_bid is None:
        return StructuredRegion(kind="block")

    root = _structure_block(entry_bid)

    # Append any un-emitted blocks (disconnected or complex)
    leftover = [b for b in topo if b not in emitted]
    if leftover:
        extra = [_structure_block(b) for b in leftover]
        if root.kind == "sequence":
            root.children.extend(extra)
        else:
            root = StructuredRegion(kind="sequence", children=[root] + extra)

    return root


def emit_region(
    region: StructuredRegion,
    indent: int = 0,
) -> list[str]:
    """Recursively emit pseudocode lines from a :class:`StructuredRegion` tree."""
    pad = "    " * indent
    lines: list[str] = []

    if region.kind == "block":
        for child in region.children:
            if isinstance(child, StructuredBlock):
                for ln in child.lines:
                    lines.append(pad + ln)
            elif isinstance(child, StructuredRegion):
                lines.extend(emit_region(child, indent))

    elif region.kind == "sequence":
        for child in region.children:
            if isinstance(child, StructuredRegion):
                lines.extend(emit_region(child, indent))
            elif isinstance(child, StructuredBlock):
                for ln in child.lines:
                    lines.append(pad + ln)

    elif region.kind == "if_then":
        lines.append(f"{pad}if ({region.condition}) {{")
        for child in region.children:
            lines.extend(emit_region(child, indent + 1)
                         if isinstance(child, StructuredRegion)
                         else [f"{'    ' * (indent + 1)}{ln}" for ln in child.lines])
        lines.append(f"{pad}}}")

    elif region.kind == "if_then_else":
        lines.append(f"{pad}if ({region.condition}) {{")
        if len(region.children) >= 1:
            lines.extend(emit_region(region.children[0], indent + 1)
                         if isinstance(region.children[0], StructuredRegion)
                         else [])
        lines.append(f"{pad}}} else {{")
        if len(region.children) >= 2:
            lines.extend(emit_region(region.children[1], indent + 1)
                         if isinstance(region.children[1], StructuredRegion)
                         else [])
        lines.append(f"{pad}}}")

    elif region.kind == "while_loop":
        lines.append(f"{pad}while ({region.condition}) {{")
        for child in region.children:
            lines.extend(emit_region(child, indent + 1)
                         if isinstance(child, StructuredRegion)
                         else [f"{'    ' * (indent + 1)}{ln}" for ln in child.lines])
        lines.append(f"{pad}}}")

    elif region.kind == "switch":
        lines.append(f"{pad}switch ({region.condition}) {{")
        # First child is the block with the switch expression
        if region.children:
            lines.extend(emit_region(region.children[0], indent + 1)
                         if isinstance(region.children[0], StructuredRegion)
                         else [])
        # Subsequent children are cases
        for i, child in enumerate(region.children[1:]):
            label = region.case_labels[i] if i < len(region.case_labels) else f"case_{i}"
            lines.append(f"{pad}    {label}:")
            lines.extend(emit_region(child, indent + 2)
                         if isinstance(child, StructuredRegion)
                         else [])
            lines.append(f"{pad}        break;")
        lines.append(f"{pad}}}")

    return lines


def emit_cifuentes(
    opcode_table: SemanticOpcodeTable,
    boundaries: list[HandlerBoundary],
    handler_cfg: Any = None,
) -> PseudocodeResult:
    """Emit structured pseudocode using Cifuentes-style analysis.

    This is the recommended emission mode when a :class:`HandlerCFG`
    is available.  Falls back to :func:`emit_structured` (goto-based)
    if the CFG is missing.
    """
    if handler_cfg is None or not NX_AVAILABLE:
        return emit_structured(opcode_table, boundaries, handler_cfg)

    try:
        region = structure_cfg(handler_cfg, opcode_table, boundaries)
        lines = emit_region(region)
    except _GRAPH_ERRORS as exc:
        logger.warning("Cifuentes structuring failed (%s), falling back", exc)
        return emit_structured(opcode_table, boundaries, handler_cfg)

    text = "\n".join(lines)
    return PseudocodeResult(
        text=text,
        line_count=len(lines),
        style="cifuentes",
        warnings=[],
        var_widths={},
    )


# ---------------------------------------------------------------------------
# Context / Clustering annotation helpers (Batch 20)
# ---------------------------------------------------------------------------


def _extract_context_registers(context_layout: Any) -> dict[str, str]:
    """Extract role → register mapping from a VMContextLayout or dict.

    Returns an ordered dict like ``{"vSP": "rsp", "table_base": "rbx"}``.
    """
    if context_layout is None:
        return {}

    result: dict[str, str] = {}

    if isinstance(context_layout, dict):
        # From to_dict() output: look for known keys.
        for key in ("vsp", "table_base", "key_register", "context_base",
                     "vip_register"):
            val = context_layout.get(key)
            if val and isinstance(val, str):
                result[key] = val
        # Also check "registers" sub-dict.
        regs = context_layout.get("registers", {})
        if isinstance(regs, dict):
            for role, info in regs.items():
                reg = info.get("register") if isinstance(info, dict) else str(info)
                if reg:
                    result[role] = reg
    else:
        # VMContextLayout object — duck-type access.
        for attr in ("vsp", "table_base", "key_register", "context_base"):
            obj = getattr(context_layout, attr, None)
            if obj is not None:
                reg = getattr(obj, "register", None) or str(obj)
                if reg:
                    result[attr] = reg

    return result


def _extract_cluster_summary(clustering: Any) -> dict[str, int]:
    """Extract cluster_name → handler_count from clustering result.

    Returns an ordered dict like ``{"vm_add": 3, "vm_push": 2}``.
    """
    if clustering is None:
        return {}

    result: dict[str, int] = {}

    if isinstance(clustering, dict):
        clusters = clustering.get("clusters", [])
        for cl in clusters:
            if isinstance(cl, dict):
                name = cl.get("canonical_operation", cl.get("name", "unknown"))
                count = cl.get("handler_count", len(cl.get("members", [])))
                result[name] = count
    else:
        # ClusteringResult object.
        for cl in getattr(clustering, "clusters", []):
            name = getattr(cl, "canonical_operation", "unknown")
            count = len(getattr(cl, "members", []))
            result[name] = count

    return result


# ---------------------------------------------------------------------------
# Post-processing helpers (B43)
# ---------------------------------------------------------------------------

def _apply_context_renaming(
    text: str,
    context_layout: Any,
) -> str:
    """Replace generic register references with VM role names.

    If *context_layout* provides a mapping like ``{"vsp": "rsp",
    "vip_register": "rsi"}``, occurrences of ``rsp`` in the body are
    renamed to ``vSP`` and ``rsi`` to ``vIP``.  This makes the
    pseudocode significantly more readable.
    """
    if context_layout is None:
        return text

    import re as _re

    role_map = _extract_context_registers(context_layout)
    if not role_map:
        return text

    # Invert to register → pretty_name.
    _PRETTY: dict[str, str] = {
        "vsp": "vSP",
        "table_base": "hTable",
        "key_register": "vKey",
        "context_base": "vCtx",
        "vip_register": "vIP",
        "vip": "vIP",
    }
    rename_map: dict[str, str] = {}
    for role, reg in role_map.items():
        pretty = _PRETTY.get(role.lower(), role)
        rename_map[reg.lower()] = pretty

    for reg, pretty in rename_map.items():
        # Word-boundary replacement so we don't clobber substrings.
        text = _re.sub(rf"\b{_re.escape(reg)}\b", pretty, text,
                        flags=_re.IGNORECASE)

    return text


def _eliminate_trivial_dead(text: str) -> str:
    """Remove trivially dead variable assignments.

    A line ``  tmp_3 = some_value;`` is dead when ``tmp_3`` never
    appears on any other line.  This reduces noise from the SSA
    naming pass.
    """
    import re as _re

    lines = text.split("\n")
    # Identify assignments that define SSA-style vars.
    assignments: dict[int, str] = {}  # line_idx → var_name
    for i, ln in enumerate(lines):
        stripped = ln.strip()
        m = _re.match(r"([a-z]+_\d+)\s*=", stripped)
        if m:
            assignments[i] = m.group(1)

    if not assignments:
        return text

    # Count total mentions of each variable across all lines.
    full = "\n".join(lines)
    var_counts: dict[str, int] = {}
    for var in set(assignments.values()):
        var_counts[var] = len(_re.findall(rf"\b{_re.escape(var)}\b", full))

    # Remove lines where the variable appears only once (its definition).
    dead_indices: set = set()
    for i, var in assignments.items():
        if var_counts.get(var, 0) <= 1:
            dead_indices.add(i)

    if not dead_indices:
        return text

    result = [ln for i, ln in enumerate(lines) if i not in dead_indices]
    return "\n".join(result)


# ---------------------------------------------------------------------------
# C-like wrapper
# ---------------------------------------------------------------------------

def emit_c_like(
    opcode_table: SemanticOpcodeTable,
    boundaries: list[HandlerBoundary],
    handler_cfg: Any = None,
    *,
    function_name: str = "vm_func",
    context_layout: Any = None,
    clustering: Any = None,
) -> PseudocodeResult:
    """Emit C-like pseudocode wrapped in a function declaration.

    When a *handler_cfg* is available, uses Cifuentes-style structural
    analysis to produce proper ``if``/``else`` and ``while`` constructs
    instead of goto-based output.

    When *context_layout* is provided (dict or VMContextLayout), a VM
    context struct comment is emitted, virtual register names (vSP,
    vIP, etc.) appear in the header, and generic variable references
    are replaced with their VM role names.

    When *clustering* is provided (dict or ClusteringResult), canonical
    cluster operation names annotate the output.
    """
    # Use Cifuentes structuring when a CFG is present; fall back to goto-based.
    if handler_cfg is not None:
        inner = emit_cifuentes(opcode_table, boundaries, handler_cfg)
    else:
        inner = emit_structured(opcode_table, boundaries, handler_cfg)

    header_lines: list[str] = []

    # ── VM context layout annotation (Batch 20) ─────────────────────
    ctx_regs = _extract_context_registers(context_layout)
    if ctx_regs:
        header_lines.append("// VM Context Layout:")
        for role, reg in ctx_regs.items():
            header_lines.append(f"//   {role:16s} = {reg}")
        header_lines.append("")

    # ── Cluster summary annotation (Batch 20) ───────────────────────
    cluster_summary = _extract_cluster_summary(clustering)
    if cluster_summary:
        header_lines.append("// Semantic Clusters:")
        for cluster_name, count in cluster_summary.items():
            header_lines.append(f"//   {cluster_name}: {count} handler variant(s)")
        header_lines.append("")

    header_lines += [
        f"// Devirtualised from {len(boundaries)} VM instructions",
        f"// Unique handlers: {opcode_table.handler_count}",
        f"// Operations: {', '.join(opcode_table.operations_summary().keys())}",
        "",
        f"void {function_name}() {{",
    ]

    # Count distinct variable prefixes in the emitted code to declare them.
    import re as _re
    var_names = set(_re.findall(r"\b([a-z]+_\d+)\b", inner.text))
    if var_names:
        # Group variables by their width for per-type declarations.
        width_groups: dict[int, list[str]] = {}
        fallback_width = 8 if any(
            e.semantic.operand_width == 8 for e in opcode_table.entries
        ) else 4
        for vn in sorted(var_names):
            w = inner.var_widths.get(vn, 0)
            width_groups.setdefault(w, []).append(vn)

        # Emit typed declarations: known widths first, then fallback.
        for w in sorted(width_groups):
            names = width_groups[w]
            if w in _WIDTH_TYPE:
                type_name = _WIDTH_TYPE[w]
            else:
                type_name = _WIDTH_TYPE.get(fallback_width, "uint32_t")
            header_lines.append(f"  {type_name} {', '.join(names)};")
        header_lines.append("")

    footer_lines = ["}", ""]
    body = inner.text

    # ── Context-based variable renaming (B43) ───────────────────────
    body = _apply_context_renaming(body, context_layout)

    # ── Dead variable elimination (B43) ─────────────────────────────
    body = _eliminate_trivial_dead(body)

    # ── Expression simplification & type propagation (B47) ──────────
    from .expr_simplify import simplify_pseudocode as _simplify_pseudocode
    body = _simplify_pseudocode(body, var_widths=inner.var_widths or {})

    text = "\n".join(header_lines) + "\n" + body + "\n" + "\n".join(footer_lines)
    total_lines = text.count("\n") + 1

    return PseudocodeResult(
        text=text,
        line_count=total_lines,
        style="c_like",
        warnings=inner.warnings,
    )


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

def emit_pseudocode(
    opcode_table: SemanticOpcodeTable,
    boundaries: list[HandlerBoundary],
    handler_cfg: Any = None,
    *,
    style: str = "c_like",
    function_name: str = "vm_func",
    context_layout: Any = None,
    clustering: Any = None,
) -> PseudocodeResult:
    """Emit pseudocode in the requested style.

    Args:
        opcode_table: Semantic opcode table.
        boundaries: Handler boundaries in execution order.
        handler_cfg: Optional networkx DiGraph (handler-level CFG).
        style: One of ``"linear"``, ``"structured"``, ``"c_like"``,
            ``"cifuentes"``.
        function_name: Function name for C-like output.
        context_layout: Optional VM context layout (dict or VMContextLayout)
            from :func:`~..vm_discovery.context_registers.identify_vm_context`.
            If provided, virtual register names appear in pseudocode.
        clustering: Optional clustering result (dict or ClusteringResult)
            from :func:`~..handler_clustering.cluster_handlers_by_semantics`.
            If provided, canonical cluster names appear in comments.

    Returns:
        A :class:`PseudocodeResult`.
    """
    if style == "linear":
        return emit_linear(opcode_table, boundaries)
    elif style == "structured":
        return emit_structured(opcode_table, boundaries, handler_cfg)
    elif style == "cifuentes":
        return emit_cifuentes(opcode_table, boundaries, handler_cfg)
    elif style == "c_like":
        return emit_c_like(opcode_table, boundaries, handler_cfg,
                           function_name=function_name,
                           context_layout=context_layout,
                           clustering=clustering)
    else:
        return emit_linear(opcode_table, boundaries)
