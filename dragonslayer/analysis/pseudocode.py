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

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

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
    NX_AVAILABLE = True
except ImportError:
    nx = None  # type: ignore[assignment]
    NX_AVAILABLE = False

# ---------------------------------------------------------------------------
# Data-classes
# ---------------------------------------------------------------------------


@dataclass
class PseudocodeResult:
    """Output of pseudocode emission."""

    text: str = ""
    line_count: int = 0
    style: str = "linear"   # "linear" | "structured" | "c_like"
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
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
_OP_TEMPLATES: Dict[str, str] = {
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


# ---------------------------------------------------------------------------
# Linear emission
# ---------------------------------------------------------------------------

def emit_linear(
    opcode_table: SemanticOpcodeTable,
    boundaries: List[HandlerBoundary],
) -> PseudocodeResult:
    """Emit a linear pseudocode listing (no control-flow structuring).

    Uses def-use chain tracking to name variables by the handler that
    produced them, rather than sequential numbering.
    """
    lines: List[str] = []
    warnings: List[str] = []
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

    _OP_PREFIX: Dict[str, str] = {
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
        self._counters: Dict[str, int] = {}
        self._stack: List[str] = []  # simulated VM stack of variable names
        self._last_def: Optional[str] = None

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

    def define(self, op: str) -> str:
        """Create a new SSA variable for the result of *op*."""
        name = self._next_name(op)
        self._last_def = name
        return name

    def consume_binary(self, op: str) -> tuple[str, str, str]:
        """Pop two operands, define result. Returns (dst, src2, src1)."""
        src2 = self.pop()
        src1 = self.pop()
        dst = self.define(op)
        self.push(dst)
        return dst, src1, src2

    def consume_unary(self, op: str) -> tuple[str, str]:
        """Pop one operand, define result. Returns (dst, src)."""
        src = self.pop()
        dst = self.define(op)
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
    """Format one pseudocode line using SSA def-use chain naming."""
    op = entry.semantic.operation
    template = _OP_TEMPLATES.get(op, f"/* {op} */")

    imm = f"0x{entry.vip_delta:X}" if entry.vip_delta else "0"
    label = f"loc_{boundary.vip_value + entry.vip_delta:#x}" if entry.vip_delta else "loc_next"

    # Model VM stack operations
    if op in _BINARY_OPS:
        dst, src, src2 = namer.consume_binary(op)
    elif op in _UNARY_OPS:
        dst, src = namer.consume_unary(op)
        src2 = "0"
    elif op in _CMP_OPS:
        src2 = namer.pop()
        src = namer.pop()
        dst = "flags"
    elif op == VMOperation.PUSH:
        # PUSH puts a value on the stack — name it by the immediate/address
        name = namer.define(op)
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
        dst = namer.define(op)
        namer.push(dst)
        src = addr_var
        src2 = "0"
    elif op == VMOperation.STORE:
        # Memory store: pop value and address
        val = namer.pop()
        addr_var = namer.pop() if namer._stack else "addr"
        dst = addr_var
        src = val
        src2 = "0"
    elif op in (VMOperation.JMP, VMOperation.JCC):
        dst = "pc"
        src = namer.peek() if namer._stack else "0"
        src2 = "0"
    elif op == VMOperation.CALL:
        src = namer.pop() if namer._stack else "target"
        dst = "retval"
        src2 = "0"
    elif op == VMOperation.RET:
        dst = ""; src = ""; src2 = ""
    else:
        # NOP / UNKNOWN
        dst = ""; src = ""; src2 = ""

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
    boundaries: List[HandlerBoundary],
    handler_cfg: Any = None,
) -> PseudocodeResult:
    """Emit structured pseudocode using handler-level CFG.

    Falls back to :func:`emit_linear` if no CFG is provided or
    networkx is unavailable.
    """
    if handler_cfg is None or not NX_AVAILABLE:
        return emit_linear(opcode_table, boundaries)

    lines: List[str] = []
    warnings: List[str] = []
    namer = _DefUseNamer()

    # Detect back-edges (loops).
    # Graph nodes can be handler addresses OR boundary indices — detect both.
    back_edge_target_indices: set[int] = set()
    back_edge_target_addrs: set[int] = set()
    if NX_AVAILABLE and handler_cfg is not None:
        try:
            for u, v, data in handler_cfg.edges(data=True):
                if data.get("type") == "back_edge":
                    back_edge_target_indices.add(v)
                    back_edge_target_addrs.add(v)
        except Exception:
            pass

    # Map boundary index to handler address for back-edge matching
    boundary_addrs = {i: b.handler_address for i, b in enumerate(boundaries)}

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

        if entry is None:
            line = f"/* vIP={boundary.vip_value:#x} unknown */"
            warnings.append(f"No entry for 0x{boundary.handler_address:X}")
        else:
            op = entry.semantic.operation

            # Structured control-flow.
            if op == VMOperation.JCC:
                lines.append(f"    if (flags) {{")
                lines.append(f"      goto loc_{boundary.vip_value + entry.vip_delta:#x};")
                lines.append(f"    }}")
                continue
            elif op == VMOperation.JMP:
                target_vip = boundary.vip_value + entry.vip_delta
                lines.append(f"    goto loc_{target_vip:#x};")
                continue
            elif op == VMOperation.RET:
                lines.append(f"    return;")
                continue

            line = _format_instruction_ssa(entry, boundary, i, namer)

        addr_prefix = f"    /* {boundary.vip_value:#x} */  "
        lines.append(addr_prefix + line)

    # Close any open loops.
    if back_edge_target_indices or back_edge_target_addrs:
        lines.append("  }")

    text = "\n".join(lines)
    return PseudocodeResult(
        text=text,
        line_count=len(lines),
        style="structured",
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# C-like wrapper
# ---------------------------------------------------------------------------

def emit_c_like(
    opcode_table: SemanticOpcodeTable,
    boundaries: List[HandlerBoundary],
    handler_cfg: Any = None,
    *,
    function_name: str = "vm_func",
) -> PseudocodeResult:
    """Emit C-like pseudocode wrapped in a function declaration."""
    inner = emit_structured(opcode_table, boundaries, handler_cfg)

    header_lines = [
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
        width = 8 if any(
            e.semantic.operand_width == 8 for e in opcode_table.entries
        ) else 4
        type_name = "uint64_t" if width == 8 else "uint32_t"
        sorted_vars = sorted(var_names)
        # Group declarations by prefix for readability
        var_decls = ", ".join(sorted_vars)
        header_lines.append(f"  {type_name} {var_decls};")
        header_lines.append("")

    footer_lines = ["}", ""]
    body = inner.text

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
    boundaries: List[HandlerBoundary],
    handler_cfg: Any = None,
    *,
    style: str = "c_like",
    function_name: str = "vm_func",
) -> PseudocodeResult:
    """Emit pseudocode in the requested style.

    Args:
        opcode_table: Semantic opcode table.
        boundaries: Handler boundaries in execution order.
        handler_cfg: Optional networkx DiGraph (handler-level CFG).
        style: One of ``"linear"``, ``"structured"``, ``"c_like"``.
        function_name: Function name for C-like output.

    Returns:
        A :class:`PseudocodeResult`.
    """
    if style == "linear":
        return emit_linear(opcode_table, boundaries)
    elif style == "structured":
        return emit_structured(opcode_table, boundaries, handler_cfg)
    elif style == "c_like":
        return emit_c_like(opcode_table, boundaries, handler_cfg,
                           function_name=function_name)
    else:
        return emit_linear(opcode_table, boundaries)
