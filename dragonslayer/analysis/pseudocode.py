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

    One line per boundary in execution order, using the semantic opcode
    table to look up operation names.
    """
    lines: List[str] = []
    warnings: List[str] = []
    var_counter = 0

    for i, boundary in enumerate(boundaries):
        entry = opcode_table.lookup_handler(boundary.handler_address)
        if entry is None:
            line = f"/* vIP={boundary.vip_value:#x} unknown handler 0x{boundary.handler_address:X} */"
            warnings.append(f"No semantic entry for handler 0x{boundary.handler_address:X}")
        else:
            line = _format_instruction(entry, boundary, i, var_counter)
            # Advance variable counter for ops that produce a result.
            if entry.semantic.operation in _PRODUCES_RESULT:
                var_counter += 1

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
    """Format one pseudocode line from an opcode table entry."""
    op = entry.semantic.operation
    template = _OP_TEMPLATES.get(op, f"/* {op} */")

    width = entry.semantic.operand_width or 4
    type_prefix = "q" if width == 8 else "d"

    # Generate variable names.
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
    var_counter = 0

    # Detect back-edges (loops).
    back_edge_targets = set()
    if NX_AVAILABLE and handler_cfg is not None:
        for u, v, data in handler_cfg.edges(data=True):
            if data.get("type") == "back_edge":
                back_edge_targets.add(v)

    for i, boundary in enumerate(boundaries):
        entry = opcode_table.lookup_handler(boundary.handler_address)

        # Emit loop header if this node is a back-edge target.
        if i in back_edge_targets:
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

            line = _format_instruction(entry, boundary, i, var_counter)
            if entry.semantic.operation in _PRODUCES_RESULT:
                var_counter += 1

        addr_prefix = f"    /* {boundary.vip_value:#x} */  "
        lines.append(addr_prefix + line)

    # Close any open loops.
    if back_edge_targets:
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

    # Declare variables.
    max_vars = sum(1 for b in boundaries
                   if opcode_table.lookup_handler(b.handler_address) is not None
                   and opcode_table.lookup_handler(b.handler_address).semantic.operation in _PRODUCES_RESULT)
    if max_vars > 0:
        width = 8 if any(
            e.semantic.operand_width == 8 for e in opcode_table.entries
        ) else 4
        type_name = "uint64_t" if width == 8 else "uint32_t"
        var_decls = ", ".join(f"v{i}" for i in range(max_vars))
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
