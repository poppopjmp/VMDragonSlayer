"""
Trace Export System
===================

Export :class:`~dragonslayer.analysis.trace_ingestion.ExecutionTrace`
objects to multiple output formats.  Provides both a programmatic API
and a plugin-style format registry.

Supported formats
-----------------
- **JSON** — full-fidelity round-trip serialisation
- **FORMAT.md text** — line-oriented ``i:/m:/c:/h:`` format
  (complements :func:`~dragonslayer.analysis.trace_ingestion.parse_trace_text`)
- **CSV** — tabular instruction data for data-science workflows
- **IDA annotations** — JSON for IDA Pro plugin consumption
- **Ghidra script** — Jython script for Ghidra comment injection

Usage::

    from dragonslayer.analysis.trace_export import (
        export_trace, OutputFormat, list_formats,
    )

    # Export to JSON
    export_trace(trace, "output/trace.json", format=OutputFormat.JSON)

    # Export to FORMAT.md text
    text = render_trace_text(trace)

    # Export IDA annotations
    export_trace(trace, "ida_annot.json", format=OutputFormat.IDA)
"""

from __future__ import annotations

import csv
import io
import json
import logging
from collections.abc import Callable
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

from dragonslayer.analysis.trace_ingestion import (
    ExecutionTrace,
    TraceInstruction,
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Format registry
# ═══════════════════════════════════════════════════════════════════════════

class OutputFormat(Enum):
    """Supported output formats."""
    JSON = "json"
    TEXT = "text"       # FORMAT.md line-oriented
    CSV = "csv"
    IDA = "ida"         # IDA Pro annotation JSON
    GHIDRA = "ghidra"   # Ghidra Jython script


class TraceExporter(Protocol):
    """Protocol for trace format exporters."""

    def export(self, trace: ExecutionTrace) -> str:
        """Render the trace to a string."""
        ...  # pragma: no cover


# Internal registry: format → render function
_FORMAT_REGISTRY: dict[OutputFormat, Callable[[ExecutionTrace], str]] = {}


def _register_format(
    fmt: OutputFormat,
) -> Callable[[Callable[[ExecutionTrace], str]], Callable[[ExecutionTrace], str]]:
    """Decorator to register a render function for a format."""
    def decorator(
        fn: Callable[[ExecutionTrace], str],
    ) -> Callable[[ExecutionTrace], str]:
        _FORMAT_REGISTRY[fmt] = fn
        return fn
    return decorator


def list_formats() -> list[str]:
    """Return the names of all registered export formats."""
    return [f.value for f in _FORMAT_REGISTRY]


# ═══════════════════════════════════════════════════════════════════════════
# High-level API
# ═══════════════════════════════════════════════════════════════════════════

def export_trace(
    trace: ExecutionTrace,
    output_path: str,
    *,
    format: OutputFormat = OutputFormat.JSON,
    encoding: str = "utf-8",
) -> str:
    """Export a trace to *output_path* in the given *format*.

    Parameters
    ----------
    trace : ExecutionTrace
        The trace to export.
    output_path : str
        File path to write.  Parent directories are created if needed.
    format : OutputFormat
        Output format.
    encoding : str
        File encoding.

    Returns
    -------
    str
        The rendered string (same content written to file).
    """
    renderer = _FORMAT_REGISTRY.get(format)
    if renderer is None:
        raise ValueError(
            f"Unknown format {format!r}. Available: {list_formats()}"
        )

    rendered = renderer(trace)

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding=encoding)

    logger.info("Exported trace to %s (format=%s, %d bytes)", output_path, format.value, len(rendered))
    return rendered


def render_trace(
    trace: ExecutionTrace,
    format: OutputFormat = OutputFormat.JSON,
) -> str:
    """Render a trace to a string without writing to a file.

    Parameters
    ----------
    trace : ExecutionTrace
        The trace to render.
    format : OutputFormat
        Output format.

    Returns
    -------
    str
        The rendered trace content.
    """
    renderer = _FORMAT_REGISTRY.get(format)
    if renderer is None:
        raise ValueError(
            f"Unknown format {format!r}. Available: {list_formats()}"
        )
    return renderer(trace)


# ═══════════════════════════════════════════════════════════════════════════
# JSON format — full-fidelity round-trip
# ═══════════════════════════════════════════════════════════════════════════

@_register_format(OutputFormat.JSON)
def render_trace_json(trace: ExecutionTrace) -> str:
    """Render trace as full-fidelity JSON.

    Unlike ``ExecutionTrace.to_dict()`` (which only serialises summary
    counts), this includes *all* instructions, memory accesses, control
    flow edges, and handler markers.
    """
    data = {
        "version": "1.0",
        "source": trace.source,
        "metadata": trace.metadata,
        "instructions": [_instruction_to_dict(i) for i in trace.instructions],
        "memory_accesses": [i.to_dict() for i in trace.memory_accesses],
        "control_flow": [i.to_dict() for i in trace.control_flow],
        "handlers": [i.to_dict() for i in trace.handlers],
    }
    return json.dumps(data, indent=2, default=str)


def _instruction_to_dict(instr: TraceInstruction) -> dict[str, Any]:
    """Serialise a TraceInstruction to a JSON-compatible dict."""
    return {
        "address": instr.address,
        "size": instr.size,
        "raw_bytes": instr.raw_bytes.hex().upper() if instr.raw_bytes else "",
        "disassembly": instr.disassembly,
        "registers": instr.registers,
    }


# ═══════════════════════════════════════════════════════════════════════════
# FORMAT.md text — line-oriented trace format (round-trip writer)
# ═══════════════════════════════════════════════════════════════════════════

@_register_format(OutputFormat.TEXT)
def render_trace_text(trace: ExecutionTrace) -> str:
    """Render trace in FORMAT.md line-oriented format.

    Format::

        # DragonSlayer Trace v1.0
        # source: <source>
        i: <addr> | <size> | <bytes_hex> | <disasm> | <registers_csv>
        m: <R|W> | <addr> | <size> | <value>
        c: <type> | <source> | <target>
        h: <id> | <addr> | <type>

    This is the inverse of
    :func:`~dragonslayer.analysis.trace_ingestion.parse_trace_text`.
    """
    lines: list[str] = [
        "# DragonSlayer Trace v1.0",
        f"# source: {trace.source}",
    ]
    if trace.metadata:
        lines.append(f"# metadata: {json.dumps(trace.metadata, default=str)}")
    lines.append("---")

    for instr in trace.instructions:
        hex_bytes = instr.raw_bytes.hex().upper() if instr.raw_bytes else ""
        reg_csv = ",".join(
            f"{k}=0x{v:x}" for k, v in sorted(instr.registers.items())
        ) if instr.registers else ""
        lines.append(
            f"i: 0x{instr.address:x} | {instr.size} | {hex_bytes} | "
            f"{instr.disassembly} | {reg_csv}"
        )

    for mem in trace.memory_accesses:
        lines.append(
            f"m: {mem.type} | 0x{mem.address:x} | {mem.size} | 0x{mem.value:x}"
        )

    for cf in trace.control_flow:
        lines.append(
            f"c: {cf.type} | 0x{cf.source:x} | 0x{cf.target:x}"
        )

    for h in trace.handlers:
        lines.append(
            f"h: {h.handler_id} | 0x{h.address:x} | {h.handler_type}"
        )

    return "\n".join(lines) + "\n"


# ═══════════════════════════════════════════════════════════════════════════
# CSV format — tabular instruction data
# ═══════════════════════════════════════════════════════════════════════════

@_register_format(OutputFormat.CSV)
def render_trace_csv(trace: ExecutionTrace) -> str:
    """Render trace instructions as CSV.

    Columns: address, size, raw_bytes, disassembly, mnemonic, operands
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["address", "size", "raw_bytes", "disassembly", "mnemonic", "operands"])

    for instr in trace.instructions:
        parts = instr.disassembly.split(None, 1) if instr.disassembly else ["", ""]
        mnemonic = parts[0] if parts else ""
        operands = parts[1] if len(parts) > 1 else ""
        writer.writerow([
            f"0x{instr.address:x}",
            instr.size,
            instr.raw_bytes.hex().upper() if instr.raw_bytes else "",
            instr.disassembly,
            mnemonic,
            operands,
        ])

    return buf.getvalue()


# ═══════════════════════════════════════════════════════════════════════════
# IDA Pro annotations — JSON for IDA plugin consumption
# ═══════════════════════════════════════════════════════════════════════════

@_register_format(OutputFormat.IDA)
def render_ida_annotations(trace: ExecutionTrace) -> str:
    """Render IDA Pro annotation JSON.

    Produces a JSON file that the dragonslayer IDA plugin can import
    to set comments, colours, and function renames in IDA.

    Structure::

        {
          "version": "1.0",
          "annotations": [
            {"address": addr, "comment": str, "color": int | null},
            ...
          ],
          "functions": [
            {"address": addr, "name": str},
            ...
          ]
        }
    """
    annotations: list[dict[str, Any]] = []
    functions: list[dict[str, Any]] = []

    # Annotate handler boundaries
    for h in trace.handlers:
        annotations.append({
            "address": h.address,
            "comment": f"VM Handler #{h.handler_id} ({h.handler_type})",
            "color": 0x98FB98 if h.handler_type != "unknown" else 0xFFFF00,
        })
        functions.append({
            "address": h.address,
            "name": f"vm_handler_{h.handler_id}_{h.handler_type}",
        })

    # Annotate control flow edges with comment
    for cf in trace.control_flow:
        annotations.append({
            "address": cf.source,
            "comment": f"CF: {cf.type} -> 0x{cf.target:x}",
            "color": None,
        })

    # Annotate unique instruction addresses with execution counts
    from collections import Counter
    addr_counts: Counter[int] = Counter(i.address for i in trace.instructions)
    for addr, count in addr_counts.most_common():
        if count > 1:
            annotations.append({
                "address": addr,
                "comment": f"Executed {count}x",
                "color": 0xADD8E6,  # light blue for hot code
            })

    data = {
        "version": "1.0",
        "source": trace.source,
        "annotations": annotations,
        "functions": functions,
    }
    return json.dumps(data, indent=2)


# ═══════════════════════════════════════════════════════════════════════════
# Ghidra script — Jython script for comment injection
# ═══════════════════════════════════════════════════════════════════════════

@_register_format(OutputFormat.GHIDRA)
def render_ghidra_script(trace: ExecutionTrace) -> str:
    """Render a Ghidra Jython script that sets comments and bookmarks.

    The generated script calls ``setEOLComment()`` for handler markers
    and ``createBookmark()`` for handler entry points.
    """
    lines: list[str] = [
        "# Auto-generated by DragonSlayer trace_export",
        "# Import this script into Ghidra's Script Manager",
        "",
        "from ghidra.program.model.listing import CodeUnit",
        "from ghidra.program.model.address import AddressFactory",
        "",
        "listing = currentProgram.getListing()",
        "af = currentProgram.getAddressFactory()",
        "bm = currentProgram.getBookmarkManager()",
        "",
    ]

    for h in trace.handlers:
        addr_hex = f"0x{h.address:x}"
        comment = f"VM Handler #{h.handler_id} ({h.handler_type})"
        lines.append(f"# Handler {h.handler_id}")
        lines.append(f'addr = af.getDefaultAddressSpace().getAddress({addr_hex})')
        lines.append('cu = listing.getCodeUnitAt(addr)')
        lines.append('if cu is not None:')
        lines.append(f'    cu.setComment(CodeUnit.EOL_COMMENT, "{comment}")')
        lines.append(f'bm.setBookmark(addr, "Analysis", "VMHandler", "{comment}")')
        lines.append("")

    # Add execution heat annotations
    from collections import Counter
    addr_counts: Counter[int] = Counter(i.address for i in trace.instructions)
    hot_addrs = [addr for addr, count in addr_counts.most_common(50) if count > 1]

    if hot_addrs:
        lines.append("# Hot instruction addresses (executed multiple times)")
        for addr in hot_addrs:
            count = addr_counts[addr]
            addr_hex = f"0x{addr:x}"
            lines.append(f'addr = af.getDefaultAddressSpace().getAddress({addr_hex})')
            lines.append('cu = listing.getCodeUnitAt(addr)')
            lines.append('if cu is not None:')
            lines.append(f'    cu.setComment(CodeUnit.PLATE_COMMENT, "Executed {count}x")')
            lines.append("")

    lines.append('println("DragonSlayer annotations applied.")')
    return "\n".join(lines) + "\n"


# ═══════════════════════════════════════════════════════════════════════════
# Round-trip validation helper
# ═══════════════════════════════════════════════════════════════════════════

def validate_roundtrip(trace: ExecutionTrace) -> bool:
    """Validate that JSON export → re-import preserves instruction count.

    Returns *True* if instruction count matches after round-trip.
    """
    json_str = render_trace_json(trace)
    data = json.loads(json_str)
    return len(data.get("instructions", [])) == len(trace.instructions)
