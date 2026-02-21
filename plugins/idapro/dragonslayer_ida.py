"""
VMDragonSlayer — IDA Pro Plugin
================================

Loads DragonSlayer analysis results and trace export annotations into IDA Pro.

Installation
------------
1. Copy this file to ``<IDA_INSTALL>/plugins/`` or add to IDA plugin path.
2. ``pip install vmdragonslayer`` in IDA's Python environment,
   **or** set ``VMDS_ANALYSIS_PATH`` to a pre-exported JSON.

Usage (Script)
--------------
Run via *File → Script File…* or *Alt+F7* in IDA::

    # Automatically analyses the current binary and applies annotations
    import dragonslayer_ida
    dragonslayer_ida.run()

Usage (Plugin)
--------------
After installing as IDA plugin, invoke via *Edit → Plugins → DragonSlayer*.

The plugin:
- Detects VM protection (VMProtect, Themida, Code Virtualizer)
- Sets IDA comments on handler entry points
- Colours handler basic blocks (green = classified, yellow = unknown)
- Creates bookmarks at VM entry and handler dispatch points
- Renames handler functions (``vm_handler_N_<category>``)
- Optionally imports pre-exported annotation JSON from trace_export
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("dragonslayer.ida")

# ── IDA API availability ────────────────────────────────────────────────

try:
    import idaapi  # type: ignore[import-untyped]
    import idc  # type: ignore[import-untyped]
    import ida_bytes  # type: ignore[import-untyped]
    import ida_name  # type: ignore[import-untyped]
    import ida_funcs  # type: ignore[import-untyped]
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False

# ── Annotation colours (IDA uses BGR) ───────────────────────────────────

COLOR_HANDLER_KNOWN = 0x98FB98     # Pale green
COLOR_HANDLER_UNKNOWN = 0x00FFFF   # Yellow
COLOR_HOT_CODE = 0xE6D8AD          # Light blue
COLOR_VM_ENTRY = 0x9370DB          # Medium purple

# ── Helpers ──────────────────────────────────────────────────────────────


def _set_comment(address: int, comment: str) -> None:
    """Set an IDA EOL comment at *address*."""
    if IDA_AVAILABLE:
        idc.set_cmt(address, comment, 0)


def _set_color(address: int, color: int) -> None:
    """Set background colour for address."""
    if IDA_AVAILABLE:
        idc.set_color(address, idc.CIC_ITEM, color)


def _rename_function(address: int, name: str) -> None:
    """Rename function at *address*."""
    if IDA_AVAILABLE:
        ida_name.set_name(address, name, ida_name.SN_CHECK)


def _add_bookmark(address: int, description: str) -> None:
    """Add a bookmark (marked position) in IDA."""
    if IDA_AVAILABLE:
        # Use next available slot
        for slot in range(1024):
            if idc.get_bookmark(slot) == idaapi.BADADDR:
                idc.put_bookmark(address, 0, 0, 0, slot, description)
                break


# ── Core annotation functions ────────────────────────────────────────────


def apply_annotations(annotations_json: Dict[str, Any]) -> int:
    """Apply annotation data from trace_export IDA format.

    Parameters
    ----------
    annotations_json : dict
        Parsed JSON from ``render_ida_annotations()`` or ``export_trace()``.

    Returns
    -------
    int
        Number of annotations applied.
    """
    count = 0

    for annot in annotations_json.get("annotations", []):
        addr = annot.get("address", 0)
        comment = annot.get("comment", "")
        color = annot.get("color")

        if comment:
            _set_comment(addr, comment)
            count += 1
        if color is not None:
            _set_color(addr, color)

    for func in annotations_json.get("functions", []):
        addr = func.get("address", 0)
        name = func.get("name", "")
        if name:
            _rename_function(addr, name)
            count += 1

    return count


def load_annotations_file(path: str) -> Dict[str, Any]:
    """Load an IDA annotation JSON file."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def analyze_current_binary() -> Dict[str, Any]:
    """Run DragonSlayer analysis on the binary currently loaded in IDA.

    Returns the analysis result dict.  Requires the ``dragonslayer``
    package to be importable.
    """
    from dragonslayer.core.orchestrator import Orchestrator

    if not IDA_AVAILABLE:
        logger.error("IDA API not available — run this script inside IDA Pro")
        return {}

    # Get binary bytes from IDA
    start = idaapi.get_inf_structure().min_ea
    end = idaapi.get_inf_structure().max_ea
    binary_data = ida_bytes.get_bytes(start, end - start) or b""

    orch = Orchestrator()
    result = orch.analyze_binary(binary_data, analysis_type="hybrid")
    return result.to_dict()


def run(annotations_path: Optional[str] = None) -> None:
    """Main entry point for IDA script execution.

    If *annotations_path* is provided, loads pre-exported annotations.
    Otherwise, runs live analysis on the current binary.
    """
    # Check for environment variable override
    if annotations_path is None:
        annotations_path = os.environ.get("VMDS_ANALYSIS_PATH")

    if annotations_path and Path(annotations_path).exists():
        logger.info("Loading annotations from %s", annotations_path)
        data = load_annotations_file(annotations_path)
        count = apply_annotations(data)
        msg = f"DragonSlayer: Applied {count} annotations from file"
    else:
        logger.info("Running live DragonSlayer analysis...")
        try:
            result = analyze_current_binary()

            # Convert analysis result to IDA annotations
            from dragonslayer.analysis.trace_export import render_ida_annotations
            from dragonslayer.analysis.trace_ingestion import ExecutionTrace

            trace = ExecutionTrace(
                metadata=result.get("metadata", {}),
                source="ida_live",
            )
            json_str = render_ida_annotations(trace)
            data = json.loads(json_str)
            count = apply_annotations(data)
            msg = f"DragonSlayer: Analysis complete, {count} annotations applied"
        except Exception as exc:
            msg = f"DragonSlayer: Analysis failed — {exc}"
            logger.error(msg)

    if IDA_AVAILABLE:
        idaapi.msg(msg + "\n")
    else:
        print(msg)


# ── IDA Plugin class (for plugin installation) ─────────────────────────


if IDA_AVAILABLE:

    class DragonSlayerPlugin(idaapi.plugin_t):
        """IDA Pro plugin wrapper for DragonSlayer."""

        flags = idaapi.PLUGIN_UNL
        comment = "VMDragonSlayer — VM protection analysis"
        help = "Analyse VM-based binary protection and annotate handlers"
        wanted_name = "DragonSlayer"
        wanted_hotkey = "Ctrl+Shift+D"

        def init(self):
            logger.info("DragonSlayer plugin loaded")
            return idaapi.PLUGIN_OK

        def run(self, arg):
            run()

        def term(self):
            pass

    def PLUGIN_ENTRY():  # noqa: N802 — IDA convention
        return DragonSlayerPlugin()
