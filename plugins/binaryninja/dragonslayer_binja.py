"""
VMDragonSlayer — Binary Ninja Plugin
=====================================

Loads DragonSlayer analysis results into Binary Ninja via comments,
tags, and function renames.

Installation
------------
1. Copy this directory to ``~/.binaryninja/plugins/dragonslayer/``.
2. ``pip install vmdragonslayer`` in Binary Ninja's Python environment,
   **or** set ``VMDS_ANALYSIS_PATH`` to a pre-exported JSON.

Usage
-----
After installation, the plugin appears in the *Plugins* menu:

    Plugins → DragonSlayer → Apply Annotations

Or use the Python console::

    import dragonslayer_binja
    dragonslayer_binja.apply_annotations_to_bv(bv, data)
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("dragonslayer.binja")

# ── Binary Ninja API availability ───────────────────────────────────────

try:
    import binaryninja as bn  # type: ignore[import-untyped]
    from binaryninja import (  # type: ignore[import-untyped]
        BinaryView,
        PluginCommand,
        BackgroundTaskThread,
    )
    BINJA_AVAILABLE = True
except ImportError:
    BINJA_AVAILABLE = False
    # Stub types for type checking outside Binary Ninja
    BinaryView = None  # type: ignore[assignment,misc]

# ── Annotation colours ──────────────────────────────────────────────────

# Binary Ninja uses highlight colours from binaryninja.highlight
try:
    from binaryninja.highlight import HighlightStandardColor  # type: ignore[import-untyped]
    COLOR_HANDLER_KNOWN = HighlightStandardColor.GreenHighlightColor
    COLOR_HANDLER_UNKNOWN = HighlightStandardColor.YellowHighlightColor
    COLOR_HOT_CODE = HighlightStandardColor.BlueHighlightColor
except ImportError:
    COLOR_HANDLER_KNOWN = None
    COLOR_HANDLER_UNKNOWN = None
    COLOR_HOT_CODE = None


# ── Core annotation functions ────────────────────────────────────────────


def apply_annotations_to_bv(
    bv: "BinaryView",  # type: ignore[type-arg]
    annotations_data: Dict[str, Any],
) -> int:
    """Apply annotation data to a Binary Ninja BinaryView.

    Parameters
    ----------
    bv : BinaryView
        The Binary Ninja binary view to annotate.
    annotations_data : dict
        Parsed JSON from ``render_ida_annotations()`` format.

    Returns
    -------
    int
        Number of annotations applied.
    """
    count = 0

    for annot in annotations_data.get("annotations", []):
        addr = annot.get("address", 0)
        comment = annot.get("comment", "")
        color_val = annot.get("color")

        if comment:
            # Set comment at address
            existing = bv.get_comment_at(addr) or ""
            if comment not in existing:
                new_comment = f"{existing}\n{comment}".strip() if existing else comment
                bv.set_comment_at(addr, new_comment)
                count += 1

        if color_val is not None and COLOR_HANDLER_KNOWN is not None:
            # Map IDA BGR colours to Binary Ninja highlight colours
            if color_val == 0x98FB98:
                bv.set_user_instr_highlight(addr, COLOR_HANDLER_KNOWN)
            elif color_val == 0x00FFFF:
                bv.set_user_instr_highlight(addr, COLOR_HANDLER_UNKNOWN)
            elif color_val == 0xADD8E6:
                bv.set_user_instr_highlight(addr, COLOR_HOT_CODE)

    for func_data in annotations_data.get("functions", []):
        addr = func_data.get("address", 0)
        name = func_data.get("name", "")
        if name:
            func = bv.get_function_at(addr)
            if func is not None:
                func.name = name
                count += 1
            else:
                # Create function if it doesn't exist
                bv.create_user_function(addr)
                func = bv.get_function_at(addr)
                if func is not None:
                    func.name = name
                    count += 1

    # Add tags for handler types
    for annot in annotations_data.get("annotations", []):
        addr = annot.get("address", 0)
        comment = annot.get("comment", "")
        if "VM Handler" in comment:
            tag_type = bv.create_tag_type("DragonSlayer", "🐉")
            for func in bv.get_functions_containing(addr):
                func.create_user_address_tag(addr, tag_type, comment)
                count += 1
                break

    return count


def load_annotations_file(path: str) -> Dict[str, Any]:
    """Load an annotation JSON file."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


# ── Plugin interaction ──────────────────────────────────────────────────


def _find_annotations_path(bv: "BinaryView") -> Optional[str]:  # type: ignore[type-arg]
    """Find annotations file via convention or environment."""
    # 1. Environment variable
    env_path = os.environ.get("VMDS_ANALYSIS_PATH")
    if env_path and Path(env_path).exists():
        return env_path

    # 2. Convention: <binary>.dragonslayer.json next to binary
    if bv.file and bv.file.filename:
        candidate = Path(bv.file.filename + ".dragonslayer.json")
        if candidate.exists():
            return str(candidate)

    return None


def _apply_from_file(bv: "BinaryView") -> None:  # type: ignore[type-arg]
    """Binary Ninja plugin command handler: apply annotations."""
    annotations_path = _find_annotations_path(bv)

    if annotations_path is None:
        # Ask user to select file
        annotations_path = bn.interaction.get_open_filename_input(
            "Select DragonSlayer Annotations JSON",
            "JSON files (*.json)",
        )
        if not annotations_path:
            bn.log_warn("DragonSlayer: No annotations file selected")
            return

    try:
        data = load_annotations_file(str(annotations_path))
        count = apply_annotations_to_bv(bv, data)
        bn.log_info(f"DragonSlayer: Applied {count} annotations from {annotations_path}")
    except Exception as exc:
        bn.log_error(f"DragonSlayer: Failed to apply annotations — {exc}")


def _analyze_and_annotate(bv: "BinaryView") -> None:  # type: ignore[type-arg]
    """Binary Ninja plugin command: analyze binary and apply annotations."""
    try:
        from dragonslayer.core.orchestrator import Orchestrator
        from dragonslayer.analysis.trace_export import render_ida_annotations

        # Get raw binary data from BinaryView
        binary_data = bv.read(bv.start, bv.length)

        bn.log_info("DragonSlayer: Running analysis...")

        orch = Orchestrator()
        result = orch.analyze_binary(binary_data, analysis_type="hybrid")

        # Convert to IDA annotation format (shared with IDA plugin)
        from dragonslayer.analysis.trace_ingestion import ExecutionTrace

        trace = ExecutionTrace(
            metadata=result.to_dict().get("metadata", {}),
            source="binja_live",
        )
        json_str = render_ida_annotations(trace)
        data = json.loads(json_str)

        count = apply_annotations_to_bv(bv, data)
        bn.log_info(f"DragonSlayer: Analysis complete, {count} annotations applied")

    except ImportError as exc:
        bn.log_error(f"DragonSlayer: Missing dependency — {exc}")
    except Exception as exc:
        bn.log_error(f"DragonSlayer: Analysis failed — {exc}")


# ── Register plugin commands ────────────────────────────────────────────

if BINJA_AVAILABLE:
    PluginCommand.register(
        "DragonSlayer\\Apply Annotations from File",
        "Load DragonSlayer annotation JSON and apply to current binary",
        _apply_from_file,
    )
    PluginCommand.register(
        "DragonSlayer\\Analyze and Annotate",
        "Run DragonSlayer analysis on current binary and apply annotations",
        _analyze_and_annotate,
    )
