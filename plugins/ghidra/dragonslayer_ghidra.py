"""
VMDragonSlayer — Ghidra Plugin (Jython)
========================================

Loads DragonSlayer analysis results into Ghidra via comments, bookmarks,
and function renames.

Installation
------------
1. Copy this file to ``<GHIDRA>/Ghidra/Extensions/`` or your user scripts
   directory (``~/.ghidra/<version>/scripts/``).
2. In Ghidra's Script Manager, run ``dragonslayer_ghidra.py``.

Usage
-----
- **Automatic**: Run the script with a single argument — path to the
  annotation JSON exported by ``trace_export.render_ghidra_script()``
  or the IDA-format JSON from ``render_ida_annotations()``.
- **Environment**: Set ``VMDS_ANALYSIS_PATH`` to auto-load annotations.
- **Programmatic**: Call ``apply_annotations(data)`` from Ghidra's Python
  console.

This script is Jython-compatible (Ghidra uses Jython 2.7) but the helper
functions can also be used from CPython if ``ghidra`` bridge packages are
available.
"""

# Ghidra script metadata (used by Script Manager)
# @author DragonSlayer
# @category Analysis.VMProtection
# @keybinding Ctrl+Shift+D
# @menupath Tools.DragonSlayer.Apply Annotations
# @toolbar

from __future__ import print_function  # Jython 2.7 compat

import json
import os

# ── Ghidra API availability ─────────────────────────────────────────────

try:
    from ghidra.program.model.listing import CodeUnit  # type: ignore[import]
    from ghidra.app.script import GhidraScript  # type: ignore[import]
    GHIDRA_AVAILABLE = True
except ImportError:
    GHIDRA_AVAILABLE = False

# When running inside Ghidra, these are injected by the script manager
try:
    currentProgram  # type: ignore[name-defined]  # noqa: F821
    GHIDRA_CONTEXT = True
except NameError:
    GHIDRA_CONTEXT = False


# ── Helpers ──────────────────────────────────────────────────────────────


def _get_address(program, addr_int):
    """Convert integer address to Ghidra Address object."""
    af = program.getAddressFactory()
    return af.getDefaultAddressSpace().getAddress(addr_int)


def _set_eol_comment(program, address_int, comment):
    """Set EOL comment at address."""
    listing = program.getListing()
    addr = _get_address(program, address_int)
    cu = listing.getCodeUnitAt(addr)
    if cu is not None:
        cu.setComment(CodeUnit.EOL_COMMENT, comment)
        return True
    return False


def _set_plate_comment(program, address_int, comment):
    """Set plate comment at address."""
    listing = program.getListing()
    addr = _get_address(program, address_int)
    cu = listing.getCodeUnitAt(addr)
    if cu is not None:
        cu.setComment(CodeUnit.PLATE_COMMENT, comment)
        return True
    return False


def _add_bookmark(program, address_int, category, description):
    """Add a bookmark at address."""
    bm = program.getBookmarkManager()
    addr = _get_address(program, address_int)
    bm.setBookmark(addr, "Analysis", category, description)


def _rename_function(program, address_int, name):
    """Rename function at address."""
    fm = program.getFunctionManager()
    addr = _get_address(program, address_int)
    func = fm.getFunctionAt(addr)
    if func is not None:
        func.setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED)  # type: ignore[name-defined]  # noqa: F821
        return True
    return False


# ── Core annotation functions ────────────────────────────────────────────


def apply_annotations(program, annotations_data):
    """Apply annotation JSON data to the given Ghidra program.

    Parameters
    ----------
    program : ghidra.program.model.listing.Program
        The Ghidra program to annotate.
    annotations_data : dict
        Parsed JSON from ``render_ida_annotations()`` (IDA format) or
        ``render_ghidra_script()`` output.

    Returns
    -------
    int
        Number of annotations applied.
    """
    count = 0

    for annot in annotations_data.get("annotations", []):
        addr = annot.get("address", 0)
        comment = annot.get("comment", "")
        if comment and _set_eol_comment(program, addr, comment):
            count += 1

    for func in annotations_data.get("functions", []):
        addr = func.get("address", 0)
        name = func.get("name", "")
        if name:
            _rename_function(program, addr, name)
            count += 1
            _add_bookmark(program, addr, "VMHandler", name)

    return count


def load_annotations_file(path):
    """Load an annotation JSON file.

    Parameters
    ----------
    path : str
        Path to the JSON file.

    Returns
    -------
    dict
        Parsed annotation data.
    """
    with open(path, "r") as f:
        return json.load(f)


# ── Ghidra Script runner ────────────────────────────────────────────────


def run_in_ghidra():
    """Main entry point when run as a Ghidra script.

    Looks for annotations in:
    1. Script arguments (first arg = path to JSON)
    2. ``VMDS_ANALYSIS_PATH`` environment variable
    3. ``<binary_name>.dragonslayer.json`` next to the binary
    """
    if not GHIDRA_CONTEXT:
        print("ERROR: This script must be run inside Ghidra")
        return

    program = currentProgram  # type: ignore[name-defined]  # noqa: F821

    # Try to find annotations file
    annotations_path = None

    # 1. Script arguments
    try:
        args = getScriptArgs()  # type: ignore[name-defined]  # noqa: F821
        if args and len(args) > 0:
            annotations_path = str(args[0])
    except Exception:
        pass

    # 2. Environment variable
    if not annotations_path:
        annotations_path = os.environ.get("VMDS_ANALYSIS_PATH")

    # 3. Convention: <binary>.dragonslayer.json
    if not annotations_path:
        exe_path = program.getExecutablePath()
        if exe_path:
            candidate = exe_path + ".dragonslayer.json"
            if os.path.exists(candidate):
                annotations_path = candidate

    if annotations_path and os.path.exists(annotations_path):
        print("DragonSlayer: Loading annotations from %s" % annotations_path)
        data = load_annotations_file(annotations_path)

        # Start a transaction for modifications
        txn = program.startTransaction("DragonSlayer Annotations")
        try:
            count = apply_annotations(program, data)
            program.endTransaction(txn, True)
            print("DragonSlayer: Applied %d annotations" % count)
        except Exception as e:
            program.endTransaction(txn, False)
            print("DragonSlayer: Error applying annotations: %s" % str(e))
    else:
        print("DragonSlayer: No annotations file found.")
        print("  Set VMDS_ANALYSIS_PATH or pass path as script argument.")
        print("  Or run: vmdragonslayer export <binary> -f ida -o <path>.json")


# ── Auto-run when loaded as Ghidra script ───────────────────────────────

if GHIDRA_CONTEXT:
    run_in_ghidra()
