"""
Symbolic Depth — per-handler symbolic summary extraction
=========================================================

Bridges the gap between:

* **Handler extraction** (Batch 14), which produces concrete handler
  bodies (``HandlerBody``) with raw bytes and address ranges, and
* **Handler clustering** (Batch 16), which accepts
  ``{handler_address: HandlerSymbolicSummary}`` for semantic grouping.

When the symbolic executor or dynamic plugins have already run, this
module converts their outputs into per-handler symbolic summaries.
When raw handler bytes are available (from handler extraction), it can
also run *fresh* per-handler symbolic execution.

Usage::

    from dragonslayer.analysis.symbolic_depth import (
        extract_symbolic_summaries,
        run_handler_symbolic_execution,
    )

    # From existing symbolic / plugin output:
    summaries = extract_symbolic_summaries(
        shared_data=ctx.shared_data,
        boundaries=boundaries,
    )

    # From raw handler bodies:
    summaries = run_handler_symbolic_execution(
        handler_bodies=extraction_result.handlers,
        bit_width=64,
    )
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any, cast

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1.  Extract from existing shared_data
# ---------------------------------------------------------------------------

def extract_symbolic_summaries(
    shared_data: dict[str, Any],
    boundaries: Sequence[Any] | None = None,
) -> dict[int, dict[str, Any]]:
    """Harvest per-handler symbolic summaries from pipeline shared_data.

    Probes the following sources (in priority order):

    1. ``shared_data["symbolic_execution"]["handler_summaries"]``
       — if the symbolic executor already produced per-handler data.
    2. ``shared_data["symbolic_execution"]["handlers"]``
       — handler info dicts with ``address``, ``category``, etc.
    3. ``shared_data["angr"]`` / ``shared_data["triton"]``
       — dynamic plugin output that may contain register snapshots
       keyed by handler address.
    4. ``shared_data["handler_extraction"]["handlers"]``
       — from Batch 14 handler extraction.  These include register
       deltas which can be converted into a minimal symbolic summary.

    Returns a dict mapping handler address → summary dict compatible
    with :func:`~dragonslayer.analysis.handler_clustering.cluster_handlers_by_semantics`.
    """
    summaries: dict[int, dict[str, Any]] = {}

    # ── Source 1: explicit handler_summaries ──────────────────────────
    sym_exec = shared_data.get("symbolic_execution", {})
    explicit = sym_exec.get("handler_summaries")
    if isinstance(explicit, dict) and explicit:
        for addr_key, summary in explicit.items():
            addr = int(addr_key) if isinstance(addr_key, str) else addr_key
            if isinstance(summary, dict):
                summaries[addr] = summary
            elif hasattr(summary, "to_dict"):
                summaries[addr] = summary.to_dict()
        if summaries:
            logger.debug("Symbolic depth: %d summaries from handler_summaries",
                         len(summaries))
            return summaries

    # ── Source 2: handler info from symbolic execution result ─────────
    handlers: list = sym_exec.get("handlers", [])
    if handlers:
        for h in handlers:
            if isinstance(h, dict):
                addr = h.get("address", 0)
                if addr:
                    summaries[addr] = _handler_info_to_summary(h)
            elif hasattr(h, "address") and h.address:
                d = h.to_dict() if hasattr(h, "to_dict") else {"address": h.address}
                summaries[h.address] = _handler_info_to_summary(d)
        if summaries:
            logger.debug("Symbolic depth: %d summaries from SE handlers",
                         len(summaries))

    # ── Source 3: dynamic plugin register snapshots ──────────────────
    for plugin_key in ("angr", "triton"):
        plugin_data = shared_data.get(plugin_key, {})
        if not isinstance(plugin_data, dict):
            continue
        snap_key = "register_snapshots"
        snapshots = plugin_data.get(snap_key) or plugin_data.get("snapshots", [])
        if isinstance(snapshots, dict):
            # Dict keyed by address
            for addr_key, snap in snapshots.items():
                addr = int(addr_key) if isinstance(addr_key, str) else addr_key
                if addr and addr not in summaries:
                    summaries[addr] = _snapshot_to_summary(addr, snap)
        elif isinstance(snapshots, list):
            for snap in snapshots:
                if isinstance(snap, dict):
                    addr = snap.get("address", snap.get("pc", 0))
                    if addr and addr not in summaries:
                        summaries[addr] = _snapshot_to_summary(addr, snap)

    # ── Source 4: handler extraction register deltas ─────────────────
    extraction = shared_data.get("handler_extraction", {})
    ext_handlers = extraction.get("handlers", [])
    for h in ext_handlers:
        if not isinstance(h, dict):
            continue
        addr = h.get("address", 0)
        if addr and addr not in summaries:
            summaries[addr] = _extraction_to_summary(h)

    logger.debug("Symbolic depth: %d total summaries collected",
                 len(summaries))
    return summaries


# ---------------------------------------------------------------------------
# 2.  Run fresh per-handler symbolic execution
# ---------------------------------------------------------------------------

def run_handler_symbolic_execution(
    handler_bodies: Sequence[Any],
    *,
    bit_width: int = 64,
    max_handlers: int = 500,
) -> dict[int, dict[str, Any]]:
    """Run the symbolic executor on extracted handler bodies.

    Parameters
    ----------
    handler_bodies:
        Sequence of ``HandlerBody`` objects (from handler extraction).
        Each must have ``address`` and ``raw_bytes``.
    bit_width:
        Architecture width for the symbolic executor.
    max_handlers:
        Safety cap — skip handlers beyond this count.

    Returns
    -------
    Dict mapping handler address → ``HandlerSymbolicSummary.to_dict()``.
    """
    try:
        from .symbolic_execution.executor import SymbolicExecutor
    except ImportError:
        logger.warning("SymbolicExecutor not available — skipping per-handler SE")
        return {}

    executor = SymbolicExecutor(arch="x86_64" if bit_width == 64 else "x86")
    summaries: dict[int, dict[str, Any]] = {}

    for i, body in enumerate(handler_bodies):
        if i >= max_handlers:
            logger.debug("Symbolic depth: cap of %d handlers reached", max_handlers)
            break

        addr = getattr(body, "address", 0) or 0
        raw = getattr(body, "raw_bytes", b"")

        # Also accept dict form
        if isinstance(body, dict):
            addr = body.get("address", 0)
            raw = body.get("raw_bytes", b"")
            if isinstance(raw, str):
                raw = bytes.fromhex(raw)

        if not raw:
            continue

        try:
            summary = executor.execute_handler(raw, handler_address=addr)
            summaries[addr] = cast("dict[str, Any]", summary.to_dict())
        except (ValueError, TypeError, KeyError, RuntimeError, AttributeError, IndexError) as exc:
            logger.debug("Symbolic depth: handler %#x failed: %s", addr, exc)
            summaries[addr] = {"address": addr, "error": str(exc)}

    logger.debug("Symbolic depth: %d handlers symbolically executed",
                 len(summaries))
    return summaries


# ---------------------------------------------------------------------------
# 3.  Pipeline integration helper
# ---------------------------------------------------------------------------

def collect_symbolic_summaries(
    shared_data: dict[str, Any],
    boundaries: Sequence[Any] | None = None,
    handler_bodies: Sequence[Any] | None = None,
    *,
    bit_width: int = 64,
    run_fresh: bool = True,
) -> dict[int, dict[str, Any]]:
    """Unified function: extract existing summaries, optionally run fresh SE.

    This is the intended entry point from the pipeline.

    1. Try :func:`extract_symbolic_summaries` first.
    2. If the result is sparse and *handler_bodies* are available and
       *run_fresh* is True, supplement with per-handler SE.
    """
    summaries = extract_symbolic_summaries(shared_data, boundaries)

    # Count how many boundaries have a summary
    covered = 0
    total = 0
    if boundaries:
        total = len(list(boundaries))
        for b in boundaries:
            addr = getattr(b, "handler_address", None)
            if addr is None and isinstance(b, dict):
                addr = b.get("handler_address", 0)
            if addr and addr in summaries:
                covered += 1

    coverage_ratio = covered / total if total > 0 else 0.0

    if run_fresh and handler_bodies and coverage_ratio < 0.5:
        logger.debug(
            "Symbolic depth: coverage %.0f%% (%d/%d), running per-handler SE",
            coverage_ratio * 100, covered, total,
        )
        fresh = run_handler_symbolic_execution(
            handler_bodies, bit_width=bit_width)
        # Merge: fresh fills gaps, doesn't overwrite existing
        for addr, s in fresh.items():
            if addr not in summaries:
                summaries[addr] = s

    return summaries


# ---------------------------------------------------------------------------
# Converters  (internal)
# ---------------------------------------------------------------------------

def _handler_info_to_summary(h: dict[str, Any]) -> dict[str, Any]:
    """Convert a HandlerInfo dict to HandlerSymbolicSummary-compatible dict."""
    return {
        "address": h.get("address", 0),
        "instruction_count": h.get("instruction_count", 0),
        "final_registers": h.get("register_effects", {}),
        "simplified_registers": {},
        "memory_writes": h.get("memory_accesses", []),
        "constraints": [],
        "input_symbols": {},
    }


def _snapshot_to_summary(addr: int, snap: dict[str, Any]) -> dict[str, Any]:
    """Convert a register snapshot dict to HandlerSymbolicSummary-compatible."""
    regs = snap.get("registers", snap)
    if not isinstance(regs, dict):
        regs = {}
    # Build final_registers as register → "value" strings
    final = {}
    for k, v in regs.items():
        if k in ("address", "pc", "rip", "eip"):
            continue
        final[k] = str(v)
    return {
        "address": addr,
        "instruction_count": snap.get("instruction_count", 0),
        "final_registers": final,
        "simplified_registers": {},
        "memory_writes": snap.get("memory_writes", []),
        "constraints": [],
        "input_symbols": {},
    }


def _extraction_to_summary(h: dict[str, Any]) -> dict[str, Any]:
    """Convert handler extraction dict to HandlerSymbolicSummary-compatible.

    Handler extraction provides ``register_delta`` which lists registers
    that changed.  We represent these as ``init_<reg> + delta``.
    """
    addr = h.get("address", 0)
    deltas = h.get("register_delta", {})
    final = {}
    input_symbols = {}
    for reg, delta_info in deltas.items():
        if isinstance(delta_info, dict):
            before = delta_info.get("before", 0)
            after = delta_info.get("after", 0)
            diff = after - before if isinstance(after, int) and isinstance(before, int) else 0
            sym = f"init_{reg}"
            input_symbols[reg] = sym
            if diff == 0:
                final[reg] = sym
            elif diff > 0:
                final[reg] = f"({sym} + {diff:#x})"
            else:
                final[reg] = f"({sym} - {abs(diff):#x})"
        elif isinstance(delta_info, (int, float)):
            sym = f"init_{reg}"
            input_symbols[reg] = sym
            if delta_info == 0:
                final[reg] = sym
            elif delta_info > 0:
                final[reg] = f"({sym} + {delta_info:#x})"
            else:
                final[reg] = f"({sym} - {abs(int(delta_info)):#x})"

    return {
        "address": addr,
        "instruction_count": h.get("instruction_count", 0),
        "final_registers": final,
        "simplified_registers": {},
        "memory_writes": h.get("memory_writes", []),
        "constraints": [],
        "input_symbols": input_symbols,
    }
