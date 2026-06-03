"""
Devirtualisation Sub-Stages
============================

Decomposition of the monolithic ``_run_devirtualize()`` into focused,
independently testable sub-functions.  Each function handles one logical
step of the devirtualisation pipeline and communicates via explicit
parameters and return values rather than relying on a shared mutable dict.

This module is imported exclusively by :mod:`dragonslayer.core.pipeline`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .exceptions import VMDragonSlayerError

logger = logging.getLogger(__name__)

# B88: Named exception tuple — only catch framework + I/O errors.
_STAGE_ERRORS: tuple[type[BaseException], ...] = (
    VMDragonSlayerError, OSError, ImportError,
)


# ---------------------------------------------------------------------------
# Workspace that accumulates devirt state across sub-steps
# ---------------------------------------------------------------------------

@dataclass
class DevirtWorkspace:
    """Mutable workspace carrying intermediate devirt state.

    Each sub-step reads from / writes to this workspace so the caller
    (``_do_devirt``) doesn't need dozens of local variables.
    """

    # Inputs
    binary_data: bytes = b""
    shared_data: Any = None  # PipelineState / dict
    base_address: int = 0

    # Step 1 — trace ingestion
    trace: Any = None  # ExecutionTrace | None

    # Step 2 — anti-evasion hooks
    hook_set_data: dict[str, Any] | None = None

    # Step 2b — VM entry points
    vm_entry_data: dict[str, Any] | None = None

    # Step 3 — dispatcher identification
    dispatcher_match: dict[str, Any] | None = None
    detected_protector: str = "unknown"
    vmprotect_match: dict[str, Any] | None = None

    # Step 3b — bytecode decryptor
    bytecode_decryptor: Any = None  # RollingKeyDecryptor | None

    # Step 4 — vIP + segmentation
    vip_candidate: Any = None
    boundaries: list = field(default_factory=list)
    dispatcher_addrs: list = field(default_factory=list)

    # Step 5 — handler extraction
    extraction_data: dict[str, Any] | None = None

    # Step 6 — context registers
    context_layout_data: dict[str, Any] | None = None

    # Step 7 — semantics + clustering + ML
    opcode_table: Any = None
    clustering_data: dict[str, Any] | None = None
    ml_labels: dict[str, str] | None = None

    # Step 7b — handler CFG
    handler_cfg: Any = None  # networkx DiGraph | None
    handler_cfg_data: dict[str, Any] | None = None

    # Step 8 — pseudocode
    pseudocode_result: Any = None

    # Step 9 — nested VMs
    nested_layers: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Sub-step 1: Trace ingestion
# ---------------------------------------------------------------------------

def step_ingest_trace(ws: DevirtWorkspace) -> None:
    """Obtain an :class:`ExecutionTrace` from shared_data plugin output.

    Sets ``ws.trace`` and resolves ``ws.base_address`` from PE info
    when not already set.
    """
    from ..analysis.trace_ingestion import from_shared_data

    try:
        plugin_trace = from_shared_data(ws.shared_data)
    except _STAGE_ERRORS:
        plugin_trace = None
    ws.trace = plugin_trace

    # Also produce a built-in Unicorn trace from the binary's entry point and
    # keep whichever trace is *richer* (more instructions). A dynamic plugin
    # (Qiling/Triton/angr) may only cover a short prefix, so the built-in
    # whole-program emulation often segments more handlers. Best-effort and
    # bounded by max_instructions; only when the optional 'unicorn' backend
    # is installed.
    if ws.binary_data:
        try:
            from ..analysis.trace_engine import UNICORN_AVAILABLE, TraceEngine

            if UNICORN_AVAILABLE:
                from ..analysis.binary_format import parse_binary

                pb = parse_binary(ws.binary_data)
                entry = int(getattr(pb, "entry_point", 0) or 0)
                base = int(getattr(pb, "image_base", 0) or 0) or 0x400000
                arch = "x86_64" if "64" in str(getattr(pb, "architecture", "")) else "x86"
                if entry:
                    builtin = TraceEngine(arch=arch).trace(
                        ws.binary_data, entry_va=entry, image_base=base,
                    )
                    plugin_n = len(plugin_trace.instructions) if plugin_trace else 0
                    if builtin and len(builtin.instructions) > plugin_n:
                        ws.trace = builtin
                        if not ws.base_address:
                            ws.base_address = base
                        ws.shared_data["entry_point"] = entry
                        ws.shared_data["image_base"] = base
                        ws.shared_data["trace_source"] = "builtin_unicorn"
        except Exception as exc:  # best-effort: emulating arbitrary input
            logger.debug("Built-in trace fallback failed: %s", exc)

    # Resolve base address from PE/shared_data
    if not ws.base_address:
        ws.base_address = ws.shared_data.get("image_base", 0)
    if not ws.base_address:
        pe_info = ws.shared_data.get("pe_analyzer", {})
        if isinstance(pe_info, dict):
            ws.base_address = (
                pe_info.get("image_base", 0) or pe_info.get("base_address", 0)
            )
    if not ws.base_address:
        ws.base_address = ws.shared_data.get("base_address", 0)


# ---------------------------------------------------------------------------
# Sub-step 2: Anti-evasion hook-set
# ---------------------------------------------------------------------------

def step_build_hook_set(ws: DevirtWorkspace) -> None:
    """Build runtime hook-set from anti-evasion report if available."""
    try:
        from ..analysis.anti_evasion.runtime_hooks import (
            build_hook_set_from_report,
        )
        ae_report = ws.shared_data.get("anti_evasion")
        if ae_report is not None:
            hook_set = build_hook_set_from_report(ae_report)
            ws.hook_set_data = {
                "hook_count": len(hook_set.hooks),
                "categories": list({h.category.value for h in hook_set.hooks}),
                "hook_names": [h.name for h in hook_set.hooks],
            }
    except _STAGE_ERRORS as exc:
        logger.debug("Anti-evasion hook-set skipped: %s", exc)


# ---------------------------------------------------------------------------
# Sub-step 2b: VM entry point locator
# ---------------------------------------------------------------------------

def step_locate_vm_entries(ws: DevirtWorkspace) -> None:
    """Locate VM entry points from PE structure."""
    try:
        from ..analysis.vm_discovery.vm_entry_locator import (
            locate_entries_from_pe_result,
            locate_vm_entries,
        )
        pe_result = ws.shared_data.get("pe_analyzer")
        if pe_result and isinstance(pe_result, dict):
            entry_report = locate_entries_from_pe_result(
                ws.binary_data, pe_result)
        elif len(ws.binary_data) > 64 and ws.binary_data[:2] == b"MZ":
            entry_report = locate_vm_entries(ws.binary_data)
        else:
            entry_report = None

        if entry_report is not None and entry_report.count > 0:
            ws.vm_entry_data = entry_report.to_dict()
            ws.shared_data["vm_entry_points"] = ws.vm_entry_data
    except _STAGE_ERRORS as exc:
        logger.debug("VM entry locator skipped: %s", exc)


# ---------------------------------------------------------------------------
# Sub-step 3: Dispatcher identification (multi-protector)
# ---------------------------------------------------------------------------

def step_identify_dispatcher(ws: DevirtWorkspace) -> None:
    """Identify VM dispatcher using generic multi-protector orchestrator."""
    try:
        from ..analysis.vm_discovery.dispatcher import (
            find_dispatcher,
            find_vmprotect_dispatcher,
        )

        # B100: Try VMProtect → Themida → Code Virtualizer → generic.
        # find_dispatcher expects trace *records* (list of dicts with
        # ``address``/``disassembly``), so normalise the ExecutionTrace.
        protector_hint = ws.shared_data.get("detected_protector")
        trace_records: list[dict[str, Any]] = []
        if ws.trace is not None:
            insns = getattr(ws.trace, "instructions", ws.trace)
            for ti in insns:
                trace_records.append(ti.to_dict() if hasattr(ti, "to_dict") else ti)
        generic_match = find_dispatcher(
            trace_records, bit_width=64,
            protector_hint=protector_hint,
        )

        if generic_match is not None:
            ws.dispatcher_match = generic_match.to_dict()
            ws.detected_protector = generic_match.protector
            ws.shared_data["dispatcher_match"] = ws.dispatcher_match
            ws.shared_data["detected_protector"] = ws.detected_protector

            if ws.detected_protector == "vmprotect":
                ws.vmprotect_match = ws.dispatcher_match
                ws.shared_data.setdefault(
                    "vmprotect_dispatcher", ws.vmprotect_match,
                )
        else:
            # Legacy fallback: VMProtect-specific binary scan. ``binary_data``
            # is a keyword arg used for handler-table extraction; dispatcher
            # detection itself needs lifted instructions (none here at this
            # stage), so this returns None unless instructions were supplied.
            disp_match = find_vmprotect_dispatcher(
                [], binary_data=ws.binary_data,
            )
            if disp_match is not None:
                ws.vmprotect_match = disp_match.to_dict()
                ws.dispatcher_match = ws.vmprotect_match
                ws.detected_protector = "vmprotect"
                ws.shared_data.setdefault(
                    "vmprotect_dispatcher", ws.vmprotect_match,
                )
                ws.shared_data["dispatcher_match"] = ws.dispatcher_match
                ws.shared_data["detected_protector"] = ws.detected_protector
    except _STAGE_ERRORS as exc:
        logger.debug("Dispatcher identification skipped: %s", exc)


# ---------------------------------------------------------------------------
# Sub-step 3b: Bytecode decryptor + handler table decrypt
# ---------------------------------------------------------------------------

def step_decrypt_bytecode(ws: DevirtWorkspace) -> None:
    """Create rolling-key decryptor and decrypt handler table."""
    try:
        from ..analysis.bytecode_decrypt import (
            decrypt_handler_table,
            make_decryptor_from_dispatcher,
            make_generic_decryptor,
        )
        trace_records = ws.trace.instructions if ws.trace is not None else []
        if ws.vmprotect_match is not None:
            ws.bytecode_decryptor = make_decryptor_from_dispatcher(
                ws.vmprotect_match, trace_records,
            )
        elif ws.dispatcher_match is not None:
            ws.bytecode_decryptor = make_generic_decryptor(
                ws.dispatcher_match, trace_records,
            )

        if ws.bytecode_decryptor is not None:
            ws.shared_data["bytecode_decryptor"] = {
                "initial_key": ws.bytecode_decryptor.initial_key,
                "key_width": ws.bytecode_decryptor.key_width,
                "transform_count": len(ws.bytecode_decryptor.transforms),
            }

        # Decrypt handler table if table_base is available
        src_match = ws.vmprotect_match or ws.dispatcher_match
        if src_match is not None:
            tbl_base = src_match.get("table_base", 0)
            if tbl_base and ws.binary_data and len(ws.binary_data) > 64:
                known_addrs = src_match.get("handler_addresses", [])
                dec_table = decrypt_handler_table(
                    ws.binary_data, tbl_base, ws.base_address,
                    bit_width=64,
                    known_handler_addresses=known_addrs or None,
                )
                if dec_table.count > 0:
                    ws.shared_data["decrypted_handler_table"] = (
                        dec_table.to_dict()
                    )
    except _STAGE_ERRORS as exc:
        logger.debug("Bytecode decryptor / table decrypt skipped: %s", exc)


# ---------------------------------------------------------------------------
# Sub-step 4: vIP identification + segmentation
# ---------------------------------------------------------------------------

def step_segment_handlers(ws: DevirtWorkspace) -> bool:
    """Identify vIP register and segment trace into handler boundaries.

    Returns ``True`` if segmentation succeeded, ``False`` otherwise.
    Populates ``ws.vip_candidate``, ``ws.boundaries``,
    ``ws.dispatcher_addrs``.
    """
    from ..analysis.vm_discovery.handler_boundaries import (
        identify_vip_register,
        segment_trace,
    )

    ws.dispatcher_addrs = list(
        ws.shared_data.get("vm_discovery", {}).get("dispatcher_addresses", [])
    )

    def _merge(addrs: list[int]) -> None:
        existing = set(ws.dispatcher_addrs)
        for a in addrs:
            if a and a not in existing:
                ws.dispatcher_addrs.append(a)
                existing.add(a)

    # Supplement from DispatcherAnalyzer / dispatcher-match handler tables.
    def _table_addrs(table: Any) -> list[int]:
        out: list[int] = []
        for e in table or []:
            a = e.get("handler_address") if isinstance(e, dict) else getattr(
                e, "handler_address", None
            )
            if a:
                out.append(a)
        return out

    _merge(_table_addrs(ws.shared_data.get("handler_table", [])))
    src_disp = ws.dispatcher_match or ws.vmprotect_match
    if src_disp is not None:
        _merge(_table_addrs(src_disp.get("handler_table", [])))

    # Structurally-localised dispatch loop.  This isolates the *outermost*
    # interpreter's fetch/decode/dispatch block even when the trace contains
    # multiple interleaved dispatchers (nested VMs) or a hot startup decrypt
    # loop — both of which would otherwise pollute a naive global hot-address
    # chain and mis-identify the vIP (e.g. picking the opcode/decrypt scratch
    # register).  Used as the authoritative dispatcher set for vIP
    # identification and segmentation; the merged table addresses above remain
    # in ``ws.dispatcher_addrs`` for downstream consumers.
    struct_loop: list[int] = []
    if ws.trace is not None and ws.trace.instructions:
        from ..analysis.vm_discovery.structural import localized_outer_dispatch

        struct_loop = localized_outer_dispatch(ws.trace)
        _merge(struct_loop)

    # Fallback revisit-frequency chain (branch-dispatch VMs whose structural
    # loop may be empty): the dispatch loop runs once per handler invocation.
    if not struct_loop and ws.trace is not None and ws.trace.instructions:
        from collections import Counter

        counts = Counter(ti.address for ti in ws.trace.instructions)
        max_c = max(counts.values()) if counts else 0
        if max_c >= 2:
            thr = max(2, int(max_c * 0.7))
            chain = sorted(
                (a for a, c in counts.items() if c >= thr),
                key=lambda a: counts[a],
                reverse=True,
            )
            _merge(chain)
            ws.shared_data.setdefault("dispatcher_addresses_inferred", chain[:8])

    # Prefer the localised outer dispatch loop; fall back to the merged set.
    seg_disp = struct_loop if struct_loop else ws.dispatcher_addrs
    ws.vip_candidate = identify_vip_register(ws.trace, seg_disp)
    if ws.vip_candidate is None:
        return False

    seg = segment_trace(ws.trace, ws.vip_candidate, seg_disp)
    ws.boundaries = seg.boundaries
    return bool(ws.boundaries)


# ---------------------------------------------------------------------------
# Sub-step 5: Handler extraction
# ---------------------------------------------------------------------------

def step_extract_handlers(ws: DevirtWorkspace) -> None:
    """Extract handler bodies, register deltas, and fingerprints."""
    try:
        from ..analysis.vm_discovery.handler_extraction import (
            extract_handler_bodies,
        )
        extraction = extract_handler_bodies(
            ws.trace.instructions, ws.boundaries, ws.vip_candidate.name,
            dispatcher_addresses=tuple(ws.dispatcher_addrs),
        )
        ws.extraction_data = extraction.to_dict()
        ws.shared_data["handler_extraction"] = ws.extraction_data
    except _STAGE_ERRORS as exc:
        logger.debug("Handler extraction skipped: %s", exc)


# ---------------------------------------------------------------------------
# Sub-step 6: VM context register identification
# ---------------------------------------------------------------------------

def step_identify_context(ws: DevirtWorkspace) -> None:
    """Identify virtual stack pointer, table-base, and context-base registers."""
    try:
        from ..analysis.vm_discovery.context_registers import (
            identify_vm_context,
        )
        context_layout = identify_vm_context(
            ws.trace.instructions, ws.dispatcher_addrs, ws.boundaries,
            vip_register=ws.vip_candidate.name,
        )
        ws.context_layout_data = context_layout.to_dict()
        ws.shared_data["vm_context_layout"] = ws.context_layout_data
    except _STAGE_ERRORS as exc:
        logger.debug("VM context register identification skipped: %s", exc)


# ---------------------------------------------------------------------------
# Sub-step 7: Semantic analysis + clustering + ML
# ---------------------------------------------------------------------------

def step_analyze_semantics(ws: DevirtWorkspace) -> None:
    """Classify handler semantics, cluster variants, and run ML ensemble."""
    from ..analysis.handler_semantics import analyse_handler_semantics

    # Collect symbolic summaries from all available sources
    sym_summaries: dict[int, Any] | None = None
    try:
        from ..analysis.symbolic_depth import collect_symbolic_summaries
        ext_handlers = None
        if ws.extraction_data and isinstance(ws.extraction_data, dict):
            ext_handlers = ws.extraction_data.get("handlers")
        sym_summaries = collect_symbolic_summaries(
            ws.shared_data,
            boundaries=ws.boundaries,
            handler_bodies=ext_handlers,
            bit_width=64,
            run_fresh=True,
        ) or None
    except _STAGE_ERRORS as exc:
        logger.debug("Symbolic depth collection skipped: %s", exc)
        sym_summaries = ws.shared_data.get(
            "symbolic_execution", {},
        ).get("handler_summaries", None)

    ws.opcode_table = analyse_handler_semantics(
        ws.trace, ws.boundaries,
        symbolic_summaries=sym_summaries,
        vip_register=ws.vip_candidate.name if ws.vip_candidate else None,
        dispatcher_addresses=tuple(ws.dispatcher_addrs),
    )

    # Cluster semantically-equivalent handler variants
    try:
        from ..analysis.handler_clustering import (
            cluster_handlers_by_semantics,
            refine_opcode_table,
        )
        clustering_result = cluster_handlers_by_semantics(
            ws.opcode_table.entries,
            symbolic_summaries=sym_summaries,
        )
        ws.clustering_data = clustering_result.to_dict()
        ws.shared_data["handler_clustering"] = ws.clustering_data

        ws.opcode_table = refine_opcode_table(
            ws.opcode_table, clustering_result,
        )
    except _STAGE_ERRORS as exc:
        logger.debug("Handler clustering skipped: %s", exc)

    # ML ensemble classification
    _run_ml_classification(ws, sym_summaries)


def _run_ml_classification(
    ws: DevirtWorkspace,
    sym_summaries: dict[int, Any] | None,
) -> None:
    """Run ML ensemble classification on opcode table entries."""
    try:
        from ..ml.ensemble import WeightedEnsemble
        from ..ml.model import SymbolicClassifierModel, VMHandlerModel

        sym_model = SymbolicClassifierModel()
        heur_model = VMHandlerModel()
        ensemble = WeightedEnsemble(
            models=[heur_model, sym_model],
            weights=[0.4, 0.6],
        )

        ws.ml_labels = {}
        for entry in ws.opcode_table.entries:
            features: dict[str, Any] = {}
            if sym_summaries and entry.handler_address in sym_summaries:
                s = sym_summaries[entry.handler_address]
                features["symbolic_summary"] = (
                    s.to_dict() if hasattr(s, "to_dict") else s
                )
            sem = entry.semantic
            if sem is not None:
                hist = getattr(sem, "mnemonic_histogram", {}) or {}
                total = max(sum(hist.values()), 1)
                features["values"] = [
                    hist.get("add", 0) / total,
                    hist.get("and", 0) / total,
                    hist.get("mov", 0) / total,
                    hist.get("push", 0) / total,
                    0.0, 0.0, 0.0, 0.0, 0.0,
                    float(total), 0.0, 0.0, 0.0,
                ]
                features["names"] = [
                    "arith_ratio", "logic_ratio", "mem_ratio",
                    "stack_ratio", "branch_ratio", "vip_delta",
                    "nop_ratio", "junk_ratio", "reg_diversity",
                    "insn_count", "avg_operands", "push_ratio",
                    "pop_ratio",
                ]

            pred = ensemble.predict(features)
            addr_hex = f"0x{entry.handler_address:x}"
            ws.ml_labels[addr_hex] = pred.label

            # Confidence boost when ML agrees with symbolic
            if (
                sem is not None
                and pred.label == sem.operation
                and pred.confidence > 0.7
            ):
                sem.confidence = min(sem.confidence + 0.05, 1.0)
    except _STAGE_ERRORS as exc:
        logger.debug("ML ensemble classification skipped: %s", exc)


# ---------------------------------------------------------------------------
# Sub-step 7b: Handler-level CFG construction
# ---------------------------------------------------------------------------

def step_build_cfgs(ws: DevirtWorkspace) -> None:
    """Build handler-level CFG from trace and optionally from static bytecode."""
    try:
        from ..analysis.bytecode_cfg import (
            build_handler_cfg,
            build_static_cfg,
        )
        handler_cfg_obj = build_handler_cfg(
            ws.opcode_table, ws.boundaries, ws.trace,
        )
        if handler_cfg_obj.blocks:
            ws.handler_cfg = handler_cfg_obj.graph  # networkx DiGraph
            ws.handler_cfg_data = handler_cfg_obj.to_dict()
            ws.shared_data["handler_cfg"] = ws.handler_cfg_data

        # Static CFG from decrypted bytecode
        if ws.bytecode_decryptor is not None and ws.binary_data:
            vip_start = (
                ws.boundaries[0].vip_value if ws.boundaries else 0
            )
            bc_offset = vip_start - ws.base_address
            if 0 <= bc_offset < len(ws.binary_data):
                bc_end = min(len(ws.binary_data), bc_offset + 0x10000)
                bc_bytes = ws.binary_data[bc_offset:bc_end]
                static_cfg_obj = build_static_cfg(
                    bc_bytes, ws.opcode_table, vip_start,
                    decryptor=ws.bytecode_decryptor,
                )
                if static_cfg_obj.blocks:
                    ws.shared_data["static_handler_cfg"] = (
                        static_cfg_obj.to_dict()
                    )
                    if ws.handler_cfg is None:
                        ws.handler_cfg = static_cfg_obj.graph
                        ws.handler_cfg_data = static_cfg_obj.to_dict()
                        ws.shared_data["handler_cfg"] = ws.handler_cfg_data
    except _STAGE_ERRORS as exc:
        logger.debug("Handler CFG construction skipped: %s", exc)


# ---------------------------------------------------------------------------
# Sub-step 8: Pseudocode emission
# ---------------------------------------------------------------------------

def step_emit_pseudocode(ws: DevirtWorkspace) -> None:
    """Emit human-readable pseudocode from the opcode table."""
    from ..analysis.pseudocode import emit_pseudocode

    ws.pseudocode_result = emit_pseudocode(
        ws.opcode_table, ws.boundaries, ws.handler_cfg,
        style="c_like",
        context_layout=ws.shared_data.get("vm_context_layout"),
        clustering=ws.shared_data.get("handler_clustering"),
    )


# ---------------------------------------------------------------------------
# Sub-step 9: Nested VM detection
# ---------------------------------------------------------------------------

def _recover_nested_structural(
    trace_insns: list[Any],
    boundaries: list[Any],
    outer_vip: str,
    depth: int,
    max_depth: int,
    out_layers: list[dict[str, Any]],
    seen: set[int],
) -> None:
    """Structurally detect & recover nested VMs inside *boundaries*.

    Unlike the semantic-label path, this fires on any handler slice that is
    *itself* a VM (its own dispatch loop + a distinct monotonic vIP), so it
    catches nested interpreters that opcode classification mislabelled and
    inner dispatchers of any shape (``cmp/je`` chains, jump tables, …).
    Recurses up to *max_depth* for VM-in-VM-in-VM.
    """
    from ..analysis.handler_semantics import analyse_handler_semantics
    from ..analysis.pseudocode import emit_pseudocode
    from ..analysis.trace_ingestion import ExecutionTrace
    from ..analysis.vm_discovery.handler_boundaries import (
        identify_vip_register,
        segment_trace,
    )
    from ..analysis.vm_discovery.structural import find_nested_vms

    if depth > max_depth or not boundaries:
        return

    full = ExecutionTrace(instructions=list(trace_insns))
    for nv in find_nested_vms(full, boundaries, outer_vip):
        if nv.outer_handler_address in seen:
            continue
        seen.add(nv.outer_handler_address)

        sub_insns = trace_insns[nv.trace_start:nv.trace_end]
        sub = ExecutionTrace(instructions=sub_insns)
        # Inner dispatch may be a cmp/je chain (no indirect jump), so segment
        # using the structurally-detected loop addresses; segment_trace also
        # falls back to vIP-change boundaries if these are empty.
        inner_vip = identify_vip_register(sub, nv.dispatch_addresses)
        if inner_vip is None:
            continue
        inner_seg = segment_trace(sub, inner_vip, nv.dispatch_addresses)
        if not inner_seg.boundaries:
            continue
        inner_opcode = analyse_handler_semantics(
            sub, inner_seg.boundaries,
            vip_register=inner_vip.name,
            dispatcher_addresses=tuple(nv.dispatch_addresses),
        )
        inner_pseudo = emit_pseudocode(
            inner_opcode, inner_seg.boundaries, None, style="c_like",
        )
        out_layers.append({
            "depth": depth,
            "entry_address": nv.outer_handler_address,
            "detection": "structural",
            "vip_register": inner_vip.name,
            "handler_count": len(inner_seg.boundaries),
            "unique_operations": inner_opcode.unique_operations,
            "operations": sorted({
                e.semantic.operation for e in inner_opcode.entries
            }),
            "pseudocode": inner_pseudo.text,
            "confidence": nv.confidence,
        })
        # Recurse: a nested VM may itself enter a deeper VM.
        _recover_nested_structural(
            sub_insns, inner_seg.boundaries, inner_vip.name,
            depth + 1, max_depth, out_layers, seen,
        )


def step_detect_nested_vms(ws: DevirtWorkspace) -> None:
    """Detect and recursively deobfuscate nested VM layers (B100)."""
    from ..analysis.handler_semantics import analyse_handler_semantics
    from ..analysis.pseudocode import emit_pseudocode

    # These helpers are defined in pipeline.py at module level
    from ..analysis.trace_ingestion import ExecutionTrace
    from ..analysis.vm_discovery.dispatcher import find_dispatcher
    from ..analysis.vm_discovery.handler_boundaries import (
        identify_vip_register,
        segment_trace,
    )
    from .pipeline import _detect_inner_vm_entries, _extract_inner_trace

    max_nesting = int(ws.shared_data.get("max_nesting_depth", 3))

    try:
        inner_entries = _detect_inner_vm_entries(
            ws.opcode_table, ws.handler_cfg, ws.shared_data,
        )
        nesting_depth = 0
        while inner_entries and nesting_depth < max_nesting:
            nesting_depth += 1
            logger.info(
                "Nested VM layer %d: %d inner entry points detected",
                nesting_depth, len(inner_entries),
            )
            for inner_entry in inner_entries:
                inner_trace = _extract_inner_trace(
                    ws.trace.instructions, inner_entry, ws.boundaries,
                )
                if not inner_trace:
                    continue
                inner_records = [
                    ti.to_dict() if hasattr(ti, "to_dict") else ti
                    for ti in inner_trace
                ]
                inner_match = find_dispatcher(
                    inner_records, bit_width=64,
                )
                if inner_match is None:
                    continue
                inner_disp_addrs = inner_match.to_dict().get(
                    "handler_addresses", [],
                )
                # Wrap the sliced instruction list as an ExecutionTrace for the
                # boundary/semantics helpers (which read ``trace.instructions``).
                inner_exec = ExecutionTrace(instructions=inner_trace)
                inner_vip = identify_vip_register(
                    inner_exec, inner_disp_addrs,
                )
                if inner_vip is None:
                    continue
                inner_seg = segment_trace(
                    inner_exec, inner_vip, inner_disp_addrs,
                )
                if not inner_seg.boundaries:
                    continue
                inner_opcode = analyse_handler_semantics(
                    inner_exec, inner_seg.boundaries,
                )
                inner_pseudo = emit_pseudocode(
                    inner_opcode, inner_seg.boundaries, None,
                    style="c_like",
                )
                ws.nested_layers.append({
                    "depth": nesting_depth,
                    "entry_address": inner_entry,
                    "protector": inner_match.protector,
                    "handler_count": len(inner_seg.boundaries),
                    "unique_operations": inner_opcode.unique_operations,
                    "pseudocode": inner_pseudo.text,
                })
            # Check for deeper nesting in the last layer
            if ws.nested_layers:
                inner_entries = _detect_inner_vm_entries(
                    inner_opcode, None, ws.shared_data,
                )
            else:
                break

        # Structural pass: catch nested VMs that opcode classification
        # mislabelled (so the semantic-label trigger above missed) and inner
        # dispatchers of any shape.  Recurses for VM-in-VM and dedupes against
        # whatever the semantic path already recorded.
        if ws.vip_candidate is not None and ws.boundaries:
            seen: set[int] = {
                int(layer.get("entry_address", 0))
                for layer in ws.nested_layers
            }
            _recover_nested_structural(
                ws.trace.instructions, ws.boundaries,
                ws.vip_candidate.name, 1, max_nesting,
                ws.nested_layers, seen,
            )
    except _STAGE_ERRORS as exc:
        logger.debug("Nested VM detection skipped: %s", exc)


# ---------------------------------------------------------------------------
# Sub-step 10: Assemble final result
# ---------------------------------------------------------------------------

def step_assemble_result(ws: DevirtWorkspace) -> dict[str, Any]:
    """Build the final :class:`DevirtualisationResult` and return as dict."""
    from ..analysis.devirtualisation_result import DevirtualisationResult

    result = DevirtualisationResult(
        success=True,
        vip_register=ws.vip_candidate.name,
        handler_count=len(ws.boundaries),
        unique_operations=ws.opcode_table.unique_operations,
        opcode_table=ws.opcode_table.to_dict(),
        pseudocode=ws.pseudocode_result.to_dict(),
        pseudocode_text=ws.pseudocode_result.text,
        anti_evasion_hooks=ws.hook_set_data,
        vmprotect_dispatcher=ws.vmprotect_match,
        dispatcher_match=ws.dispatcher_match,
        detected_protector=ws.detected_protector,
        handler_extraction=ws.extraction_data,
        vm_context_layout=ws.context_layout_data,
        handler_clustering=ws.clustering_data,
        handler_cfg=ws.handler_cfg_data,
        vm_entry_points=ws.vm_entry_data,
        decrypted_handler_table=ws.shared_data.get("decrypted_handler_table"),
        bytecode_decryptor=ws.shared_data.get("bytecode_decryptor"),
        static_handler_cfg=ws.shared_data.get("static_handler_cfg"),
        ml_classifications=ws.ml_labels,
        nested_layers=ws.nested_layers or None,
    )

    # Store boundaries for downstream stages
    ws.shared_data["devirt_boundaries"] = [
        {
            "vip_value": b.vip_value,
            "handler_address": b.handler_address,
            "vip_delta": b.vip_delta,
            "instruction_count": b.instruction_count,
        }
        for b in ws.boundaries
    ]

    return result.to_dict()
