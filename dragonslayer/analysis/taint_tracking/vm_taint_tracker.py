"""
Taint Tracking — VM Taint Tracker
==================================

Specialised taint tracker for VM-protected binaries.  Extends
:class:`TaintTracker` with VM-specific heuristics:

* Taints VM context registers (virtual IP, virtual SP, handler table ptr).
* Tracks operand fetch → decode → execute flow.
* Identifies handler boundaries by taint-flow discontinuities.
* Maps native registers to VM virtual registers for easier analysis.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .tracker import TaintTracker, TaintTag, TaintResult

logger = logging.getLogger(__name__)

# ── Virtual register mapping presets ───────────────────────────────────
# Each mapping: native_reg -> vm_role
_VMPROTECT_X64_MAP: Dict[str, str] = {
    "rsi": "vIP",          # virtual instruction pointer
    "rbp": "vSP",          # virtual stack pointer
    "rdi": "vContext",     # VM context base pointer
    "r12": "vHandlerTbl",  # handler dispatch table base
}

_VMPROTECT_X86_MAP: Dict[str, str] = {
    "esi": "vIP",
    "ebp": "vSP",
    "edi": "vContext",
}

_THEMIDA_X64_MAP: Dict[str, str] = {
    "rbx": "vIP",
    "rbp": "vSP",
    "rsi": "vContext",
}

VM_REG_PRESETS: Dict[str, Dict[str, str]] = {
    "vmprotect_x64": _VMPROTECT_X64_MAP,
    "vmprotect_x86": _VMPROTECT_X86_MAP,
    "themida_x64": _THEMIDA_X64_MAP,
}


class VMTaintTracker:
    """
    VM-aware taint tracker.

    Automatically taints likely VM context locations and tracks
    handler-to-handler data flow.  Supports virtual register mapping
    so that taint events expose VM-level register names.

    Usage::

        vtt = VMTaintTracker()
        result = vtt.analyze_vm_trace(
            instructions=lifted_insns,
            vm_context_regs=["rbp", "rsi"],
            vm_preset="vmprotect_x64",
        )
    """

    def __init__(self) -> None:
        self._tracker = TaintTracker()
        self._vreg_map: Dict[str, str] = {}   # native → VM role

    # ── public API ─────────────────────────────────────────────────────
    def analyze_vm_trace(
        self,
        instructions: list,
        *,
        vm_context_regs: Optional[List[str]] = None,
        vm_operand_regs: Optional[List[str]] = None,
        vm_preset: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Analyse a VM execution trace with automatic VM-context tainting.

        Parameters
        ----------
        instructions : list[LiftedInstruction]
            Lifted instruction trace (potentially from qiling/angr).
        vm_context_regs : list[str] | None
            Registers used as VM context pointers (default: rbp, rsi).
        vm_operand_regs : list[str] | None
            Registers used to fetch VM operands (default: rbx, rcx).
        vm_preset : str | None
            Name of VM register preset (e.g. ``"vmprotect_x64"``).
            Overrides vm_context_regs if provided.
        """
        # Default VM register assignments (common in VMProtect)
        ctx_regs = vm_context_regs or ["rbp", "rsi"]
        op_regs = vm_operand_regs or ["rbx", "rcx"]

        # Load virtual register map from preset or build from explicit regs
        if vm_preset and vm_preset in VM_REG_PRESETS:
            self._vreg_map = dict(VM_REG_PRESETS[vm_preset])
            ctx_regs = [r for r, role in self._vreg_map.items()
                        if role in ("vIP", "vSP", "vContext", "vHandlerTbl")]
        else:
            # Build a map from explicit context regs
            self._vreg_map = {}
            role_names = ["vIP", "vSP", "vContext", "vHandlerTbl"]
            for i, reg in enumerate(ctx_regs):
                self._vreg_map[reg.lower()] = role_names[i] if i < len(role_names) else f"vCtx{i}"
            for i, reg in enumerate(op_regs):
                self._vreg_map[reg.lower()] = f"vOperand{i}"

        # Taint VM context registers
        for reg in ctx_regs:
            self._tracker.taint_register(reg, TaintTag.VM_CONTEXT)

        # Taint VM operand registers
        for reg in op_regs:
            self._tracker.taint_register(reg, TaintTag.VM_OPERAND)

        # Run taint analysis
        result = self._tracker.analyze(instructions)

        # Post-process: map native registers to VM register names in events
        mapped_events = self._map_events_to_vreg(result)

        # Post-process: identify handler boundaries
        handler_boundaries = self._find_handler_boundaries(result)

        # Track memory taint summary
        mem_taint_summary = self._summarise_memory_taint()

        return {
            "taint_result": result.to_dict(),
            "mapped_events": mapped_events,
            "vm_context_registers": ctx_regs,
            "vm_operand_registers": op_regs,
            "virtual_register_map": self._vreg_map,
            "handler_boundaries": handler_boundaries,
            "data_flow_summary": self._summarise_flow(result),
            "memory_taint_summary": mem_taint_summary,
        }

    # ── virtual register mapping ───────────────────────────────────────
    def _map_events_to_vreg(self, result: TaintResult) -> List[Dict[str, Any]]:
        """
        Produce an event list where native register names are annotated
        with their VM role names.
        """
        mapped: List[Dict[str, Any]] = []
        for event in result.events:
            entry = dict(event)
            src = event.get("source", "")
            dst = event.get("destination", "")
            if src in self._vreg_map:
                entry["source_vreg"] = self._vreg_map[src]
            if dst in self._vreg_map:
                entry["destination_vreg"] = self._vreg_map[dst]
            mapped.append(entry)
        return mapped

    # ── memory taint summary ───────────────────────────────────────────
    def _summarise_memory_taint(self) -> Dict[str, Any]:
        """Expose memory taint state from the underlying tracker."""
        mem_t = self._tracker._mem_taint  # noqa: SLF001
        if not mem_t:
            return {"tainted_locations": 0, "addresses": []}
        return {
            "tainted_locations": len(mem_t),
            "addresses": [
                {"address": addr, "tag": int(tag)}
                for addr, tag in sorted(mem_t.items())
            ],
        }

    # ── handler boundary detection ─────────────────────────────────────
    @staticmethod
    def _find_handler_boundaries(result: TaintResult) -> List[Dict[str, Any]]:
        """
        Find handler boundaries by looking for patterns where taint
        is consumed and new taint is introduced (handler transitions).

        Detection heuristics:
        1. vIP taint source appears after a gap → new handler fetched.
        2. Untaint followed by re-taint of operand registers → handler switch.
        """
        boundaries: List[Dict[str, Any]] = []
        prev_destinations: set = set()
        last_untaint_addr: int = 0

        for event in result.events:
            dst = event.get("destination", "")
            src = event.get("source", "")
            event_type = event.get("type", "")
            addr = event.get("address", 0)

            if event_type == "untaint":
                last_untaint_addr = addr
                continue

            if event_type == "propagate" and dst not in prev_destinations:
                # Detect re-taint after untaint (handler transition)
                if last_untaint_addr and (addr - last_untaint_addr) < 0x40:
                    boundaries.append({
                        "address": addr,
                        "type": "handler_start",
                        "instruction": event.get("instruction", ""),
                        "evidence": "untaint_retaint_pattern",
                    })
                    last_untaint_addr = 0
                elif prev_destinations:
                    boundaries.append({
                        "address": addr,
                        "type": "handler_start",
                        "instruction": event.get("instruction", ""),
                        "evidence": "new_destination",
                    })
            prev_destinations.add(dst)

        return boundaries

    @staticmethod
    def _summarise_flow(result: TaintResult) -> Dict[str, Any]:
        """Build a summary of the taint flow."""
        event_types: Dict[str, int] = {}
        sources: set = set()
        destinations: set = set()

        for event in result.events:
            et = event.get("type", "")
            event_types[et] = event_types.get(et, 0) + 1
            sources.add(event.get("source", ""))
            destinations.add(event.get("destination", ""))

        return {
            "event_type_counts": event_types,
            "unique_sources": sorted(sources - {""}),
            "unique_destinations": sorted(destinations - {""}),
            "has_implicit_flow": event_types.get("implicit", 0) > 0,
            "has_memory_flow": any(
                "mem[" in d for d in destinations
            ),
        }
