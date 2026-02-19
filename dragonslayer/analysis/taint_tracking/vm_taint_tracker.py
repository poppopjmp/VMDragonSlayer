"""
Taint Tracking — VM Taint Tracker
==================================

Specialised taint tracker for VM-protected binaries.  Extends
:class:`TaintTracker` with VM-specific heuristics:

* Taints VM context registers (virtual IP, virtual SP, handler table ptr).
* Tracks operand fetch → decode → execute flow.
* Identifies handler boundaries by taint-flow discontinuities.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .tracker import TaintTracker, TaintTag, TaintResult

logger = logging.getLogger(__name__)


class VMTaintTracker:
    """
    VM-aware taint tracker.

    Automatically taints likely VM context locations and tracks
    handler-to-handler data flow.

    Usage::

        vtt = VMTaintTracker()
        result = vtt.analyze_vm_trace(
            instructions=lifted_insns,
            vm_context_regs=["rbp", "rsi"],
        )
    """

    def __init__(self) -> None:
        self._tracker = TaintTracker()

    def analyze_vm_trace(
        self,
        instructions: list,
        *,
        vm_context_regs: Optional[List[str]] = None,
        vm_operand_regs: Optional[List[str]] = None,
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
        """
        # Default VM register assignments (common in VMProtect)
        ctx_regs = vm_context_regs or ["rbp", "rsi"]
        op_regs = vm_operand_regs or ["rbx", "rcx"]

        # Taint VM context registers
        for reg in ctx_regs:
            self._tracker.taint_register(reg, TaintTag.VM_CONTEXT)

        # Taint VM operand registers
        for reg in op_regs:
            self._tracker.taint_register(reg, TaintTag.VM_OPERAND)

        # Run taint analysis
        result = self._tracker.analyze(instructions)

        # Post-process: identify handler boundaries
        handler_boundaries = self._find_handler_boundaries(result)

        return {
            "taint_result": result.to_dict(),
            "vm_context_registers": ctx_regs,
            "vm_operand_registers": op_regs,
            "handler_boundaries": handler_boundaries,
            "data_flow_summary": self._summarise_flow(result),
        }

    @staticmethod
    def _find_handler_boundaries(result: TaintResult) -> List[Dict[str, Any]]:
        """
        Find handler boundaries by looking for patterns where taint
        is consumed and new taint is introduced (handler transitions).
        """
        boundaries: List[Dict[str, Any]] = []
        prev_destinations: set = set()

        for event in result.events:
            dst = event.get("destination", "")
            event_type = event.get("type", "")

            if event_type == "propagate" and dst not in prev_destinations:
                if prev_destinations:
                    boundaries.append({
                        "address": event.get("address", 0),
                        "type": "handler_start",
                        "instruction": event.get("instruction", ""),
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
        }
