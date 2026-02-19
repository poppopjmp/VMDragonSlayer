"""
Taint Tracking — DTT Executor
==============================

Dynamic Taint Tracking executor that combines the :class:`TaintTracker`
with the :class:`SymbolicExecutor` to perform taint-guided symbolic
execution — tracking data flow while exploring paths.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .tracker import TaintTracker, TaintTag, TaintResult

logger = logging.getLogger(__name__)


class DTTExecutor:
    """
    Dynamic Taint Tracking executor.

    Combines taint analysis with instruction execution to provide
    per-instruction taint snapshots.  This is used by the pipeline
    to feed LLM-assisted code recovery.

    Usage::

        dtt = DTTExecutor()
        result = dtt.execute(lifted_instructions, taint_sources={"rdi": "input"})
    """

    def __init__(self) -> None:
        self._tracker = TaintTracker()

    def execute(
        self,
        instructions: list,
        *,
        taint_sources: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Execute taint tracking with per-instruction snapshots.

        Parameters
        ----------
        instructions : list
            Lifted instruction sequence.
        taint_sources : dict | None
            Initial taint sources (register name → tag name).

        Returns
        -------
        dict
            Analysis result with per-instruction taint state.
        """
        tag_map = {
            "input": TaintTag.INPUT,
            "vm_operand": TaintTag.VM_OPERAND,
            "vm_context": TaintTag.VM_CONTEXT,
            "memory": TaintTag.MEMORY,
        }

        # Apply initial taints
        for reg, tag_name in (taint_sources or {}).items():
            tag = tag_map.get(tag_name.lower(), TaintTag.INPUT)
            self._tracker.taint_register(reg, tag)

        # Execute with snapshots
        snapshots: List[Dict[str, Any]] = []
        for insn in instructions:
            # Snapshot before
            state_before = self._tracker.get_state()

            # Process instruction
            self._tracker._process_instruction(insn)

            # Snapshot after
            state_after = self._tracker.get_state()

            # Record if taint changed
            changed_regs = {}
            for reg in set(list(state_before.registers.keys()) + list(state_after.registers.keys())):
                before = state_before.registers.get(reg, TaintTag.CLEAN)
                after = state_after.registers.get(reg, TaintTag.CLEAN)
                if before != after:
                    changed_regs[reg] = {"before": str(before), "after": str(after)}

            if changed_regs:
                snapshots.append({
                    "address": getattr(insn, "address", 0),
                    "instruction": f"{getattr(insn, 'mnemonic', '')} {getattr(insn, 'operands', '')}",
                    "taint_changes": changed_regs,
                })

        # Final result
        final_result = self._tracker.analyze([])  # get accumulated state

        return {
            "success": True,
            "snapshots": snapshots[:200],  # cap
            "snapshots_total": len(snapshots),
            "final_tainted_registers": {
                reg: str(tag) for reg, tag in self._tracker._reg_taint.items()
                if tag != TaintTag.CLEAN
            },
            "instructions_processed": len(instructions),
        }
