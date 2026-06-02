"""
Taint Tracking — DTT Executor
==============================

Dynamic Taint Tracking executor that combines the :class:`TaintTracker`
with the :class:`SymbolicExecutor` to perform taint-guided symbolic
execution — tracking data flow while exploring paths.

When Triton plugin output is available, the executor can be seeded with
Triton's per-instruction taint flags and path constraints for a more
accurate analysis.
"""

from __future__ import annotations

import logging
from typing import Any

from .tracker import TaintTag, TaintTracker

logger = logging.getLogger(__name__)


class DTTExecutor:
    """
    Dynamic Taint Tracking executor.

    Combines taint analysis with instruction execution to provide
    per-instruction taint snapshots.  This is used by the pipeline
    to feed LLM-assisted code recovery.

    When the instruction sequence comes from
    :meth:`ExecutionTrace.to_lifted_instructions`, each instruction may
    carry an ``is_tainted`` flag (from Triton) and a ``registers`` dict
    (concrete snapshots from Qiling/angr/Triton).  The executor uses
    these to:

    * Automatically seed taint on registers that Triton flagged as
      tainted at the first instruction.
    * Supply concrete register values for memory-address resolution.

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
        taint_sources: dict[str, str] | None = None,
        triton_taint_flow: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Execute taint tracking with per-instruction snapshots.

        Parameters
        ----------
        instructions : list
            Lifted instruction sequence.
        taint_sources : dict | None
            Initial taint sources (register name → tag name).
        triton_taint_flow : list[dict] | None
            Raw ``taint_flow`` entries from the Triton plugin.  Each
            entry may have ``address``, ``is_tainted``, and a list of
            ``tainted_regs``.  When provided, any register that Triton
            considers tainted at the first trace address is
            automatically seeded.

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
        self._tracker.reset()
        for reg, tag_name in (taint_sources or {}).items():
            tag = tag_map.get(tag_name.lower(), TaintTag.INPUT)
            self._tracker.taint_register(reg, tag)

        # --- Seed from Triton taint_flow if provided --------------------
        triton_seeded: list[str] = []
        if triton_taint_flow:
            for entry in triton_taint_flow:
                for reg in entry.get("tainted_regs", []):
                    rn = reg.lower()
                    if not self._tracker.is_tainted(rn):
                        self._tracker.taint_register(rn, TaintTag.INPUT)
                        triton_seeded.append(rn)
                # Only seed from the first entry that has tainted_regs.
                if triton_seeded:
                    break

        # --- Seed from per-instruction ``is_tainted`` flag --------------
        # If the first instruction is itself marked tainted and carries
        # concrete registers, taint all registers present.
        if instructions and not triton_seeded:
            first = instructions[0]
            if getattr(first, "is_tainted", False):
                for reg in getattr(first, "writes", []):
                    rn = reg.lower()
                    if not self._tracker.is_tainted(rn):
                        self._tracker.taint_register(rn, TaintTag.INPUT)
                        triton_seeded.append(rn)

        # Execute with snapshots
        snapshots: list[dict[str, Any]] = []
        for insn in instructions:
            # Snapshot before
            state_before = self._tracker.get_state()

            # Process instruction
            self._tracker.process_instruction(insn)

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

        return {
            "success": True,
            "snapshots": snapshots[:200],  # cap
            "snapshots_total": len(snapshots),
            "final_tainted_registers": {
                reg: str(tag) for reg, tag in self._tracker.reg_taint.items()
                if tag != TaintTag.CLEAN
            },
            "instructions_processed": len(instructions),
            "triton_seeded_registers": triton_seeded,
        }
