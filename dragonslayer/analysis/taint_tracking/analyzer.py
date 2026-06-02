"""
Taint Tracking — Analyzer
==========================

High-level analysis interface that integrates taint tracking with
the pipeline's shared context and other analysis results.
"""

from __future__ import annotations

import logging
from typing import Any

from .tracker import TaintTag, TaintTracker

logger = logging.getLogger(__name__)


class TaintAnalyzer:
    """
    Combines taint tracking with external analysis data.

    Used by the pipeline to run taint analysis and store results
    in the shared context.
    """

    def __init__(self) -> None:
        self._tracker = TaintTracker()

    def analyze(
        self,
        instructions: list,
        *,
        taint_sources: dict[str, str] | None = None,
        shared_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Run taint analysis with configurable taint sources.

        Parameters
        ----------
        instructions : list
            Lifted instructions.
        taint_sources : dict | None
            Map of register/label → taint tag name to apply.
        shared_data : dict | None
            Pipeline shared data for cross-stage context.
        """
        tag_map = {
            "input": TaintTag.INPUT,
            "vm_operand": TaintTag.VM_OPERAND,
            "vm_context": TaintTag.VM_CONTEXT,
            "memory": TaintTag.MEMORY,
            "crypto": TaintTag.CRYPTO,
        }

        # Reset accumulated state from any previous analysis *first*,
        # then apply taint sources exactly once.
        self._tracker.reset()

        # Apply explicit taint sources
        for name, tag_name in (taint_sources or {}).items():
            tag = tag_map.get(tag_name.lower(), TaintTag.INPUT)
            self._tracker.taint_register(name, tag)

        # Auto-taint VM context registers when VM protection is detected
        if shared_data:
            vm_data = shared_data.get("vm_discovery", {})
            if vm_data.get("vm_detected"):
                self._tracker.taint_register("rbp", TaintTag.VM_CONTEXT)
                self._tracker.taint_register("rsi", TaintTag.VM_CONTEXT)

        result = self._tracker.analyze(instructions)

        return result.to_dict()
