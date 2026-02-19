"""
Taint Tracking — Analyzer
==========================

High-level analysis interface that integrates taint tracking with
the pipeline's shared context and other analysis results.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .tracker import TaintTracker, TaintTag

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
        taint_sources: Optional[Dict[str, str]] = None,
        shared_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
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
        # Apply taint sources
        tag_map = {
            "input": TaintTag.INPUT,
            "vm_operand": TaintTag.VM_OPERAND,
            "vm_context": TaintTag.VM_CONTEXT,
            "memory": TaintTag.MEMORY,
            "crypto": TaintTag.CRYPTO,
        }

        for name, tag_name in (taint_sources or {}).items():
            tag = tag_map.get(tag_name.lower(), TaintTag.INPUT)
            self._tracker.taint_register(name, tag)

        # Auto-taint from shared data
        if shared_data:
            vm_data = shared_data.get("vm_discovery", {})
            if vm_data.get("vm_detected"):
                # Auto-taint common VM context registers
                self._tracker.taint_register("rbp", TaintTag.VM_CONTEXT)
                self._tracker.taint_register("rsi", TaintTag.VM_CONTEXT)

        result = self._tracker.analyze(instructions)

        return result.to_dict()
