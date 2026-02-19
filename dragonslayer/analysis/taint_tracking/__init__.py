"""
Taint Tracking Module
====================

Data-flow taint tracking for VM-protected binary analysis.

Tracks how tainted inputs flow through registers and memory
to identify handler semantics and data dependencies.
"""

try:
    from .tracker import (
        TaintTracker,
        TaintTag,
        TaintState,
        TaintEvent,
        TaintResult,
    )
except (ImportError, AttributeError):
    TaintTracker = None  # type: ignore[assignment,misc]
    TaintTag = None  # type: ignore[assignment,misc]
    TaintState = None  # type: ignore[assignment,misc]
    TaintEvent = None  # type: ignore[assignment,misc]
    TaintResult = None  # type: ignore[assignment,misc]

try:
    from .analyzer import TaintAnalyzer
except (ImportError, AttributeError):
    TaintAnalyzer = None  # type: ignore[assignment,misc]

try:
    from .vm_taint_tracker import VMTaintTracker, VM_REG_PRESETS
except (ImportError, AttributeError):
    VMTaintTracker = None  # type: ignore[assignment,misc]
    VM_REG_PRESETS = {}  # type: ignore[assignment]

try:
    from .dtt_executor import DTTExecutor
except (ImportError, AttributeError):
    DTTExecutor = None  # type: ignore[assignment,misc]

__all__ = [
    "TaintTracker",
    "TaintTag",
    "TaintState",
    "TaintEvent",
    "TaintResult",
    "TaintAnalyzer",
    "VMTaintTracker",
    "VM_REG_PRESETS",
    "DTTExecutor",
]
