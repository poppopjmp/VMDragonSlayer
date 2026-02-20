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
        ByteTaintMap,
        MemoryAliasTracker,
        subreg_canonical,
        subreg_aliases,
        subreg_info,
        is_eflags_producer,
        is_eflags_consumer,
    )
except (ImportError, AttributeError):
    TaintTracker = None  # type: ignore[assignment,misc]
    TaintTag = None  # type: ignore[assignment,misc]
    TaintState = None  # type: ignore[assignment,misc]
    TaintEvent = None  # type: ignore[assignment,misc]
    TaintResult = None  # type: ignore[assignment,misc]
    ByteTaintMap = None  # type: ignore[assignment,misc]
    subreg_canonical = None  # type: ignore[assignment,misc]
    subreg_aliases = None  # type: ignore[assignment,misc]
    subreg_info = None  # type: ignore[assignment,misc]
    is_eflags_producer = None  # type: ignore[assignment,misc]
    is_eflags_consumer = None  # type: ignore[assignment,misc]

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

try:
    from .inter_handler import (
        InterHandlerDataFlow,
        InterHandlerFlowResult,
        InterHandlerFlowEdge,
        HandlerTaintSummary,
        build_handler_summary,
        canonicalize_reg,
        compose_summaries,
    )
except (ImportError, AttributeError):
    InterHandlerDataFlow = None  # type: ignore[assignment,misc]
    InterHandlerFlowResult = None  # type: ignore[assignment,misc]
    InterHandlerFlowEdge = None  # type: ignore[assignment,misc]
    HandlerTaintSummary = None  # type: ignore[assignment,misc]
    build_handler_summary = None  # type: ignore[assignment,misc]
    canonicalize_reg = None  # type: ignore[assignment,misc]
    compose_summaries = None  # type: ignore[assignment,misc]

__all__ = [
    "TaintTracker",
    "TaintTag",
    "TaintState",
    "TaintEvent",
    "TaintResult",
    "ByteTaintMap",
    "TaintAnalyzer",
    "VMTaintTracker",
    "VM_REG_PRESETS",
    "DTTExecutor",
    "InterHandlerDataFlow",
    "InterHandlerFlowResult",
    "InterHandlerFlowEdge",
    "HandlerTaintSummary",
    "build_handler_summary",
    "canonicalize_reg",
    "compose_summaries",
]
