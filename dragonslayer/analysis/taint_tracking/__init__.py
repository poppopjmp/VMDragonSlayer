"""
Taint Tracking Module
====================

Unified dynamic taint tracking for VM analysis.

This module provides comprehensive taint tracking capabilities including:
- Dynamic taint propagation through VMDragonTaint.cpp
- VM handler signature analysis
- Data flow analysis
- Execution trace processing
- Optimized DTT execution
"""

from .tracker import (
    TaintTracker,
    TaintInfo,
    TaintType,
    TaintScope,
    OperationType,
    TaintEvent,
    TaintPropagation,
    TaintEventAnalyzer,
    EnhancedVMTaintTracker  # Backwards compatibility alias
)

from .analyzer import (
    VMTaintAnalyzer,
    VMHandlerSignature,
    TaintAnalysisResult
)

# Import VM taint tracker and DTT executor
try:
    from .vm_taint_tracker import VMTaintTracker
    from .dtt_executor import OptimizedDTTExecutor
except ImportError:
    # Graceful fallback if dependencies are missing
    VMTaintTracker = None
    OptimizedDTTExecutor = None

__all__ = [
    # Core tracking
    "TaintTracker",
    "TaintInfo",
    "TaintType",
    "TaintScope", 
    "OperationType",
    "TaintEvent",
    "TaintPropagation",
    "TaintEventAnalyzer",
    
    # Analysis
    "VMTaintAnalyzer",
    "VMHandlerSignature",
    "TaintAnalysisResult",
    
    # VM taint tracking (if available)
    "VMTaintTracker",
    "OptimizedDTTExecutor",
    
    # Backwards compatibility
    "EnhancedVMTaintTracker"
]
