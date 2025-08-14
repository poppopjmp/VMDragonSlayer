# VMDragonSlayer - Advanced VM detection and analysis library
# Copyright (C) 2025 van1sh
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

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

from .analyzer import TaintAnalysisResult, VMHandlerSignature, VMTaintAnalyzer
from .tracker import (
    EnhancedVMTaintTracker,  # Backwards compatibility alias
    OperationType,
    TaintEvent,
    TaintEventAnalyzer,
    TaintInfo,
    TaintPropagation,
    TaintScope,
    TaintTracker,
    TaintType,
)

# Import VM taint tracker and DTT executor
try:
    from .dtt_executor import OptimizedDTTExecutor
    from .vm_taint_tracker import VMTaintTracker
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
    "EnhancedVMTaintTracker",
]
