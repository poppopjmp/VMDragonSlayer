"""
Symbolic Execution Module

All imports are guarded so the package loads even when the backing
modules have not been implemented yet.
"""

try:
    from .state import (
        AliasResult,
        MemoryAccessRecord,
        MemoryWrite,
        SymbolicMemoryRegion,
        SymbolicState,
    )
except (ImportError, AttributeError):
    SymbolicState = None  # type: ignore[assignment,misc]
    AliasResult = None  # type: ignore[assignment,misc]
    MemoryWrite = None  # type: ignore[assignment,misc]
    SymbolicMemoryRegion = None  # type: ignore[assignment,misc]
    MemoryAccessRecord = None  # type: ignore[assignment,misc]

try:
    from .solver import SolverResult, Z3Solver
except (ImportError, AttributeError):
    Z3Solver = None  # type: ignore[assignment,misc]
    SolverResult = None  # type: ignore[assignment,misc]

try:
    from .lifter import InstructionLifter, LiftedInstruction
except (ImportError, AttributeError):
    InstructionLifter = None  # type: ignore[assignment,misc]
    LiftedInstruction = None  # type: ignore[assignment,misc]

try:
    from .executor import (
        ExecutionResult,
        HandlerSymbolicSummary,
        LoopInfo,
        SymbolicExecutor,
    )
except (ImportError, AttributeError):
    SymbolicExecutor = None  # type: ignore[assignment,misc]
    ExecutionResult = None  # type: ignore[assignment,misc]
    HandlerSymbolicSummary = None  # type: ignore[assignment,misc]
    LoopInfo = None  # type: ignore[assignment,misc]

__all__ = [
    'SymbolicState',
    'SymbolicMemoryRegion',
    'MemoryAccessRecord',
    'Z3Solver',
    'SolverResult',
    'InstructionLifter',
    'LiftedInstruction',
    'SymbolicExecutor',
    'ExecutionResult',
    'HandlerSymbolicSummary',
    'LoopInfo',
]
