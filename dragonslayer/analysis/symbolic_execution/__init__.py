"""
Symbolic Execution Module

All imports are guarded so the package loads even when the backing
modules have not been implemented yet.
"""

try:
    from .state import SymbolicState, AliasResult, MemoryWrite
except (ImportError, AttributeError):
    SymbolicState = None  # type: ignore[assignment,misc]
    AliasResult = None  # type: ignore[assignment,misc]
    MemoryWrite = None  # type: ignore[assignment,misc]

try:
    from .solver import Z3Solver, SolverResult
except (ImportError, AttributeError):
    Z3Solver = None  # type: ignore[assignment,misc]
    SolverResult = None  # type: ignore[assignment,misc]

try:
    from .lifter import InstructionLifter, LiftedInstruction
except (ImportError, AttributeError):
    InstructionLifter = None  # type: ignore[assignment,misc]
    LiftedInstruction = None  # type: ignore[assignment,misc]

try:
    from .executor import SymbolicExecutor, ExecutionResult, HandlerSymbolicSummary
except (ImportError, AttributeError):
    SymbolicExecutor = None  # type: ignore[assignment,misc]
    ExecutionResult = None  # type: ignore[assignment,misc]
    HandlerSymbolicSummary = None  # type: ignore[assignment,misc]

__all__ = [
    'SymbolicState',
    'Z3Solver',
    'SolverResult',
    'InstructionLifter',
    'LiftedInstruction',
    'SymbolicExecutor',
    'ExecutionResult',
    'HandlerSymbolicSummary',
]
