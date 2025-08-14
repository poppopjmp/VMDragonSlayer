"""
Symbolic Execution Module
========================

Unified symbolic execution engine for VM handler analysis.

This module provides symbolic execution capabilities for analyzing
VM bytecode handlers and understanding their behavior.
"""

from .executor import (
    SymbolicExecutor,
    ExecutionContext,
    SymbolicValue,
    SymbolicConstraint,
    ConstraintType,
    PathPriority
)

from .solver import (
    ConstraintSolver,
    Z3Solver,
    SimplifiedSolver,
    SolverResult
)

from .lifter import (
    HandlerLifter,
    InstructionLifter,
    Instruction,
    InstructionType,
    LiftingStrategy,
    LiftingResult,
    VMHandlerInfo
)

__all__ = [
    # Executor components
    "SymbolicExecutor",
    "ExecutionContext", 
    "SymbolicValue",
    "SymbolicConstraint",
    "ConstraintType",
    "PathPriority",
    
    # Solver components
    "ConstraintSolver",
    "Z3Solver",
    "SimplifiedSolver", 
    "SolverResult",
    
    # Lifter components
    "HandlerLifter",
    "InstructionLifter",
    "Instruction",
    "InstructionType",
    "LiftingStrategy",
    "LiftingResult",
    "VMHandlerInfo"
]
