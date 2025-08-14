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
Symbolic Execution Module
========================

Unified symbolic execution engine for VM handler analysis.

This module provides symbolic execution capabilities for analyzing
VM bytecode handlers and understanding their behavior.
"""

from .executor import (
    ConstraintType,
    ExecutionContext,
    PathPriority,
    SymbolicConstraint,
    SymbolicExecutor,
    SymbolicValue,
)
from .lifter import (
    HandlerLifter,
    Instruction,
    InstructionLifter,
    InstructionType,
    LiftingResult,
    LiftingStrategy,
    VMHandlerInfo,
)
from .solver import ConstraintSolver, SimplifiedSolver, SolverResult, Z3Solver

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
    "VMHandlerInfo",
]
