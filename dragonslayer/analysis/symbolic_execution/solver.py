"""
Symbolic Execution — Solver
============================

Z3-backed constraint solver for resolving symbolic values during VM
handler analysis.  Wraps z3 to provide a simpler interface focused on
common VM deobfuscation tasks:

* Solving opaque predicates (prove always-true / always-false).
* Computing concrete inputs that reach a given handler.
* Simplifying symbolic expressions.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

import z3


@dataclass
class SolverResult:
    """Outcome of a solver query."""
    satisfiable: bool
    model: Optional[Dict[str, Any]] = None
    simplified: Optional[str] = None
    error: Optional[str] = None


class Z3Solver:
    """
    High-level Z3 wrapper for VM deobfuscation tasks.

    Usage::

        solver = Z3Solver()
        x = solver.bitvec("x", 64)
        solver.add(x + 1 == 42)
        result = solver.check()
        assert result.satisfiable
        assert result.model["x"] == 41
    """

    def __init__(self, timeout_ms: int = 10000) -> None:
        self.timeout_ms = timeout_ms
        self._constraints: List[Any] = []
        self._constraint_stack: List[int] = []  # indices for push/pop sync
        self._solver = z3.Solver()
        self._solver.set("timeout", timeout_ms)

    @staticmethod
    def available() -> bool:
        """Always True — z3 is a required dependency."""
        return True

    # -- Variable creation --------------------------------------------------

    @staticmethod
    def bitvec(name: str, bits: int = 64) -> Any:
        """Create a symbolic bit-vector variable."""
        return z3.BitVec(name, bits)

    @staticmethod
    def bitvec_val(value: int, bits: int = 64) -> Any:
        """Create a concrete bit-vector value."""
        return z3.BitVecVal(value, bits)

    # -- Constraint management -----------------------------------------------

    def add(self, *constraints: Any) -> None:
        """Add constraints."""
        self._constraints.extend(constraints)
        self._solver.add(*constraints)

    def reset(self) -> None:
        """Clear all constraints."""
        self._constraints.clear()
        self._constraint_stack.clear()
        self._solver.reset()

    def push(self) -> None:
        """Save the current constraint count for later pop()."""
        self._constraint_stack.append(len(self._constraints))
        self._solver.push()

    def pop(self) -> None:
        """Restore constraints to the last push() point."""
        if self._constraint_stack:
            idx = self._constraint_stack.pop()
            self._constraints = self._constraints[:idx]
        self._solver.pop()

    # -- Solving -------------------------------------------------------------

    def check(self) -> SolverResult:
        """Check satisfiability and extract a model if SAT."""

        try:
            result = self._solver.check()
            if result == z3.sat:
                model = self._solver.model()
                model_dict: Dict[str, Any] = {}
                for decl in model.decls():
                    val = model[decl]
                    try:
                        model_dict[decl.name()] = val.as_long()
                    except (AttributeError, z3.Z3Exception):
                        model_dict[decl.name()] = str(val)
                return SolverResult(satisfiable=True, model=model_dict)
            elif result == z3.unsat:
                return SolverResult(satisfiable=False)
            else:
                return SolverResult(satisfiable=False, error="solver returned unknown")
        except Exception as exc:
            return SolverResult(satisfiable=False, error=str(exc))

    # -- Analysis helpers ---------------------------------------------------

    def is_opaque_predicate(self, condition: Any) -> Optional[bool]:
        """
        Determine if *condition* is an opaque predicate.

        Returns:
        * ``True`` — always true (tautology).
        * ``False`` — always false (contradiction).
        * ``None`` — genuinely conditional.
        """
        s = z3.Solver()
        s.set("timeout", self.timeout_ms)

        # Check if ¬condition is UNSAT → always true
        s.push()
        s.add(z3.Not(condition))
        if s.check() == z3.unsat:
            s.pop()
            return True

        s.pop()

        # Check if condition is UNSAT → always false
        s.push()
        s.add(condition)
        if s.check() == z3.unsat:
            s.pop()
            return False

        s.pop()
        return None  # Genuinely conditional

    @staticmethod
    def simplify(expr: Any) -> Any:
        """Simplify a z3 expression."""
        return z3.simplify(expr)

    def solve_for(self, target_var: Any, constraints: List[Any] | None = None) -> SolverResult:
        """
        Solve for a specific variable given constraints.

        Returns the concrete value of *target_var* (if SAT).
        """
        s = z3.Solver()
        s.set("timeout", self.timeout_ms)
        all_constraints = list(self._constraints) + (constraints or [])
        s.add(*all_constraints)

        if s.check() == z3.sat:
            model = s.model()
            try:
                val = model.eval(target_var, model_completion=True)
                return SolverResult(
                    satisfiable=True,
                    model={str(target_var): val.as_long() if hasattr(val, "as_long") else str(val)},
                )
            except Exception as exc:
                return SolverResult(satisfiable=True, error=f"Eval failed: {exc}")

        return SolverResult(satisfiable=False)
