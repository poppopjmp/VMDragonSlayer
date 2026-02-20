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

# B57: Import resource-limit exceptions for raising on solver exhaustion.
try:
    from dragonslayer.core.exceptions import ResourceLimitError, AnalysisTimeoutError
except ImportError:  # pragma: no cover — standalone usage
    class ResourceLimitError(RuntimeError):  # type: ignore[no-redef]
        pass
    class AnalysisTimeoutError(RuntimeError):  # type: ignore[no-redef]
        pass


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

    def __init__(self, timeout_ms: int = 10000, memory_limit_mb: int = 0) -> None:
        self.timeout_ms = timeout_ms
        self.memory_limit_mb = memory_limit_mb
        self._constraints: List[Any] = []

        # B53: Apply global z3 memory limit if requested
        if memory_limit_mb > 0:
            try:
                z3.set_param("memory_max_size", memory_limit_mb)
            except Exception:
                logger.debug("Failed to set z3 memory limit to %d MB", memory_limit_mb)
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

    # -- B59: Named constraints & unsat core --------------------------------

    def assert_and_track(self, constraint: Any, name: str) -> None:
        """Add a *named* constraint for unsat-core extraction.

        Unlike :meth:`add`, tracked constraints participate in
        :meth:`unsat_core` so the caller can identify which subset of
        named constraints is responsible for unsatisfiability.
        """
        label = z3.Bool(name)
        self._constraints.append(constraint)
        self._solver.assert_and_track(constraint, label)

    def unsat_core(self) -> List[str]:
        """Return the names of constraints in the UNSAT core.

        Only meaningful after :meth:`check` returns UNSAT and the
        conflicting constraints were added via :meth:`assert_and_track`.
        """
        try:
            core = self._solver.unsat_core()
            return [str(c) for c in core]
        except Exception:
            return []

    # -- B59: Incremental feasibility check ---------------------------------

    def check_feasibility(
        self, *extra_constraints: Any
    ) -> bool:
        """Check whether *extra_constraints* are feasible under the current
        constraint set **without** permanently adding them.

        Uses push/pop on the persistent solver, avoiding the overhead of
        creating a fresh ``z3.Solver`` instance.

        Returns ``True`` if SAT, ``False`` otherwise (UNSAT or unknown).
        """
        self._solver.push()
        try:
            if extra_constraints:
                self._solver.add(*extra_constraints)
            result = self._solver.check()
            return result == z3.sat
        except Exception:
            return False
        finally:
            self._solver.pop()

    # -- Solving -------------------------------------------------------------

    def check(self, *, raise_on_resource_limit: bool = False) -> SolverResult:
        """Check satisfiability and extract a model if SAT.

        Parameters
        ----------
        raise_on_resource_limit : bool
            When *True*, a solver ``unknown`` result (typically caused by
            timeout or memory exhaustion) raises :class:`ResourceLimitError`
            instead of returning a non-satisfiable :class:`SolverResult`.
        """

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
                # B57: ``unknown`` — typically timeout or memory exhaustion.
                reason = str(self._solver.reason_unknown())
                if raise_on_resource_limit:
                    if "timeout" in reason.lower():
                        raise AnalysisTimeoutError(
                            f"Z3 solver timed out: {reason}",
                            error_code="SOLVER_TIMEOUT",
                            details={"reason": reason, "timeout_ms": self.timeout_ms},
                        )
                    raise ResourceLimitError(
                        f"Z3 solver returned unknown: {reason}",
                        error_code="SOLVER_RESOURCE_LIMIT",
                        details={"reason": reason, "memory_limit_mb": self.memory_limit_mb},
                    )
                return SolverResult(satisfiable=False, error=f"solver returned unknown: {reason}")
        except (ResourceLimitError, AnalysisTimeoutError):
            raise  # re-raise our own exceptions
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

    def is_opaque_predicate_with_context(
        self,
        condition: Any,
        path_constraints: Any,
    ) -> Optional[bool]:
        """Determine if *condition* is opaque *under* accumulated path
        constraints.

        Unlike :meth:`is_opaque_predicate` which checks for universal
        tautology/contradiction, this method adds the *path_constraints*
        (a list of z3 expressions or z3-compatible objects) to the solver
        before testing.  A branch that is genuinely conditional in
        isolation may be always-true given the path context.

        Returns ``True``, ``False``, or ``None`` (genuinely conditional
        even under constraints).
        """
        s = z3.Solver()
        s.set("timeout", self.timeout_ms)

        # Add path constraints.
        if path_constraints:
            for c in path_constraints:
                try:
                    s.add(c)
                except Exception:
                    continue

        # Check if ¬condition is UNSAT under path → always true in context.
        s.push()
        s.add(z3.Not(condition))
        if s.check() == z3.unsat:
            s.pop()
            return True

        s.pop()

        # Check if condition is UNSAT under path → always false in context.
        s.push()
        s.add(condition)
        if s.check() == z3.unsat:
            s.pop()
            return False

        s.pop()
        return None

    @staticmethod
    def simplify(expr: Any) -> Any:
        """Simplify a z3 expression."""
        return z3.simplify(expr)

    def enumerate_values(
        self,
        expr: Any,
        constraints: List[Any] | None = None,
        max_values: int = 256,
    ) -> List[int]:
        """Enumerate all distinct concrete values of *expr* under constraints.

        Used for indirect dispatch resolution: given a symbolic jump
        target expression, enumerate all concrete addresses the jump may
        resolve to (up to *max_values*).

        Returns a sorted list of concrete ``int`` values.
        """
        s = z3.Solver()
        s.set("timeout", self.timeout_ms)

        all_constraints = list(self._constraints) + (constraints or [])
        if all_constraints:
            s.add(*all_constraints)

        values: List[int] = []
        bits = expr.sort().size() if hasattr(expr, "sort") else 64

        for _ in range(max_values):
            if s.check() != z3.sat:
                break
            model = s.model()
            val = model.eval(expr, model_completion=True)
            try:
                concrete = val.as_long()
            except (AttributeError, z3.Z3Exception):
                break
            values.append(concrete)
            # Exclude this value and continue
            s.add(expr != z3.BitVecVal(concrete, bits))

        return sorted(values)

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
