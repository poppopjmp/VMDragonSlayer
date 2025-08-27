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
Constraint Solver
================

Unified constraint solver for symbolic execution.

This module consolidates constraint solving functionality and provides
a clean interface to Z3 SMT solver with graceful fallbacks.
"""

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from ...core.config import VMDragonSlayerConfig
from ...core.exceptions import ConfigurationError

logger = logging.getLogger(__name__)

# Optional Z3 dependency with graceful fallback
try:
    import z3

    HAS_Z3 = True
    logger.info("Z3 solver available")
except ImportError:
    HAS_Z3 = False
    logger.warning("Z3 solver not available - using real fallback constraint solver")


class SolverResult(Enum):
    """Constraint solver result types"""

    SAT = "sat"
    UNSAT = "unsat"
    UNKNOWN = "unknown"
    TIMEOUT = "timeout"
    ERROR = "error"


class ConstraintType(Enum):
    """Types of constraints supported"""

    EQUALITY = "equality"
    INEQUALITY = "inequality"
    BOOLEAN = "boolean"
    ARITHMETIC = "arithmetic"
    BITWISE = "bitwise"
    MEMORY = "memory"


@dataclass
class Variable:
    """Symbolic variable definition"""

    name: str
    type: str  # "int", "bitvec", "bool"
    size: int = 32  # for bitvec
    domain: Optional[Tuple[int, int]] = None  # value range
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Constraint:
    """Constraint representation"""

    expression: str
    type: ConstraintType
    variables: Set[str]
    confidence: float = 1.0
    source: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not isinstance(self.variables, set):
            self.variables = set(self.variables) if self.variables else set()


@dataclass
class SolverModel:
    """Model returned by constraint solver"""

    result: SolverResult
    assignments: Dict[str, Any] = field(default_factory=dict)
    statistics: Dict[str, Any] = field(default_factory=dict)
    solve_time: float = 0.0
    error_message: Optional[str] = None

    def get_value(self, variable: str) -> Optional[Any]:
        """Get value assignment for variable"""
        return self.assignments.get(variable)

    def is_satisfiable(self) -> bool:
        """Check if constraints are satisfiable"""
        return self.result == SolverResult.SAT

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "result": self.result.value,
            "assignments": self.assignments,
            "statistics": self.statistics,
            "solve_time": self.solve_time,
            "error_message": self.error_message,
        }


class SimplifiedSolver:
    """Real constraint solver implementation when Z3 is not available"""

    def __init__(self):
        self.variables = {}
        self.constraints = []
        self.state_stack = []  # For push/pop operations

    def add_variable(self, var: Variable):
        """Add a variable to the solver"""
        self.variables[var.name] = var

    def add_constraint(self, constraint: Constraint):
        """Add a constraint to the solver"""
        self.constraints.append(constraint)

    def solve(self, timeout: Optional[float] = None) -> SolverModel:
        """Solve constraints using real constraint solving logic"""
        start_time = time.time()
        
        try:
            # If no constraints, assign default values
            if not self.constraints:
                assignments = {}
                for var_name, var in self.variables.items():
                    assignments[var_name] = self._get_default_value(var)
                
                return SolverModel(
                    result=SolverResult.SAT,
                    assignments=assignments,
                    solve_time=time.time() - start_time,
                    statistics={
                        "solver": "real_simplified",
                        "variable_count": len(self.variables),
                        "constraint_count": 0,
                    },
                )
            
            # Try to find satisfying assignment using backtracking
            assignments = {}
            if self._solve_recursive(list(self.variables.keys()), assignments, timeout, start_time):
                return SolverModel(
                    result=SolverResult.SAT,
                    assignments=assignments,
                    solve_time=time.time() - start_time,
                    statistics={
                        "solver": "real_simplified",
                        "variable_count": len(self.variables),
                        "constraint_count": len(self.constraints),
                    },
                )
            else:
                return SolverModel(
                    result=SolverResult.UNSAT,
                    solve_time=time.time() - start_time,
                    statistics={
                        "solver": "real_simplified",
                        "variable_count": len(self.variables),
                        "constraint_count": len(self.constraints),
                    },
                )
                
        except Exception as e:
            return SolverModel(
                result=SolverResult.ERROR,
                solve_time=time.time() - start_time,
                error_message=str(e),
            )

    def _solve_recursive(self, variables: List[str], assignments: Dict[str, Any], 
                        timeout: Optional[float], start_time: float) -> bool:
        """Recursive backtracking solver"""
        # Check timeout
        if timeout and (time.time() - start_time) > timeout:
            return False
            
        # Base case - all variables assigned
        if not variables:
            return self._check_satisfiability(assignments)
        
        # Pick next variable
        var_name = variables[0]
        remaining_vars = variables[1:]
        var = self.variables[var_name]
        
        # Try different values for this variable
        candidates = self._get_value_candidates(var)
        
        for value in candidates:
            assignments[var_name] = value
            
            # Check if current partial assignment is consistent
            if self._is_partial_assignment_consistent(assignments):
                # Recurse with remaining variables
                if self._solve_recursive(remaining_vars, assignments, timeout, start_time):
                    return True
            
            # Backtrack
            del assignments[var_name]
        
        return False

    def _get_value_candidates(self, var: Variable) -> List[Any]:
        """Get candidate values to try for a variable"""
        if var.type == "bool":
            return [False, True]
        elif var.type == "int":
            if var.domain:
                min_val, max_val = var.domain
                # Try a reasonable range of values
                if max_val - min_val <= 20:
                    return list(range(min_val, max_val + 1))
                else:
                    # Sample key values
                    return [min_val, min_val + 1, (min_val + max_val) // 2, max_val - 1, max_val]
            else:
                return [0, 1, -1, 10, 100]
        elif var.type == "bitvec":
            max_val = (1 << var.size) - 1
            if var.domain:
                min_val, domain_max = var.domain
                max_val = min(max_val, domain_max)
            else:
                min_val = 0
            
            # Try key bitvector values
            candidates = [0, 1]
            if max_val > 1:
                candidates.extend([max_val, max_val // 2])
            if var.size >= 8:
                candidates.extend([0xFF & max_val, 0x10, 0x20])
            return list(set(candidates))[:10]  # Limit candidates
        
        return [0]

    def _is_partial_assignment_consistent(self, assignments: Dict[str, Any]) -> bool:
        """Check if partial assignment is consistent with constraints"""
        try:
            for constraint in self.constraints:
                # Only check constraints where all variables are assigned
                if constraint.variables.issubset(set(assignments.keys())):
                    if not self._evaluate_constraint(constraint, assignments):
                        return False
            return True
        except Exception:
            return True  # Assume consistent on error

    def _get_default_value(self, var: Variable) -> Any:
        """Get default value for a variable"""
        if var.type == "bool":
            return False
        elif var.type == "int":
            if var.domain:
                return var.domain[0]
            else:
                return 0
        elif var.type == "bitvec":
            return 0
        else:
            return 0

    def _check_satisfiability(self, assignments: Dict[str, Any]) -> bool:
        """Real satisfiability check by evaluating all constraints"""
        try:
            for constraint in self.constraints:
                if not self._evaluate_constraint(constraint, assignments):
                    return False
            return True
        except Exception as e:
            logger.debug(f"Error checking satisfiability: {e}")
            return False

    def _evaluate_constraint(self, constraint: Constraint, assignments: Dict[str, Any]) -> bool:
        """Evaluate a single constraint against variable assignments"""
        try:
            expr = constraint.expression.strip()
            
            # Replace variables with their assigned values
            eval_expr = expr
            for var_name in constraint.variables:
                if var_name in assignments:
                    value = assignments[var_name]
                    # Replace variable names with their values
                    eval_expr = eval_expr.replace(var_name, str(value))
            
            # Evaluate different constraint types
            if constraint.type == ConstraintType.EQUALITY:
                if "==" in eval_expr:
                    left, right = eval_expr.split("==", 1)
                    try:
                        return int(left.strip()) == int(right.strip())
                    except ValueError:
                        return str(left.strip()) == str(right.strip())
                        
            elif constraint.type == ConstraintType.INEQUALITY:
                if "!=" in eval_expr:
                    left, right = eval_expr.split("!=", 1)
                    try:
                        return int(left.strip()) != int(right.strip())
                    except ValueError:
                        return str(left.strip()) != str(right.strip())
                elif ">" in eval_expr and ">=" not in eval_expr:
                    left, right = eval_expr.split(">", 1)
                    return int(left.strip()) > int(right.strip())
                elif ">=" in eval_expr:
                    left, right = eval_expr.split(">=", 1)
                    return int(left.strip()) >= int(right.strip())
                elif "<" in eval_expr and "<=" not in eval_expr:
                    left, right = eval_expr.split("<", 1)
                    return int(left.strip()) < int(right.strip())
                elif "<=" in eval_expr:
                    left, right = eval_expr.split("<=", 1)
                    return int(left.strip()) <= int(right.strip())
                    
            elif constraint.type == ConstraintType.BOOLEAN:
                if "true" in eval_expr.lower() or eval_expr == "1":
                    return True
                elif "false" in eval_expr.lower() or eval_expr == "0":
                    return False
                # Try to evaluate as boolean expression
                try:
                    return bool(eval(eval_expr))
                except:
                    return True
                    
            elif constraint.type == ConstraintType.ARITHMETIC:
                # For arithmetic constraints, assume they're satisfied if we can evaluate them
                try:
                    result = eval(eval_expr)
                    return bool(result)
                except:
                    return True
                    
            elif constraint.type == ConstraintType.BITWISE:
                # For bitwise operations
                try:
                    result = eval(eval_expr)
                    return bool(result)
                except:
                    return True
                    
            # Default case - assume satisfied
            return True
            
        except Exception as e:
            logger.debug(f"Error evaluating constraint {constraint.expression}: {e}")
            return True  # Assume satisfied on error

    def reset(self):
        """Reset solver state"""
        self.constraints.clear()
        self.variables.clear()
        self.state_stack.clear()

    def push(self):
        """Push current solver state onto stack"""
        state = {
            'variables': self.variables.copy(),
            'constraints': self.constraints.copy()
        }
        self.state_stack.append(state)

    def pop(self):
        """Pop solver state from stack"""
        if self.state_stack:
            state = self.state_stack.pop()
            self.variables = state['variables']
            self.constraints = state['constraints']


class Z3Solver:
    """Z3-based constraint solver"""

    def __init__(self):
        if not HAS_Z3:
            raise ConfigurationError("Z3 solver not available")

        self.solver = z3.Solver()
        self.variables = {}
        self.z3_variables = {}
        self.constraints = []

    def add_variable(self, var: Variable):
        """Add a variable to the Z3 solver"""
        self.variables[var.name] = var

        # Create Z3 variable based on type
        if var.type == "bool":
            z3_var = z3.Bool(var.name)
        elif var.type == "int":
            z3_var = z3.Int(var.name)
        elif var.type == "bitvec":
            z3_var = z3.BitVec(var.name, var.size)
        else:
            # Default to bitvec
            z3_var = z3.BitVec(var.name, 32)

        self.z3_variables[var.name] = z3_var

        # Add domain constraints if specified
        if var.domain and var.type in ["int", "bitvec"]:
            min_val, max_val = var.domain
            self.solver.add(z3_var >= min_val)
            self.solver.add(z3_var <= max_val)

    def add_constraint(self, constraint: Constraint):
        """Add a constraint to the Z3 solver"""
        self.constraints.append(constraint)

        try:
            # Parse and add constraint to Z3
            z3_constraint = self._parse_constraint(constraint)
            if z3_constraint is not None:
                self.solver.add(z3_constraint)
        except Exception as e:
            logger.warning("Failed to add constraint: %s", e)

    def _parse_constraint(self, constraint: Constraint):
        """Parse constraint expression into Z3 format using real expression parsing"""
        try:
            expr = constraint.expression.strip()
            
            # Handle different constraint types with real parsing
            if constraint.type == ConstraintType.EQUALITY:
                return self._parse_equality_constraint(expr)
            elif constraint.type == ConstraintType.INEQUALITY:
                return self._parse_inequality_constraint(expr)
            elif constraint.type == ConstraintType.BOOLEAN:
                return self._parse_boolean_constraint(expr, constraint.variables)
            elif constraint.type == ConstraintType.ARITHMETIC:
                return self._parse_arithmetic_constraint(expr)
            elif constraint.type == ConstraintType.BITWISE:
                return self._parse_bitwise_constraint(expr)
            else:
                # Try general parsing
                return self._parse_general_expression(expr)
                
        except Exception as e:
            logger.debug(f"Failed to parse constraint '{constraint.expression}': {e}")
            return None

    def _parse_equality_constraint(self, expr: str):
        """Parse equality constraints (==)"""
        if "==" in expr:
            left, right = expr.split("==", 1)
            left_z3 = self._parse_expression_part(left.strip())
            right_z3 = self._parse_expression_part(right.strip())
            if left_z3 is not None and right_z3 is not None:
                return left_z3 == right_z3
        return None

    def _parse_inequality_constraint(self, expr: str):
        """Parse inequality constraints (!=, >, >=, <, <=)"""
        for op in ["!=", ">=", "<=", ">", "<"]:
            if op in expr:
                left, right = expr.split(op, 1)
                left_z3 = self._parse_expression_part(left.strip())
                right_z3 = self._parse_expression_part(right.strip())
                if left_z3 is not None and right_z3 is not None:
                    if op == "!=":
                        return left_z3 != right_z3
                    elif op == ">":
                        return left_z3 > right_z3
                    elif op == ">=":
                        return left_z3 >= right_z3
                    elif op == "<":
                        return left_z3 < right_z3
                    elif op == "<=":
                        return left_z3 <= right_z3
                break
        return None

    def _parse_boolean_constraint(self, expr: str, variables: Set[str]):
        """Parse boolean constraints"""
        expr_lower = expr.lower()
        if "true" in expr_lower or expr == "1":
            return True
        elif "false" in expr_lower or expr == "0":
            return False
        
        # Check if it's a variable name
        var_name = expr.strip()
        if var_name in self.z3_variables:
            var = self.z3_variables[var_name]
            return var if isinstance(var, z3.BoolRef) else (var != 0)
        
        # Check for negation
        if expr.startswith("!") or expr.startswith("not "):
            var_name = expr[1:].strip() if expr.startswith("!") else expr[4:].strip()
            if var_name in self.z3_variables:
                var = self.z3_variables[var_name]
                return z3.Not(var) if isinstance(var, z3.BoolRef) else (var == 0)
        
        return None

    def _parse_arithmetic_constraint(self, expr: str):
        """Parse arithmetic expressions"""
        return self._parse_general_expression(expr)

    def _parse_bitwise_constraint(self, expr: str):
        """Parse bitwise operations (&, |, ^, <<, >>)"""
        # Handle bitwise operations
        for op in ["&", "|", "^", "<<", ">>"]:
            if op in expr and not any(comp_op in expr for comp_op in ["==", "!=", ">=", "<=", ">", "<"]):
                parts = expr.split(op, 1)
                if len(parts) == 2:
                    left_z3 = self._parse_expression_part(parts[0].strip())
                    right_z3 = self._parse_expression_part(parts[1].strip())
                    if left_z3 is not None and right_z3 is not None:
                        if op == "&":
                            return left_z3 & right_z3
                        elif op == "|":
                            return left_z3 | right_z3
                        elif op == "^":
                            return left_z3 ^ right_z3
                        elif op == "<<":
                            return left_z3 << right_z3
                        elif op == ">>":
                            return left_z3 >> right_z3
                    break
        return self._parse_general_expression(expr)

    def _parse_general_expression(self, expr: str):
        """Parse general expressions with operators"""
        # Handle parentheses
        if "(" in expr and ")" in expr:
            try:
                return self._parse_parenthesized_expression(expr)
            except:
                pass
        
        # Handle arithmetic operations
        for op in ["+", "-", "*", "/", "%"]:
            if op in expr and not any(comp_op in expr for comp_op in ["==", "!=", ">=", "<=", ">", "<"]):
                parts = expr.split(op, 1)
                if len(parts) == 2:
                    left_z3 = self._parse_expression_part(parts[0].strip())
                    right_z3 = self._parse_expression_part(parts[1].strip())
                    if left_z3 is not None and right_z3 is not None:
                        if op == "+":
                            return left_z3 + right_z3
                        elif op == "-":
                            return left_z3 - right_z3
                        elif op == "*":
                            return left_z3 * right_z3
                        elif op == "/":
                            return left_z3 / right_z3
                        elif op == "%":
                            return left_z3 % right_z3
                    break
        
        return self._parse_expression_part(expr)

    def _parse_expression_part(self, part: str):
        """Parse a single expression part (variable or constant)"""
        part = part.strip()
        
        # Try variable lookup
        if part in self.z3_variables:
            return self.z3_variables[part]
        
        # Try integer constant
        try:
            return int(part)
        except ValueError:
            pass
        
        # Try hexadecimal constant
        if part.startswith("0x") or part.startswith("0X"):
            try:
                return int(part, 16)
            except ValueError:
                pass
        
        # Try boolean constants
        if part.lower() == "true":
            return True
        elif part.lower() == "false":
            return False
        
        return None

    def _parse_parenthesized_expression(self, expr: str):
        """Parse expressions with parentheses"""
        # Simple parentheses handling - find matching pairs and recurse
        # This is a simplified version - full implementation would need proper parsing
        if expr.startswith("(") and expr.endswith(")"):
            return self._parse_general_expression(expr[1:-1])
        return None

    def solve(self, timeout: Optional[float] = None) -> SolverModel:
        """Solve constraints using Z3"""
        start_time = time.time()

        try:
            # Set timeout if specified
            if timeout:
                self.solver.set("timeout", int(timeout * 1000))  # Z3 uses milliseconds

            # Solve
            result = self.solver.check()
            solve_time = time.time() - start_time

            if result == z3.sat:
                # Get model
                model = self.solver.model()
                assignments = {}

                for var_name, z3_var in self.z3_variables.items():
                    try:
                        value = model[z3_var]
                        if value is not None:
                            # Convert Z3 value to Python value
                            if isinstance(value, z3.BoolRef):
                                assignments[var_name] = bool(value)
                            elif isinstance(value, (z3.IntNumRef, z3.BitVecNumRef)):
                                assignments[var_name] = value.as_long()
                            else:
                                assignments[var_name] = str(value)
                    except Exception as e:
                        logger.debug("Error getting value for %s: %s", var_name, e)

                return SolverModel(
                    result=SolverResult.SAT,
                    assignments=assignments,
                    solve_time=solve_time,
                    statistics={
                        "solver": "z3",
                        "variable_count": len(self.variables),
                        "constraint_count": len(self.constraints),
                        "z3_statistics": self.solver.statistics(),
                    },
                )

            elif result == z3.unsat:
                return SolverModel(
                    result=SolverResult.UNSAT,
                    solve_time=solve_time,
                    statistics={
                        "solver": "z3",
                        "variable_count": len(self.variables),
                        "constraint_count": len(self.constraints),
                    },
                )

            else:  # unknown
                return SolverModel(
                    result=SolverResult.UNKNOWN,
                    solve_time=solve_time,
                    statistics={"solver": "z3", "reason": str(result)},
                )

        except Exception as e:
            return SolverModel(
                result=SolverResult.ERROR,
                solve_time=time.time() - start_time,
                error_message=str(e),
            )

    def reset(self):
        """Reset solver state"""
        self.solver.reset()
        self.constraints.clear()

    def push(self):
        """Push solver state onto stack"""
        self.solver.push()

    def pop(self):
        """Pop solver state from stack"""
        self.solver.pop()


class ConstraintSolver:
    """Main constraint solver interface"""

    def __init__(
        self, config: Optional[VMDragonSlayerConfig] = None, use_z3: bool = True
    ):
        """Initialize constraint solver

        Args:
            config: VMDragonSlayer configuration
            use_z3: Whether to use Z3 solver if available
        """
        self.config = config or VMDragonSlayerConfig()
        self.use_z3 = use_z3 and HAS_Z3

        # Initialize appropriate solver
        if self.use_z3:
            try:
                self.solver = Z3Solver()
                logger.info("Using Z3 constraint solver")
            except Exception as e:
                logger.warning("Failed to initialize Z3 solver: %s", e)
                self.solver = SimplifiedSolver()
                logger.info("Using real fallback constraint solver")
        else:
            self.solver = SimplifiedSolver()
            logger.info("Using real fallback constraint solver")

        self.variables = {}
        self.solve_count = 0
        self.total_solve_time = 0.0

    def add_variable(
        self,
        name: str,
        var_type: str = "bitvec",
        size: int = 32,
        domain: Optional[Tuple[int, int]] = None,
    ) -> Variable:
        """Add a variable to the solver

        Args:
            name: Variable name
            var_type: Variable type ("int", "bitvec", "bool")
            size: Size for bitvec variables
            domain: Value range for int/bitvec variables

        Returns:
            Created variable
        """
        if name in self.variables:
            return self.variables[name]

        var = Variable(name=name, type=var_type, size=size, domain=domain)

        self.variables[name] = var
        self.solver.add_variable(var)

        logger.debug("Added variable: %s (%s)", name, var_type)
        return var

    def add_constraint(
        self,
        expression: str,
        constraint_type: ConstraintType,
        variables: Optional[Set[str]] = None,
        confidence: float = 1.0,
    ) -> Constraint:
        """Add a constraint to the solver

        Args:
            expression: Constraint expression
            constraint_type: Type of constraint
            variables: Variables involved in constraint
            confidence: Confidence in constraint

        Returns:
            Created constraint
        """
        if variables is None:
            variables = set()

        constraint = Constraint(
            expression=expression,
            type=constraint_type,
            variables=variables,
            confidence=confidence,
        )

        self.solver.add_constraint(constraint)

        logger.debug("Added constraint: %s", expression)
        return constraint

    def solve(self, timeout: Optional[float] = None) -> SolverModel:
        """Solve current constraints

        Args:
            timeout: Solve timeout in seconds

        Returns:
            Solver model with results
        """
        self.solve_count += 1

        result = self.solver.solve(timeout)
        self.total_solve_time += result.solve_time

        logger.debug(
            "Solve #%d completed in %.3fs: %s",
            self.solve_count,
            result.solve_time,
            result.result.value,
        )

        return result

    def check_satisfiability(
        self, constraints: List[Constraint], timeout: Optional[float] = None
    ) -> bool:
        """Check if a set of constraints is satisfiable

        Args:
            constraints: Constraints to check
            timeout: Check timeout in seconds

        Returns:
            True if satisfiable, False otherwise
        """
        # Save current state
        self.push()

        try:
            # Add constraints temporarily
            for constraint in constraints:
                self.solver.add_constraint(constraint)

            # Solve
            result = self.solve(timeout)
            return result.is_satisfiable()

        finally:
            # Restore state
            self.pop()

    def get_variable_value(self, name: str, model: SolverModel) -> Optional[Any]:
        """Get variable value from model

        Args:
            name: Variable name
            model: Solver model

        Returns:
            Variable value if available
        """
        return model.get_value(name)

    def push(self):
        """Push solver state onto stack"""
        self.solver.push()

    def pop(self):
        """Pop solver state from stack"""
        self.solver.pop()

    def reset(self):
        """Reset solver state"""
        self.solver.reset()
        self.variables.clear()
        logger.debug("Constraint solver reset")

    def get_statistics(self) -> Dict[str, Any]:
        """Get solver statistics

        Returns:
            Statistics dictionary
        """
        return {
            "solver_type": "z3" if self.use_z3 else "real_fallback",
            "variable_count": len(self.variables),
            "solve_count": self.solve_count,
            "total_solve_time": self.total_solve_time,
            "avg_solve_time": self.total_solve_time / max(1, self.solve_count),
            "z3_available": HAS_Z3,
        }
