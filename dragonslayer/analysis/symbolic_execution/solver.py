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
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from ...core.exceptions import (
    VMDragonSlayerError,
    AnalysisError,
    ConfigurationError
)
from ...core.config import VMDragonSlayerConfig

logger = logging.getLogger(__name__)

# Optional Z3 dependency with graceful fallback
try:
    import z3
    HAS_Z3 = True
    logger.info("Z3 solver available")
except ImportError:
    HAS_Z3 = False
    logger.warning("Z3 solver not available - using simplified constraint handling")


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
            "error_message": self.error_message
        }


class SimplifiedSolver:
    """Simplified constraint solver for when Z3 is not available"""
    
    def __init__(self):
        self.variables = {}
        self.constraints = []
    
    def add_variable(self, var: Variable):
        """Add a variable to the solver"""
        self.variables[var.name] = var
    
    def add_constraint(self, constraint: Constraint):
        """Add a constraint to the solver"""
        self.constraints.append(constraint)
    
    def solve(self, timeout: Optional[float] = None) -> SolverModel:
        """Solve constraints using simplified logic"""
        start_time = time.time()
        
        try:
            # Very simplified constraint solving
            assignments = {}
            
            # Assign default values based on variable types
            for var_name, var in self.variables.items():
                if var.type == "bool":
                    assignments[var_name] = True
                elif var.type == "int":
                    if var.domain:
                        assignments[var_name] = var.domain[0]
                    else:
                        assignments[var_name] = 0
                elif var.type == "bitvec":
                    assignments[var_name] = 0
                else:
                    assignments[var_name] = 0
            
            # Check if assignments satisfy basic constraints
            satisfiable = self._check_satisfiability(assignments)
            
            solve_time = time.time() - start_time
            
            return SolverModel(
                result=SolverResult.SAT if satisfiable else SolverResult.UNKNOWN,
                assignments=assignments,
                solve_time=solve_time,
                statistics={
                    "solver": "simplified",
                    "variable_count": len(self.variables),
                    "constraint_count": len(self.constraints)
                }
            )
            
        except Exception as e:
            return SolverModel(
                result=SolverResult.ERROR,
                solve_time=time.time() - start_time,
                error_message=str(e)
            )
    
    def _check_satisfiability(self, assignments: Dict[str, Any]) -> bool:
        """Very basic satisfiability check"""
        # This is a placeholder - real implementation would evaluate constraints
        return True
    
    def reset(self):
        """Reset solver state"""
        self.constraints.clear()
    
    def push(self):
        """Push solver state (no-op for simplified solver)"""
        pass
    
    def pop(self):
        """Pop solver state (no-op for simplified solver)"""
        pass


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
        """Parse constraint expression into Z3 format"""
        # Simplified constraint parsing
        # In a full implementation, this would be a complete expression parser
        
        expr = constraint.expression
        
        # Simple equality constraints
        if "==" in expr:
            left, right = expr.split("==", 1)
            left = left.strip()
            right = right.strip()
            
            left_var = self.z3_variables.get(left)
            if left_var is not None:
                try:
                    right_val = int(right)
                    return left_var == right_val
                except ValueError:
                    right_var = self.z3_variables.get(right)
                    if right_var is not None:
                        return left_var == right_var
        
        # Simple inequality constraints
        elif "!=" in expr:
            left, right = expr.split("!=", 1)
            left = left.strip()
            right = right.strip()
            
            left_var = self.z3_variables.get(left)
            if left_var is not None:
                try:
                    right_val = int(right)
                    return left_var != right_val
                except ValueError:
                    right_var = self.z3_variables.get(right)
                    if right_var is not None:
                        return left_var != right_var
        
        # Greater than
        elif ">" in expr:
            left, right = expr.split(">", 1)
            left = left.strip()
            right = right.strip()
            
            left_var = self.z3_variables.get(left)
            if left_var is not None:
                try:
                    right_val = int(right)
                    return left_var > right_val
                except ValueError:
                    pass
        
        # Boolean constraints
        elif constraint.type == ConstraintType.BOOLEAN:
            var_name = list(constraint.variables)[0] if constraint.variables else None
            if var_name and var_name in self.z3_variables:
                var = self.z3_variables[var_name]
                if "true" in expr.lower():
                    return var == True
                elif "false" in expr.lower():
                    return var == False
        
        logger.debug("Could not parse constraint: %s", expr)
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
                        "z3_statistics": self.solver.statistics()
                    }
                )
            
            elif result == z3.unsat:
                return SolverModel(
                    result=SolverResult.UNSAT,
                    solve_time=solve_time,
                    statistics={
                        "solver": "z3",
                        "variable_count": len(self.variables),
                        "constraint_count": len(self.constraints)
                    }
                )
            
            else:  # unknown
                return SolverModel(
                    result=SolverResult.UNKNOWN,
                    solve_time=solve_time,
                    statistics={
                        "solver": "z3",
                        "reason": str(result)
                    }
                )
                
        except Exception as e:
            return SolverModel(
                result=SolverResult.ERROR,
                solve_time=time.time() - start_time,
                error_message=str(e)
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
    
    def __init__(self, config: Optional[VMDragonSlayerConfig] = None, use_z3: bool = True):
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
                logger.info("Using simplified constraint solver")
        else:
            self.solver = SimplifiedSolver()
            logger.info("Using simplified constraint solver")
        
        self.variables = {}
        self.solve_count = 0
        self.total_solve_time = 0.0
    
    def add_variable(self, name: str, var_type: str = "bitvec", 
                    size: int = 32, domain: Optional[Tuple[int, int]] = None) -> Variable:
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
        
        var = Variable(
            name=name,
            type=var_type,
            size=size,
            domain=domain
        )
        
        self.variables[name] = var
        self.solver.add_variable(var)
        
        logger.debug("Added variable: %s (%s)", name, var_type)
        return var
    
    def add_constraint(self, expression: str, constraint_type: ConstraintType,
                      variables: Optional[Set[str]] = None, 
                      confidence: float = 1.0) -> Constraint:
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
            confidence=confidence
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
        
        logger.debug("Solve #%d completed in %.3fs: %s", 
                    self.solve_count, result.solve_time, result.result.value)
        
        return result
    
    def check_satisfiability(self, constraints: List[Constraint], 
                           timeout: Optional[float] = None) -> bool:
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
            "solver_type": "z3" if self.use_z3 else "simplified",
            "variable_count": len(self.variables),
            "solve_count": self.solve_count,
            "total_solve_time": self.total_solve_time,
            "avg_solve_time": self.total_solve_time / max(1, self.solve_count),
            "z3_available": HAS_Z3
        }
