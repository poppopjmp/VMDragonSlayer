"""
Symbolic Executor
================

Unified symbolic execution engine for VM handler analysis.

This module consolidates symbolic execution functionality from multiple
implementations into a single, production-ready executor.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
import weakref

from ...core.exceptions import (
    VMDragonSlayerError,
    AnalysisError,
    ConfigurationError
)
from ...core.config import VMDragonSlayerConfig

logger = logging.getLogger(__name__)


class ConstraintType(Enum):
    """Types of symbolic constraints"""
    EQUALITY = "equality"
    INEQUALITY = "inequality"
    BOOLEAN = "boolean"
    ARITHMETIC = "arithmetic"
    BITWISE = "bitwise"
    MEMORY = "memory"


class PathPriority(Enum):
    """Path exploration priority levels"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


class ExecutionState(Enum):
    """Symbolic execution state"""
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class SymbolicConstraint:
    """Symbolic constraint representation"""
    type: ConstraintType
    expression: str
    variables: Set[str]
    confidence: float = 1.0
    source_instruction: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not isinstance(self.variables, set):
            self.variables = set(self.variables) if self.variables else set()


@dataclass
class SymbolicValue:
    """Symbolic value with constraints and concrete information"""
    name: str
    constraints: List[SymbolicConstraint] = field(default_factory=list)
    concrete_value: Optional[int] = None
    size: int = 32  # in bits
    is_input: bool = False
    creation_time: float = field(default_factory=time.time)
    
    def __post_init__(self):
        if not isinstance(self.constraints, list):
            self.constraints = list(self.constraints) if self.constraints else []
    
    def add_constraint(self, constraint: SymbolicConstraint):
        """Add a constraint to this symbolic value"""
        self.constraints.append(constraint)
    
    def is_concrete(self) -> bool:
        """Check if this value has a concrete value"""
        return self.concrete_value is not None
    
    def get_possible_values(self) -> List[int]:
        """Get possible concrete values based on constraints"""
        # Simplified implementation - would use solver in production
        if self.concrete_value is not None:
            return [self.concrete_value]
        
        # Default range based on size
        max_val = (1 << self.size) - 1
        return list(range(0, min(max_val, 256)))  # Limited for performance


@dataclass
class ExecutionContext:
    """Symbolic execution context state"""
    pc: int  # Program counter
    registers: Dict[str, SymbolicValue] = field(default_factory=dict)
    memory: Dict[int, SymbolicValue] = field(default_factory=dict)
    constraints: List[SymbolicConstraint] = field(default_factory=list)
    path_id: str = ""
    depth: int = 0
    priority: PathPriority = PathPriority.MEDIUM
    parent_context: Optional['ExecutionContext'] = None
    creation_time: float = field(default_factory=time.time)
    vm_handler_calls: int = 0
    loop_iterations: Dict[int, int] = field(default_factory=dict)
    
    def __post_init__(self):
        if not isinstance(self.constraints, list):
            self.constraints = []
        if not self.path_id:
            self.path_id = f"path_{id(self)}"
    
    def clone(self) -> 'ExecutionContext':
        """Create a deep copy of the execution context"""
        new_context = ExecutionContext(
            pc=self.pc,
            registers={k: v for k, v in self.registers.items()},
            memory={k: v for k, v in self.memory.items()},
            constraints=self.constraints.copy(),
            path_id=f"{self.path_id}_clone_{int(time.time() * 1000) % 10000}",
            depth=self.depth + 1,
            priority=self.priority,
            parent_context=self,
            vm_handler_calls=self.vm_handler_calls,
            loop_iterations=self.loop_iterations.copy()
        )
        return new_context
    
    def add_constraint(self, constraint: SymbolicConstraint):
        """Add a constraint to the execution context"""
        self.constraints.append(constraint)
    
    def get_symbolic_value(self, name: str) -> Optional[SymbolicValue]:
        """Get symbolic value by name from registers or memory"""
        if name in self.registers:
            return self.registers[name]
        
        # Try to find in memory (simplified lookup)
        for addr, value in self.memory.items():
            if value.name == name:
                return value
        
        return None
    
    def set_register(self, reg_name: str, value: SymbolicValue):
        """Set register to symbolic value"""
        self.registers[reg_name] = value
    
    def set_memory(self, address: int, value: SymbolicValue):
        """Set memory location to symbolic value"""
        self.memory[address] = value


@dataclass
class ExecutionResult:
    """Result of symbolic execution"""
    contexts: List[ExecutionContext]
    total_paths: int
    completed_paths: int
    error_paths: int
    timeout_paths: int
    execution_time: float
    constraints_generated: int
    coverage_info: Dict[str, Any] = field(default_factory=dict)
    statistics: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "total_paths": self.total_paths,
            "completed_paths": self.completed_paths,
            "error_paths": self.error_paths,
            "timeout_paths": self.timeout_paths,
            "execution_time": self.execution_time,
            "constraints_generated": self.constraints_generated,
            "coverage_info": self.coverage_info,
            "statistics": self.statistics
        }


class PathPrioritizer:
    """Path prioritization for symbolic execution"""
    
    def __init__(self):
        self.vm_patterns = {
            'dispatcher_access': 2.5,
            'handler_entry': 2.0,
            'vm_register_access': 1.8,
            'bytecode_fetch': 2.2,
            'handler_exit': 1.5,
            'opcode_decode': 2.3,
            'stack_manipulation': 1.9,
            'control_flow_change': 2.1,
            'vm_state_transition': 2.4,
            'anti_analysis_check': 3.0
        }
        self.execution_history = {}
        self.path_scores = {}
    
    def calculate_priority(self, context: ExecutionContext) -> float:
        """Calculate path exploration priority
        
        Args:
            context: Execution context to prioritize
            
        Returns:
            Priority score (higher = more important)
        """
        base_score = 1.0
        
        # VM pattern recognition
        pattern_score = self._score_vm_patterns(context)
        
        # Constraint complexity
        constraint_score = self._score_constraints(context)
        
        # Path novelty
        novelty_score = self._score_novelty(context)
        
        # Depth penalty
        depth_penalty = max(0.1, 1.0 - (context.depth * 0.1))
        
        # Combine scores
        total_score = (pattern_score * 0.4 + 
                      constraint_score * 0.3 + 
                      novelty_score * 0.3) * depth_penalty
        
        self.path_scores[context.path_id] = total_score
        return total_score
    
    def _score_vm_patterns(self, context: ExecutionContext) -> float:
        """Score based on VM pattern recognition"""
        score = 1.0
        
        # Simplified pattern detection
        if context.vm_handler_calls > 0:
            score *= 1.5
        
        if len(context.registers) > 5:  # Complex register state
            score *= 1.2
        
        if len(context.memory) > 10:  # Complex memory state
            score *= 1.3
        
        return min(score, 5.0)
    
    def _score_constraints(self, context: ExecutionContext) -> float:
        """Score based on constraint complexity"""
        if not context.constraints:
            return 1.0
        
        # Diversity of constraint types
        constraint_types = set(c.type for c in context.constraints)
        diversity_score = 1.0 + len(constraint_types) * 0.2
        
        # Number of constraints
        count_score = 1.0 + min(len(context.constraints) / 10.0, 1.0)
        
        return diversity_score * count_score
    
    def _score_novelty(self, context: ExecutionContext) -> float:
        """Score based on path novelty"""
        # Simplified novelty scoring
        if context.path_id not in self.execution_history:
            return 2.0  # New path
        
        return 1.0  # Existing path


class SymbolicExecutor:
    """Main symbolic execution engine for VM analysis"""
    
    def __init__(self, config: Optional[VMDragonSlayerConfig] = None):
        """Initialize symbolic executor
        
        Args:
            config: VMDragonSlayer configuration
        """
        self.config = config or VMDragonSlayerConfig()
        self.prioritizer = PathPrioritizer()
        self.execution_queue = []
        self.completed_paths = []
        self.error_paths = []
        self.timeout_paths = []
        self.state = ExecutionState.PAUSED
        
        # Configuration
        self.max_depth = getattr(self.config, 'symbolic_execution_max_depth', 100)
        self.max_paths = getattr(self.config, 'symbolic_execution_max_paths', 1000)
        self.timeout = getattr(self.config, 'symbolic_execution_timeout', 300)  # 5 minutes
        self.enable_state_merging = getattr(self.config, 'symbolic_execution_state_merging', True)
        
        logger.info("Symbolic executor initialized")
    
    async def execute(self, 
                     initial_context: ExecutionContext,
                     instruction_handler: Optional[callable] = None) -> ExecutionResult:
        """Execute symbolic analysis
        
        Args:
            initial_context: Starting execution context
            instruction_handler: Optional custom instruction handler
            
        Returns:
            Execution result with all discovered paths
        """
        start_time = time.time()
        self.state = ExecutionState.RUNNING
        
        # Initialize execution queue
        self.execution_queue = [initial_context]
        self.completed_paths = []
        self.error_paths = []
        self.timeout_paths = []
        
        total_constraints = 0
        
        try:
            while (self.execution_queue and 
                   len(self.completed_paths) < self.max_paths and
                   time.time() - start_time < self.timeout):
                
                # Get highest priority path
                current_context = self._get_next_context()
                
                if not current_context or current_context.depth > self.max_depth:
                    continue
                
                try:
                    # Execute one step
                    new_contexts = await self._execute_step(
                        current_context, instruction_handler
                    )
                    
                    # Count constraints
                    for ctx in new_contexts:
                        total_constraints += len(ctx.constraints)
                    
                    # Add new contexts to queue or completed list
                    for ctx in new_contexts:
                        if self._is_terminal_state(ctx):
                            self.completed_paths.append(ctx)
                        else:
                            self._add_to_queue(ctx)
                
                except Exception as e:
                    logger.error("Execution error for path %s: %s", 
                               current_context.path_id, e)
                    self.error_paths.append(current_context)
            
            # Handle timeout
            if time.time() - start_time >= self.timeout:
                self.state = ExecutionState.TIMEOUT
                # Move remaining queue items to timeout
                self.timeout_paths.extend(self.execution_queue)
                self.execution_queue.clear()
            else:
                self.state = ExecutionState.COMPLETED
            
        except Exception as e:
            logger.error("Symbolic execution failed: %s", e)
            self.state = ExecutionState.ERROR
            raise AnalysisError(f"Symbolic execution failed: {e}")
        
        execution_time = time.time() - start_time
        
        # Create result
        result = ExecutionResult(
            contexts=self.completed_paths,
            total_paths=len(self.completed_paths) + len(self.error_paths) + len(self.timeout_paths),
            completed_paths=len(self.completed_paths),
            error_paths=len(self.error_paths),
            timeout_paths=len(self.timeout_paths),
            execution_time=execution_time,
            constraints_generated=total_constraints,
            statistics=self._generate_statistics()
        )
        
        logger.info("Symbolic execution completed: %d paths, %.2fs", 
                   result.total_paths, execution_time)
        
        return result
    
    def _get_next_context(self) -> Optional[ExecutionContext]:
        """Get next context to execute based on priority"""
        if not self.execution_queue:
            return None
        
        # Calculate priorities and sort
        prioritized = []
        for ctx in self.execution_queue:
            priority = self.prioritizer.calculate_priority(ctx)
            prioritized.append((priority, ctx))
        
        # Sort by priority (highest first)
        prioritized.sort(key=lambda x: x[0], reverse=True)
        
        # Remove and return highest priority context
        if prioritized:
            _, context = prioritized[0]
            self.execution_queue.remove(context)
            return context
        
        return None
    
    def _add_to_queue(self, context: ExecutionContext):
        """Add context to execution queue"""
        # Simple queue management - could implement more sophisticated strategies
        if len(self.execution_queue) < self.max_paths * 2:
            self.execution_queue.append(context)
    
    async def _execute_step(self, 
                          context: ExecutionContext,
                          instruction_handler: Optional[callable]) -> List[ExecutionContext]:
        """Execute one symbolic step
        
        Args:
            context: Current execution context
            instruction_handler: Optional instruction handler
            
        Returns:
            List of new execution contexts
        """
        if instruction_handler:
            # Use custom instruction handler
            try:
                return await instruction_handler(context)
            except Exception as e:
                logger.error("Custom instruction handler failed: %s", e)
                return []
        
        # Default symbolic execution step
        return self._default_execution_step(context)
    
    def _default_execution_step(self, context: ExecutionContext) -> List[ExecutionContext]:
        """Default symbolic execution step implementation"""
        # Simplified default implementation
        # In a real implementation, this would:
        # 1. Decode instruction at current PC
        # 2. Execute instruction symbolically
        # 3. Update symbolic state
        # 4. Generate new contexts for branches
        
        new_contexts = []
        
        # Simulate a simple branch
        if context.depth < 5:  # Arbitrary limit for demo
            # Create two branches
            branch1 = context.clone()
            branch1.pc += 1
            branch1.add_constraint(SymbolicConstraint(
                type=ConstraintType.BOOLEAN,
                expression="condition_true",
                variables={"branch_condition"}
            ))
            
            branch2 = context.clone()
            branch2.pc += 2
            branch2.add_constraint(SymbolicConstraint(
                type=ConstraintType.BOOLEAN,
                expression="condition_false",
                variables={"branch_condition"}
            ))
            
            new_contexts = [branch1, branch2]
        else:
            # Terminal case
            context.pc += 1
            new_contexts = [context]
        
        return new_contexts
    
    def _is_terminal_state(self, context: ExecutionContext) -> bool:
        """Check if context represents a terminal state"""
        # Simplified terminal condition
        return (context.depth >= self.max_depth or 
                context.pc >= 1000 or  # Arbitrary program end
                len(context.constraints) >= 50)  # Too many constraints
    
    def _generate_statistics(self) -> Dict[str, Any]:
        """Generate execution statistics"""
        return {
            "max_depth_reached": max((ctx.depth for ctx in self.completed_paths), default=0),
            "avg_constraints_per_path": (
                sum(len(ctx.constraints) for ctx in self.completed_paths) / 
                len(self.completed_paths)
            ) if self.completed_paths else 0,
            "total_contexts_created": (
                len(self.completed_paths) + 
                len(self.error_paths) + 
                len(self.timeout_paths)
            ),
            "prioritizer_scores": dict(self.prioritizer.path_scores)
        }
    
    def reset(self):
        """Reset executor state"""
        self.execution_queue.clear()
        self.completed_paths.clear()
        self.error_paths.clear()
        self.timeout_paths.clear()
        self.state = ExecutionState.PAUSED
        self.prioritizer.path_scores.clear()
        self.prioritizer.execution_history.clear()
        
        logger.debug("Symbolic executor reset")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current executor status
        
        Returns:
            Status information dictionary
        """
        return {
            "state": self.state.value,
            "queue_size": len(self.execution_queue),
            "completed_paths": len(self.completed_paths),
            "error_paths": len(self.error_paths),
            "timeout_paths": len(self.timeout_paths),
            "configuration": {
                "max_depth": self.max_depth,
                "max_paths": self.max_paths,
                "timeout": self.timeout,
                "enable_state_merging": self.enable_state_merging
            }
        }
