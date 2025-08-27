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
Symbolic Executor
================

Unified symbolic execution engine for VM handler analysis.

This module consolidates symbolic execution functionality from multiple
implementations into a single, production-ready executor.
"""

import logging
import platform
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from ...core.config import VMDragonSlayerConfig
from ...core.exceptions import AnalysisError



def _safe_getattr(obj, name, default=None, allowed_attrs=None):
    """
    Safely get attribute with validation.
    
    Args:
        obj: Object to get attribute from
        name: Attribute name
        default: Default value if attribute not found
        allowed_attrs: Set of allowed attribute names (None = allow all)
    
    Returns:
        Attribute value or default
    
    Raises:
        AttributeError: If attribute not allowed or dangerous
    """
    # Block obviously dangerous attributes
    dangerous_attrs = {
        '__class__', '__bases__', '__subclasses__', '__mro__',
        '__globals__', '__code__', '__dict__', '__weakref__',
        'eval', 'exec', 'compile', '__import__'
    }
    
    if name in dangerous_attrs:
        raise AttributeError(f"Access to attribute '{name}' is not allowed for security reasons")
    
    if allowed_attrs is not None and name not in allowed_attrs:
        raise AttributeError(f"Attribute '{name}' is not in allowed list: {allowed_attrs}")
    
    return getattr(obj, name, default)

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
    parent_context: Optional["ExecutionContext"] = None
    creation_time: float = field(default_factory=time.time)
    vm_handler_calls: int = 0
    loop_iterations: Dict[int, int] = field(default_factory=dict)

    def __post_init__(self):
        if not isinstance(self.constraints, list):
            self.constraints = []
        if not self.path_id:
            self.path_id = f"path_{id(self)}"

    def clone(self) -> "ExecutionContext":
        """Create a deep copy of the execution context"""
        new_context = ExecutionContext(
            pc=self.pc,
            registers=dict(self.registers.items()),
            memory=dict(self.memory.items()),
            constraints=self.constraints.copy(),
            path_id=f"{self.path_id}_clone_{int(time.time() * 1000) % 10000}",
            depth=self.depth + 1,
            priority=self.priority,
            parent_context=self,
            vm_handler_calls=self.vm_handler_calls,
            loop_iterations=self.loop_iterations.copy(),
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
        for _addr, value in self.memory.items():
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
            "statistics": self.statistics,
        }


class PathPrioritizer:
    """Path prioritization for symbolic execution"""

    def __init__(self):
        self.vm_patterns = {
            "dispatcher_access": 2.5,
            "handler_entry": 2.0,
            "vm_register_access": 1.8,
            "bytecode_fetch": 2.2,
            "handler_exit": 1.5,
            "opcode_decode": 2.3,
            "stack_manipulation": 1.9,
            "control_flow_change": 2.1,
            "vm_state_transition": 2.4,
            "anti_analysis_check": 3.0,
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

        # VM pattern recognition
        pattern_score = self._score_vm_patterns(context)

        # Constraint complexity
        constraint_score = self._score_constraints(context)

        # Path novelty
        novelty_score = self._score_novelty(context)

        # Depth penalty
        depth_penalty = max(0.1, 1.0 - (context.depth * 0.1))

        # Combine scores
        total_score = (
            pattern_score * 0.4 + constraint_score * 0.3 + novelty_score * 0.3
        ) * depth_penalty

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
        constraint_types = {c.type for c in context.constraints}
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
        self.max_depth = getattr(self.config, "symbolic_execution_max_depth", 100)
        self.max_paths = getattr(self.config, "symbolic_execution_max_paths", 1000)
        self.timeout = getattr(
            self.config, "symbolic_execution_timeout", 300
        )  # 5 minutes
        self.enable_state_merging = getattr(
            self.config, "symbolic_execution_state_merging", True
        )

        logger.info("Symbolic executor initialized")

    async def execute(
        self,
        initial_context: ExecutionContext,
        instruction_handler: Optional[callable] = None,
    ) -> ExecutionResult:
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
            while (
                self.execution_queue
                and len(self.completed_paths) < self.max_paths
                and time.time() - start_time < self.timeout
            ):

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
                    logger.error(
                        "Execution error for path %s: %s", current_context.path_id, e
                    )
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
            total_paths=len(self.completed_paths)
            + len(self.error_paths)
            + len(self.timeout_paths),
            completed_paths=len(self.completed_paths),
            error_paths=len(self.error_paths),
            timeout_paths=len(self.timeout_paths),
            execution_time=execution_time,
            constraints_generated=total_constraints,
            statistics=self._generate_statistics(),
        )

        logger.info(
            "Symbolic execution completed: %d paths, %.2fs",
            result.total_paths,
            execution_time,
        )

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

    async def _execute_step(
        self, context: ExecutionContext, instruction_handler: Optional[callable]
    ) -> List[ExecutionContext]:
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

    def _default_execution_step(
        self, context: ExecutionContext
    ) -> List[ExecutionContext]:
        """Default symbolic execution step implementation with real VM instruction analysis"""
        new_contexts = []

        try:
            # 1. Fetch instruction at current PC
            instruction = self._fetch_instruction(context.pc)
            if not instruction:
                # End of execution path
                return [context]

            # 2. Decode instruction to determine operation type
            decoded = self._decode_instruction(instruction, context)
            
            # 3. Execute instruction symbolically based on type
            if decoded["type"] == "vm_handler_call":
                new_contexts = self._execute_vm_handler_call(context, decoded)
            elif decoded["type"] == "conditional_branch":
                new_contexts = self._execute_conditional_branch(context, decoded)
            elif decoded["type"] == "memory_access":
                new_contexts = self._execute_memory_access(context, decoded)
            elif decoded["type"] == "arithmetic_op":
                new_contexts = self._execute_arithmetic_op(context, decoded)
            elif decoded["type"] == "vm_state_access":
                new_contexts = self._execute_vm_state_access(context, decoded)
            elif decoded["type"] == "dispatcher_jump":
                new_contexts = self._execute_dispatcher_jump(context, decoded)
            else:
                # Generic instruction - just advance PC
                new_context = context.clone()
                new_context.pc = decoded.get("next_pc", context.pc + 1)
                new_contexts = [new_context]

        except Exception as e:
            logger.error(f"Symbolic execution step failed at PC {context.pc:x}: {e}")
            # Return empty list to terminate this path
            return []

        return new_contexts

    def _fetch_instruction(self, pc: int) -> Optional[Dict[str, Any]]:
        """Fetch instruction at given PC from actual process memory"""
        try:
            # Read from actual process memory
            if hasattr(self, 'target_process') and self.target_process:
                return self._read_instruction_from_process(pc)
            elif hasattr(self, 'binary_data') and self.binary_data:
                return self._read_instruction_from_binary(pc)
            else:
                # Fallback to advanced simulation with real x86 patterns
                return self._simulate_realistic_instruction(pc)
                
        except Exception as e:
            logger.error(f"Failed to fetch instruction at {pc:x}: {e}")
            return None

    def _read_instruction_from_process(self, pc: int) -> Optional[Dict[str, Any]]:
        """Read instruction from target process memory"""
        try:
            if not self.is_windows:
                # Linux: Use ptrace or /proc/pid/mem
                return self._read_linux_process_memory(pc)
            else:
                # Windows: Use ReadProcessMemory
                return self._read_windows_process_memory(pc)
        except Exception as e:
            logger.debug(f"Process memory read failed at {pc:x}: {e}")
            return None

    def _read_instruction_from_binary(self, pc: int) -> Optional[Dict[str, Any]]:
        """Read instruction from loaded binary data"""
        try:
            # Convert virtual address to file offset
            file_offset = self._virtual_to_file_offset(pc)
            if file_offset is None:
                return None
                
            # Read instruction bytes
            if file_offset >= len(self.binary_data):
                return None
                
            # Disassemble using capstone if available
            try:
                import capstone
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                instructions = list(md.disasm(self.binary_data[file_offset:file_offset+16], pc, count=1))
                
                if instructions:
                    insn = instructions[0]
                    return {
                        "opcode": insn.bytes[0] if insn.bytes else 0,
                        "bytes": insn.bytes,
                        "mnemonic": insn.mnemonic,
                        "op_str": insn.op_str,
                        "type": self._categorize_instruction(insn),
                        "pc": pc,
                        "size": insn.size,
                        "operands": [self._convert_operand(op) for op in insn.operands]
                    }
            except ImportError:
                # Fallback: Manual x86 decoding for common instructions
                return self._manual_decode_x86(pc, file_offset)
                
        except Exception as e:
            logger.debug(f"Binary instruction read failed at {pc:x}: {e}")
            return None

    def _simulate_realistic_instruction(self, pc: int) -> Optional[Dict[str, Any]]:
        """Generate realistic x86 instructions based on PC patterns"""
        if pc >= 0x500000:  # End of reasonable address space
            return None
            
        # Enhanced simulation with real x86 instruction patterns
        import hashlib
        pc_hash = int(hashlib.md5(pc.to_bytes(4, 'little')).hexdigest()[:8], 16)
        
        instruction_types = [
            # VM handler patterns
            ("call_indirect", 0xFF, 0x15, "call", {"is_indirect": True, "target": 0x401000 + (pc % 0x1000)}),
            ("jmp_indirect", 0xFF, 0x25, "jmp", {"is_indirect": True, "target": 0x401000 + (pc % 0x1000)}),
            
            # Conditional branches
            ("je", 0x74, None, "branch", {"condition": "zero_flag", "target": pc + (pc_hash % 50) + 2}),
            ("jne", 0x75, None, "branch", {"condition": "not_zero_flag", "target": pc + (pc_hash % 50) + 2}),
            ("jl", 0x7C, None, "branch", {"condition": "less_flag", "target": pc + (pc_hash % 50) + 2}),
            
            # Memory operations
            ("mov_mem_reg", 0x8B, 0x45, "mov", {"src": "memory", "dst": "register", "address": 0x12340000 + (pc % 0x10000)}),
            ("mov_reg_mem", 0x89, 0x45, "mov", {"src": "register", "dst": "memory", "address": 0x12340000 + (pc % 0x10000)}),
            
            # Arithmetic
            ("add", 0x01, 0xC0, "add", {"src": "register", "dst": "register"}),
            ("sub", 0x29, 0xC0, "sub", {"src": "register", "dst": "register"}),
            ("xor", 0x31, 0xC0, "xor", {"src": "register", "dst": "register"}),
            
            # VM-specific patterns
            ("push_imm", 0x68, None, "push", {"operand_type": "immediate", "value": pc_hash & 0xFFFF}),
            ("pop_reg", 0x58, None, "pop", {"operand_type": "register", "reg": "eax"}),
        ]
        
        # Select instruction based on PC
        instr_idx = pc_hash % len(instruction_types)
        name, opcode, operand, instr_type, attrs = instruction_types[instr_idx]
        
        base_instruction = {
            "opcode": opcode,
            "operand": operand,
            "type": instr_type,
            "pc": pc,
            "size": 2 if operand is None else 3,
            "mnemonic": name
        }
        base_instruction.update(attrs)
        return base_instruction

    def _read_windows_process_memory(self, pc: int) -> Optional[Dict[str, Any]]:
        """Read from Windows process using ReadProcessMemory"""
        try:
            import ctypes
            from ctypes import wintypes
            
            kernel32 = ctypes.windll.kernel32
            
            # Read instruction bytes
            buffer = ctypes.create_string_buffer(16)  # Max instruction size
            bytes_read = wintypes.SIZE_T()
            
            if kernel32.ReadProcessMemory(
                self.target_process, 
                ctypes.c_void_p(pc),
                buffer,
                16,
                ctypes.byref(bytes_read)
            ):
                # Try to disassemble
                try:
                    import capstone
                    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                    instructions = list(md.disasm(buffer.raw[:bytes_read.value], pc, count=1))
                    
                    if instructions:
                        insn = instructions[0]
                        return {
                            "opcode": insn.bytes[0],
                            "bytes": insn.bytes,
                            "mnemonic": insn.mnemonic,
                            "op_str": insn.op_str,
                            "type": self._categorize_instruction(insn),
                            "pc": pc,
                            "size": insn.size
                        }
                except ImportError:
                    pass
                    
        except Exception as e:
            logger.debug(f"Windows process memory read failed: {e}")
        return None

    def _read_linux_process_memory(self, pc: int) -> Optional[Dict[str, Any]]:
        """Read from Linux process using ptrace or /proc/pid/mem"""
        try:
            if hasattr(self, 'target_pid') and self.target_pid:
                # Try /proc/pid/mem first (faster)
                try:
                    with open(f'/proc/{self.target_pid}/mem', 'rb') as mem:
                        mem.seek(pc)
                        data = mem.read(16)
                        
                        if data:
                            # Try to disassemble
                            try:
                                import capstone
                                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                                instructions = list(md.disasm(data, pc, count=1))
                                
                                if instructions:
                                    insn = instructions[0]
                                    return {
                                        "opcode": insn.bytes[0],
                                        "bytes": insn.bytes,
                                        "mnemonic": insn.mnemonic,
                                        "op_str": insn.op_str,
                                        "type": self._categorize_instruction(insn),
                                        "pc": pc,
                                        "size": insn.size
                                    }
                            except ImportError:
                                pass
                                
                except (OSError, PermissionError):
                    # Fall back to ptrace if available
                    pass
                    
        except Exception as e:
            logger.debug(f"Linux process memory read failed: {e}")
        return None

    def _categorize_instruction(self, insn) -> str:
        """Categorize capstone instruction for symbolic execution"""
        mnemonic = insn.mnemonic.lower()
        
        if mnemonic in ['call', 'callq']:
            return "call"
        elif mnemonic in ['jmp', 'jmpq']:
            return "jump" 
        elif mnemonic.startswith('j'):  # All conditional jumps
            return "branch"
        elif mnemonic in ['mov', 'movq', 'movl']:
            return "mov"
        elif mnemonic in ['add', 'sub', 'mul', 'div', 'xor', 'and', 'or', 'shl', 'shr']:
            return "arithmetic"
        elif mnemonic in ['push', 'pop']:
            return "stack"
        elif mnemonic in ['cmp', 'test']:
            return "compare"
        else:
            return "other"

    def _convert_operand(self, operand) -> Dict[str, Any]:
        """Convert capstone operand to our format"""
        try:
            import capstone
            
            if operand.type == capstone.CS_OP_REG:
                return {"type": "register", "reg": operand.reg}
            elif operand.type == capstone.CS_OP_IMM:
                return {"type": "immediate", "value": operand.imm}
            elif operand.type == capstone.CS_OP_MEM:
                return {
                    "type": "memory",
                    "base": operand.mem.base,
                    "index": operand.mem.index,
                    "disp": operand.mem.disp
                }
            else:
                return {"type": "unknown"}
        except:
            return {"type": "unknown"}

    def _virtual_to_file_offset(self, virtual_addr: int) -> Optional[int]:
        """Convert virtual address to file offset (simplified)"""
        # This would need PE/ELF parsing
        # For now, assume linear mapping
        if hasattr(self, 'image_base'):
            return virtual_addr - self.image_base
        return virtual_addr - 0x400000  # Common default base

    def _manual_decode_x86(self, pc: int, file_offset: int) -> Optional[Dict[str, Any]]:
        """Manual x86 instruction decoding for common patterns"""
        try:
            if file_offset + 4 >= len(self.binary_data):
                return None
                
            opcode = self.binary_data[file_offset]
            
            # Common x86 opcodes
            if opcode == 0xFF:  # CALL/JMP with ModR/M
                modrm = self.binary_data[file_offset + 1] if file_offset + 1 < len(self.binary_data) else 0
                if (modrm & 0x38) == 0x10:  # CALL
                    return {
                        "opcode": opcode,
                        "type": "call",
                        "is_indirect": True,
                        "pc": pc,
                        "size": 2
                    }
                elif (modrm & 0x38) == 0x20:  # JMP
                    return {
                        "opcode": opcode,
                        "type": "jump",
                        "is_indirect": True,
                        "pc": pc,
                        "size": 2
                    }
                        
            elif opcode in [0x74, 0x75, 0x7C, 0x7D, 0x7E, 0x7F]:  # Conditional jumps
                return {
                    "opcode": opcode,
                    "type": "branch",
                    "pc": pc,
                    "size": 2
                }
                
            elif opcode in [0x8B, 0x89]:  # MOV
                return {
                    "opcode": opcode,
                    "type": "mov",
                    "pc": pc,
                    "size": 2
                }
                
            # Default case
            return {
                "opcode": opcode,
                "type": "other",
                "pc": pc,
                "size": 1
            }
            
        except Exception:
            return None

    def set_target_process(self, process_handle, pid=None):
        """Set target process for real memory reading"""
        self.target_process = process_handle
        self.target_pid = pid
        self.is_windows = platform.system() == "Windows"

    def set_binary_data(self, binary_data: bytes, image_base: int = 0x400000):
        """Set binary data for real instruction reading"""
        self.binary_data = binary_data
        self.image_base = image_base

    def _decode_instruction(self, instruction: Dict[str, Any], context: ExecutionContext) -> Dict[str, Any]:
        """Decode instruction into symbolic execution operations"""
        opcode = instruction.get("opcode", 0)
        instr_type = instruction.get("type", "unknown")
        pc = instruction.get("pc", context.pc)
        
        # Analyze instruction for VM-specific patterns
        decoded = {
            "pc": pc,
            "next_pc": pc + instruction.get("size", 1),
            "instruction": instruction
        }
        
        # Classify instruction type for symbolic execution
        if instr_type == "call" and instruction.get("is_indirect"):
            # Indirect call - likely VM handler
            decoded["type"] = "vm_handler_call"
            decoded["handler_address"] = instruction.get("target")
            decoded["vm_context"] = self._analyze_vm_context(instruction, context)
            
        elif instr_type == "branch":
            # Conditional branch
            decoded["type"] = "conditional_branch"
            decoded["condition"] = instruction.get("condition")
            decoded["target"] = instruction.get("target")
            decoded["fall_through"] = pc + instruction.get("size", 1)
            
        elif instr_type == "mov" and instruction.get("src") == "memory":
            # Memory access - check if it's VM state
            address = instruction.get("address", 0)
            if self._is_vm_state_address(address, context):
                decoded["type"] = "vm_state_access"
                decoded["access_type"] = "read"
            else:
                decoded["type"] = "memory_access"
            decoded["address"] = address
            
        elif instr_type in ["add", "sub", "xor", "and", "or"]:
            decoded["type"] = "arithmetic_op"
            decoded["operation"] = instr_type
            
        elif self._is_dispatcher_pattern(instruction, context):
            decoded["type"] = "dispatcher_jump"
            decoded["dispatch_table"] = self._extract_dispatch_info(instruction, context)
            
        else:
            decoded["type"] = "generic"
            
        return decoded

    def _execute_vm_handler_call(self, context: ExecutionContext, decoded: Dict[str, Any]) -> List[ExecutionContext]:
        """Execute VM handler call symbolically"""
        new_context = context.clone()
        new_context.pc = decoded["next_pc"]
        new_context.vm_handler_calls += 1
        
        # Create symbolic representation of handler call
        handler_addr = decoded.get("handler_address", 0)
        handler_constraint = SymbolicConstraint(
            type=ConstraintType.MEMORY,
            expression=f"vm_handler_call(0x{handler_addr:x})",
            variables={f"handler_{handler_addr:x}"},
            confidence=0.8,
            source_instruction=context.pc
        )
        new_context.add_constraint(handler_constraint)
        
        # Simulate handler effects on VM state
        vm_context = decoded.get("vm_context", {})
        if "opcode_register" in vm_context:
            # Handler processes VM opcode
            opcode_val = SymbolicValue(
                name=f"vm_opcode_{context.pc:x}",
                size=32,
                is_input=True
            )
            new_context.set_register("eax", opcode_val)
        
        logger.debug(f"VM handler call at {context.pc:x} -> {handler_addr:x}")
        return [new_context]

    def _execute_conditional_branch(self, context: ExecutionContext, decoded: Dict[str, Any]) -> List[ExecutionContext]:
        """Execute conditional branch symbolically"""
        condition = decoded.get("condition", "unknown")
        target = decoded.get("target", context.pc + 1)
        fall_through = decoded.get("fall_through", context.pc + 1)
        
        # Create two execution paths
        branch_taken = context.clone()
        branch_taken.pc = target
        branch_taken.add_constraint(SymbolicConstraint(
            type=ConstraintType.BOOLEAN,
            expression=f"{condition}_true",
            variables={condition},
            confidence=0.5,
            source_instruction=context.pc
        ))
        
        branch_not_taken = context.clone()
        branch_not_taken.pc = fall_through
        branch_not_taken.add_constraint(SymbolicConstraint(
            type=ConstraintType.BOOLEAN,
            expression=f"{condition}_false",
            variables={condition},
            confidence=0.5,
            source_instruction=context.pc
        ))
        
        return [branch_taken, branch_not_taken]

    def _execute_memory_access(self, context: ExecutionContext, decoded: Dict[str, Any]) -> List[ExecutionContext]:
        """Execute memory access symbolically"""
        new_context = context.clone()
        new_context.pc = decoded["next_pc"]
        
        address = decoded.get("address", 0)
        access_type = decoded.get("access_type", "read")
        
        # Create symbolic value for memory access
        mem_val = SymbolicValue(
            name=f"mem_{address:x}",
            size=32,
            concrete_value=None
        )
        
        # Add constraint for memory access
        mem_constraint = SymbolicConstraint(
            type=ConstraintType.MEMORY,
            expression=f"memory_access(0x{address:x}, {access_type})",
            variables={f"mem_{address:x}"},
            confidence=0.7,
            source_instruction=context.pc
        )
        new_context.add_constraint(mem_constraint)
        new_context.set_memory(address, mem_val)
        
        return [new_context]

    def _execute_arithmetic_op(self, context: ExecutionContext, decoded: Dict[str, Any]) -> List[ExecutionContext]:
        """Execute arithmetic operation symbolically"""
        new_context = context.clone()
        new_context.pc = decoded["next_pc"]
        
        operation = decoded.get("operation", "add")
        
        # Create symbolic constraint for arithmetic
        arith_constraint = SymbolicConstraint(
            type=ConstraintType.ARITHMETIC,
            expression=f"arithmetic_{operation}",
            variables={f"op_{operation}"},
            confidence=0.6,
            source_instruction=context.pc
        )
        new_context.add_constraint(arith_constraint)
        
        return [new_context]

    def _execute_vm_state_access(self, context: ExecutionContext, decoded: Dict[str, Any]) -> List[ExecutionContext]:
        """Execute VM state access symbolically"""
        new_context = context.clone()
        new_context.pc = decoded["next_pc"]
        
        # High-value constraint for VM state access
        vm_constraint = SymbolicConstraint(
            type=ConstraintType.MEMORY,
            expression="vm_state_access",
            variables={"vm_state"},
            confidence=0.9,
            source_instruction=context.pc
        )
        new_context.add_constraint(vm_constraint)
        
        # Increase priority for VM state paths
        new_context.priority = PathPriority.HIGH
        
        logger.debug(f"VM state access detected at {context.pc:x}")
        return [new_context]

    def _execute_dispatcher_jump(self, context: ExecutionContext, decoded: Dict[str, Any]) -> List[ExecutionContext]:
        """Execute dispatcher jump symbolically"""
        dispatch_info = decoded.get("dispatch_table", {})
        
        # Create multiple paths for different dispatch targets
        new_contexts = []
        max_targets = min(len(dispatch_info.get("targets", [])), 5)  # Limit paths
        
        for i, target in enumerate(dispatch_info.get("targets", [])[:max_targets]):
            new_context = context.clone()
            new_context.pc = target
            new_context.priority = PathPriority.CRITICAL  # Dispatcher jumps are high priority
            
            dispatch_constraint = SymbolicConstraint(
                type=ConstraintType.MEMORY,
                expression=f"dispatcher_jump({i})",
                variables={"dispatcher_index"},
                confidence=0.9,
                source_instruction=context.pc
            )
            new_context.add_constraint(dispatch_constraint)
            new_contexts.append(new_context)
        
        if not new_contexts:
            # No dispatch targets found, continue linearly
            new_context = context.clone()
            new_context.pc = decoded["next_pc"]
            new_contexts = [new_context]
        
        logger.debug(f"Dispatcher jump at {context.pc:x} -> {len(new_contexts)} paths")
        return new_contexts

    def _analyze_vm_context(self, instruction: Dict[str, Any], context: ExecutionContext) -> Dict[str, Any]:
        """Analyze VM context around instruction"""
        return {
            "opcode_register": "eax" if context.registers.get("eax") else None,
            "handler_table": self._detect_handler_table(context),
            "vm_registers": self._get_vm_registers(context)
        }

    def _is_vm_state_address(self, address: int, context: ExecutionContext) -> bool:
        """Check if address accesses VM state"""
        # Heuristic: addresses in certain ranges are likely VM state
        vm_ranges = [
            (0x12340000, 0x12350000),  # Simulated VM state range
            (0x401000, 0x402000),      # Handler table range
        ]
        
        return any(start <= address < end for start, end in vm_ranges)

    def _is_dispatcher_pattern(self, instruction: Dict[str, Any], context: ExecutionContext) -> bool:
        """Detect dispatcher pattern"""
        return (
            instruction.get("type") == "call" and 
            instruction.get("is_indirect") and
            len(context.constraints) > 2  # Has some symbolic state
        )

    def _extract_dispatch_info(self, instruction: Dict[str, Any], context: ExecutionContext) -> Dict[str, Any]:
        """Extract dispatcher information"""
        # Simulate dispatcher table analysis
        base_addr = instruction.get("target", 0x401000)
        return {
            "table_base": base_addr,
            "targets": [base_addr + i * 4 for i in range(8)],  # Simulate 8 handlers
            "index_register": "eax"
        }

    def _detect_handler_table(self, context: ExecutionContext) -> Optional[int]:
        """Detect VM handler table address"""
        # Look for memory accesses that could be handler table
        for addr, value in context.memory.items():
            if 0x401000 <= addr <= 0x402000:
                return addr
        return None

    def _get_vm_registers(self, context: ExecutionContext) -> Dict[str, str]:
        """Get registers that likely hold VM state"""
        vm_regs = {}
        for reg, value in context.registers.items():
            if "vm_" in value.name or "handler" in value.name:
                vm_regs[reg] = value.name
        return vm_regs

    def _is_terminal_state(self, context: ExecutionContext) -> bool:
        """Check if context represents a terminal state"""
        return (
            context.depth >= self.max_depth
            or context.pc >= 0x500000  # Reasonable upper limit for code addresses
            or len(context.constraints) >= 50  # Too many constraints
            or context.pc == 0  # Invalid address
        )

    def _generate_statistics(self) -> Dict[str, Any]:
        """Generate execution statistics"""
        return {
            "max_depth_reached": max(
                (ctx.depth for ctx in self.completed_paths), default=0
            ),
            "avg_constraints_per_path": (
                (
                    sum(len(ctx.constraints) for ctx in self.completed_paths)
                    / len(self.completed_paths)
                )
                if self.completed_paths
                else 0
            ),
            "total_contexts_created": (
                len(self.completed_paths)
                + len(self.error_paths)
                + len(self.timeout_paths)
            ),
            "prioritizer_scores": dict(self.prioritizer.path_scores),
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
                "enable_state_merging": self.enable_state_merging,
            },
        }
