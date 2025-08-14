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
Lifter
======

Unified handler lifter for symbolic execution.

This module consolidates handler lifting functionality and provides
bytecode-to-symbolic translation capabilities.
"""

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from ...core.config import VMDragonSlayerConfig
from ...core.exceptions import AnalysisError
from .executor import (
    ConstraintType,
    ExecutionContext,
    SymbolicConstraint,
    SymbolicValue,
)

logger = logging.getLogger(__name__)


class InstructionType(Enum):
    """Types of instructions that can be lifted"""

    ARITHMETIC = "arithmetic"
    LOGICAL = "logical"
    MEMORY = "memory"
    CONTROL_FLOW = "control_flow"
    STACK = "stack"
    COMPARISON = "comparison"
    BITWISE = "bitwise"
    VM_SPECIFIC = "vm_specific"
    UNKNOWN = "unknown"


class LiftingStrategy(Enum):
    """Lifting strategy options"""

    PRECISE = "precise"  # Precise modeling
    ABSTRACT = "abstract"  # Abstract modeling
    HYBRID = "hybrid"  # Mix of precise and abstract
    SUMMARY = "summary"  # Function summaries


@dataclass
class Instruction:
    """Instruction representation for lifting"""

    address: int
    opcode: int
    operands: List[Any] = field(default_factory=list)
    mnemonic: str = ""
    instruction_type: InstructionType = InstructionType.UNKNOWN
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __str__(self):
        operand_str = ", ".join(str(op) for op in self.operands)
        return f"{self.mnemonic} {operand_str}".strip()


@dataclass
class LiftingResult:
    """Result of instruction lifting"""

    new_contexts: List[ExecutionContext]
    constraints_added: List[SymbolicConstraint]
    symbolic_values_created: List[SymbolicValue]
    side_effects: Dict[str, Any] = field(default_factory=dict)
    lifting_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "context_count": len(self.new_contexts),
            "constraints_added": len(self.constraints_added),
            "symbolic_values_created": len(self.symbolic_values_created),
            "side_effects": self.side_effects,
            "lifting_time": self.lifting_time,
        }


@dataclass
class VMHandlerInfo:
    """VM handler information for lifting optimization"""

    address: int
    handler_type: str
    complexity: int = 1
    frequency: int = 0
    semantic_info: Dict[str, Any] = field(default_factory=dict)
    lifting_strategy: LiftingStrategy = LiftingStrategy.PRECISE

    def update_frequency(self):
        """Update handler call frequency"""
        self.frequency += 1

    def get_complexity_score(self) -> float:
        """Get normalized complexity score"""
        return min(self.complexity / 10.0, 1.0)


class InstructionLifter:
    """Base class for instruction lifting"""

    def __init__(self, config: Optional[VMDragonSlayerConfig] = None):
        self.config = config or VMDragonSlayerConfig()
        self.lift_count = 0
        self.total_lift_time = 0.0

    def lift_instruction(
        self, instruction: Instruction, context: ExecutionContext
    ) -> LiftingResult:
        """Lift a single instruction to symbolic form

        Args:
            instruction: Instruction to lift
            context: Current execution context

        Returns:
            Lifting result with new contexts and constraints
        """
        start_time = time.time()
        self.lift_count += 1

        try:
            result = self._perform_lift(instruction, context)
            result.lifting_time = time.time() - start_time
            self.total_lift_time += result.lifting_time

            logger.debug(
                "Lifted instruction %s at 0x%x in %.3fs",
                instruction.mnemonic,
                instruction.address,
                result.lifting_time,
            )

            return result

        except Exception as e:
            logger.error("Failed to lift instruction %s: %s", instruction, e)
            # Return empty result on error
            return LiftingResult(
                new_contexts=[context],  # Return original context
                constraints_added=[],
                symbolic_values_created=[],
                side_effects={"error": str(e)},
                lifting_time=time.time() - start_time,
            )

    def _perform_lift(
        self, instruction: Instruction, context: ExecutionContext
    ) -> LiftingResult:
        """Perform the actual instruction lifting"""
        # Dispatch based on instruction type
        if instruction.instruction_type == InstructionType.ARITHMETIC:
            return self._lift_arithmetic(instruction, context)
        elif instruction.instruction_type == InstructionType.LOGICAL:
            return self._lift_logical(instruction, context)
        elif instruction.instruction_type == InstructionType.MEMORY:
            return self._lift_memory(instruction, context)
        elif instruction.instruction_type == InstructionType.CONTROL_FLOW:
            return self._lift_control_flow(instruction, context)
        elif instruction.instruction_type == InstructionType.STACK:
            return self._lift_stack(instruction, context)
        elif instruction.instruction_type == InstructionType.COMPARISON:
            return self._lift_comparison(instruction, context)
        elif instruction.instruction_type == InstructionType.BITWISE:
            return self._lift_bitwise(instruction, context)
        elif instruction.instruction_type == InstructionType.VM_SPECIFIC:
            return self._lift_vm_specific(instruction, context)
        else:
            return self._lift_generic(instruction, context)

    def _lift_arithmetic(
        self, instruction: Instruction, context: ExecutionContext
    ) -> LiftingResult:
        """Lift arithmetic instructions"""
        new_context = context.clone()
        constraints = []
        symbolic_values = []

        # Example: ADD operation
        if instruction.mnemonic.upper() == "ADD" and len(instruction.operands) >= 2:
            dst = instruction.operands[0]
            src = instruction.operands[1]

            # Create symbolic value for result
            result_name = f"add_result_{instruction.address}"
            result_value = SymbolicValue(
                name=result_name, size=32, metadata={"instruction": str(instruction)}
            )

            # Add constraint: result = dst + src
            constraint = SymbolicConstraint(
                type=ConstraintType.ARITHMETIC,
                expression=f"{result_name} == {dst} + {src}",
                variables={result_name, str(dst), str(src)},
                source_instruction=instruction.address,
            )

            result_value.add_constraint(constraint)
            constraints.append(constraint)
            symbolic_values.append(result_value)

            # Update context
            if isinstance(dst, str) and dst.startswith("r"):  # register
                new_context.set_register(dst, result_value)

        return LiftingResult(
            new_contexts=[new_context],
            constraints_added=constraints,
            symbolic_values_created=symbolic_values,
        )

    def _lift_logical(
        self, instruction: Instruction, context: ExecutionContext
    ) -> LiftingResult:
        """Lift logical instructions (AND, OR, NOT, etc.)"""
        new_context = context.clone()
        constraints = []
        symbolic_values = []

        # Example: AND operation
        if instruction.mnemonic.upper() == "AND" and len(instruction.operands) >= 2:
            dst = instruction.operands[0]
            src = instruction.operands[1]

            result_name = f"and_result_{instruction.address}"
            result_value = SymbolicValue(
                name=result_name, size=32, metadata={"instruction": str(instruction)}
            )

            constraint = SymbolicConstraint(
                type=ConstraintType.BITWISE,
                expression=f"{result_name} == {dst} & {src}",
                variables={result_name, str(dst), str(src)},
                source_instruction=instruction.address,
            )

            result_value.add_constraint(constraint)
            constraints.append(constraint)
            symbolic_values.append(result_value)

            if isinstance(dst, str) and dst.startswith("r"):
                new_context.set_register(dst, result_value)

        return LiftingResult(
            new_contexts=[new_context],
            constraints_added=constraints,
            symbolic_values_created=symbolic_values,
        )

    def _lift_memory(
        self, instruction: Instruction, context: ExecutionContext
    ) -> LiftingResult:
        """Lift memory access instructions"""
        new_context = context.clone()
        constraints = []
        symbolic_values = []

        # Example: LOAD operation
        if instruction.mnemonic.upper() == "LOAD" and len(instruction.operands) >= 2:
            dst = instruction.operands[0]
            addr = instruction.operands[1]

            result_name = f"load_result_{instruction.address}"
            result_value = SymbolicValue(
                name=result_name,
                size=32,
                metadata={"instruction": str(instruction), "memory_access": True},
            )

            # Memory constraint
            constraint = SymbolicConstraint(
                type=ConstraintType.MEMORY,
                expression=f"{result_name} == memory[{addr}]",
                variables={result_name, str(addr)},
                source_instruction=instruction.address,
            )

            result_value.add_constraint(constraint)
            constraints.append(constraint)
            symbolic_values.append(result_value)

            if isinstance(dst, str) and dst.startswith("r"):
                new_context.set_register(dst, result_value)

        return LiftingResult(
            new_contexts=[new_context],
            constraints_added=constraints,
            symbolic_values_created=symbolic_values,
        )

    def _lift_control_flow(
        self, instruction: Instruction, context: ExecutionContext
    ) -> LiftingResult:
        """Lift control flow instructions"""
        constraints = []
        symbolic_values = []
        new_contexts = []

        # Example: conditional branch
        if instruction.mnemonic.upper() in ["JE", "JNE", "JMP"]:
            if instruction.mnemonic.upper() == "JMP":
                # Unconditional jump
                new_context = context.clone()
                if instruction.operands:
                    new_context.pc = int(instruction.operands[0])
                new_contexts.append(new_context)
            else:
                # Conditional jump - create two paths

                # Branch taken
                taken_context = context.clone()
                taken_constraint = SymbolicConstraint(
                    type=ConstraintType.BOOLEAN,
                    expression=f"branch_condition_{instruction.address} == true",
                    variables={f"branch_condition_{instruction.address}"},
                    source_instruction=instruction.address,
                )
                taken_context.add_constraint(taken_constraint)
                if instruction.operands:
                    taken_context.pc = int(instruction.operands[0])
                constraints.append(taken_constraint)
                new_contexts.append(taken_context)

                # Branch not taken
                not_taken_context = context.clone()
                not_taken_constraint = SymbolicConstraint(
                    type=ConstraintType.BOOLEAN,
                    expression=f"branch_condition_{instruction.address} == false",
                    variables={f"branch_condition_{instruction.address}"},
                    source_instruction=instruction.address,
                )
                not_taken_context.add_constraint(not_taken_constraint)
                not_taken_context.pc += 1  # Next instruction
                constraints.append(not_taken_constraint)
                new_contexts.append(not_taken_context)

        return LiftingResult(
            new_contexts=new_contexts,
            constraints_added=constraints,
            symbolic_values_created=symbolic_values,
        )

    def _lift_stack(
        self, instruction: Instruction, context: ExecutionContext
    ) -> LiftingResult:
        """Lift stack operations"""
        new_context = context.clone()
        constraints = []
        symbolic_values = []

        # Example: PUSH operation
        if instruction.mnemonic.upper() == "PUSH" and instruction.operands:
            value = instruction.operands[0]

            # Create symbolic stack operation
            stack_value = SymbolicValue(
                name=f"stack_push_{instruction.address}",
                size=32,
                metadata={"instruction": str(instruction), "stack_op": "push"},
            )

            constraint = SymbolicConstraint(
                type=ConstraintType.MEMORY,
                expression=f"stack[sp] == {value}",
                variables={"sp", str(value)},
                source_instruction=instruction.address,
            )

            stack_value.add_constraint(constraint)
            constraints.append(constraint)
            symbolic_values.append(stack_value)

            # Update stack pointer
            sp_value = SymbolicValue(name=f"sp_after_{instruction.address}", size=32)
            sp_constraint = SymbolicConstraint(
                type=ConstraintType.ARITHMETIC,
                expression=f"sp_after_{instruction.address} == sp - 4",
                variables={"sp", f"sp_after_{instruction.address}"},
                source_instruction=instruction.address,
            )
            sp_value.add_constraint(sp_constraint)
            constraints.append(sp_constraint)
            symbolic_values.append(sp_value)

            new_context.set_register("sp", sp_value)

        return LiftingResult(
            new_contexts=[new_context],
            constraints_added=constraints,
            symbolic_values_created=symbolic_values,
        )

    def _lift_comparison(
        self, instruction: Instruction, context: ExecutionContext
    ) -> LiftingResult:
        """Lift comparison instructions"""
        new_context = context.clone()
        constraints = []
        symbolic_values = []

        # Example: CMP operation
        if instruction.mnemonic.upper() == "CMP" and len(instruction.operands) >= 2:
            op1 = instruction.operands[0]
            op2 = instruction.operands[1]

            # Create comparison result
            result_name = f"cmp_result_{instruction.address}"
            result_value = SymbolicValue(
                name=result_name,
                size=1,  # Boolean result
                metadata={"instruction": str(instruction)},
            )

            # Add multiple constraint possibilities
            eq_constraint = SymbolicConstraint(
                type=ConstraintType.BOOLEAN,
                expression=f"{result_name}_eq == ({op1} == {op2})",
                variables={f"{result_name}_eq", str(op1), str(op2)},
                source_instruction=instruction.address,
            )

            lt_constraint = SymbolicConstraint(
                type=ConstraintType.BOOLEAN,
                expression=f"{result_name}_lt == ({op1} < {op2})",
                variables={f"{result_name}_lt", str(op1), str(op2)},
                source_instruction=instruction.address,
            )

            result_value.add_constraint(eq_constraint)
            result_value.add_constraint(lt_constraint)
            constraints.extend([eq_constraint, lt_constraint])
            symbolic_values.append(result_value)

            # Update flags register
            new_context.set_register("flags", result_value)

        return LiftingResult(
            new_contexts=[new_context],
            constraints_added=constraints,
            symbolic_values_created=symbolic_values,
        )

    def _lift_bitwise(
        self, instruction: Instruction, context: ExecutionContext
    ) -> LiftingResult:
        """Lift bitwise operations"""
        new_context = context.clone()
        constraints = []
        symbolic_values = []

        # Example: XOR operation
        if instruction.mnemonic.upper() == "XOR" and len(instruction.operands) >= 2:
            dst = instruction.operands[0]
            src = instruction.operands[1]

            result_name = f"xor_result_{instruction.address}"
            result_value = SymbolicValue(
                name=result_name, size=32, metadata={"instruction": str(instruction)}
            )

            constraint = SymbolicConstraint(
                type=ConstraintType.BITWISE,
                expression=f"{result_name} == {dst} ^ {src}",
                variables={result_name, str(dst), str(src)},
                source_instruction=instruction.address,
            )

            result_value.add_constraint(constraint)
            constraints.append(constraint)
            symbolic_values.append(result_value)

            if isinstance(dst, str) and dst.startswith("r"):
                new_context.set_register(dst, result_value)

        return LiftingResult(
            new_contexts=[new_context],
            constraints_added=constraints,
            symbolic_values_created=symbolic_values,
        )

    def _lift_vm_specific(
        self, instruction: Instruction, context: ExecutionContext
    ) -> LiftingResult:
        """Lift VM-specific instructions"""
        new_context = context.clone()
        new_context.vm_handler_calls += 1

        # VM-specific operations would be handled here
        # This is a placeholder for custom VM instruction lifting

        return LiftingResult(
            new_contexts=[new_context],
            constraints_added=[],
            symbolic_values_created=[],
            side_effects={"vm_handler_call": True},
        )

    def _lift_generic(
        self, instruction: Instruction, context: ExecutionContext
    ) -> LiftingResult:
        """Generic lifting for unknown instructions"""
        new_context = context.clone()
        new_context.pc += 1  # Just advance PC

        return LiftingResult(
            new_contexts=[new_context],
            constraints_added=[],
            symbolic_values_created=[],
            side_effects={"unknown_instruction": str(instruction)},
        )

    def get_statistics(self) -> Dict[str, Any]:
        """Get lifting statistics"""
        return {
            "lift_count": self.lift_count,
            "total_lift_time": self.total_lift_time,
            "avg_lift_time": self.total_lift_time / max(1, self.lift_count),
        }


class HandlerLifter:
    """High-level handler lifter for VM analysis"""

    def __init__(self, config: Optional[VMDragonSlayerConfig] = None):
        """Initialize handler lifter

        Args:
            config: VMDragonSlayer configuration
        """
        self.config = config or VMDragonSlayerConfig()
        self.instruction_lifter = InstructionLifter(config)
        self.handler_info = {}  # address -> VMHandlerInfo
        self.lifting_cache = {}

        logger.info("Handler lifter initialized")

    def register_handler(
        self, address: int, handler_type: str, complexity: int = 1
    ) -> VMHandlerInfo:
        """Register a VM handler for optimized lifting

        Args:
            address: Handler address
            handler_type: Type of handler
            complexity: Handler complexity score

        Returns:
            Created handler info
        """
        handler_info = VMHandlerInfo(
            address=address, handler_type=handler_type, complexity=complexity
        )

        self.handler_info[address] = handler_info
        logger.debug("Registered handler at 0x%x: %s", address, handler_type)

        return handler_info

    def lift_handler(
        self, instructions: List[Instruction], initial_context: ExecutionContext
    ) -> LiftingResult:
        """Lift a sequence of instructions representing a handler

        Args:
            instructions: List of instructions to lift
            initial_context: Initial execution context

        Returns:
            Combined lifting result
        """
        start_time = time.time()

        # Check cache
        cache_key = tuple((inst.address, inst.opcode) for inst in instructions)
        if cache_key in self.lifting_cache:
            cached_result = self.lifting_cache[cache_key]
            logger.debug("Using cached lifting result for handler")
            return cached_result

        current_contexts = [initial_context]
        all_constraints = []
        all_symbolic_values = []
        all_side_effects = {}

        try:
            for instruction in instructions:
                new_contexts = []

                for context in current_contexts:
                    result = self.instruction_lifter.lift_instruction(
                        instruction, context
                    )
                    new_contexts.extend(result.new_contexts)
                    all_constraints.extend(result.constraints_added)
                    all_symbolic_values.extend(result.symbolic_values_created)
                    all_side_effects.update(result.side_effects)

                current_contexts = new_contexts

            # Create combined result
            combined_result = LiftingResult(
                new_contexts=current_contexts,
                constraints_added=all_constraints,
                symbolic_values_created=all_symbolic_values,
                side_effects=all_side_effects,
                lifting_time=time.time() - start_time,
            )

            # Cache result
            self.lifting_cache[cache_key] = combined_result

            # Update handler frequency if known
            if instructions and instructions[0].address in self.handler_info:
                self.handler_info[instructions[0].address].update_frequency()

            logger.debug(
                "Lifted handler with %d instructions -> %d contexts",
                len(instructions),
                len(current_contexts),
            )

            return combined_result

        except Exception as e:
            logger.error("Handler lifting failed: %s", e)
            raise AnalysisError(f"Handler lifting failed: {e}")

    def clear_cache(self):
        """Clear lifting cache"""
        self.lifting_cache.clear()
        logger.debug("Lifting cache cleared")

    def get_handler_statistics(self) -> Dict[str, Any]:
        """Get handler lifting statistics

        Returns:
            Statistics dictionary
        """
        return {
            "registered_handlers": len(self.handler_info),
            "cache_size": len(self.lifting_cache),
            "handler_types": list(
                {h.handler_type for h in self.handler_info.values()}
            ),
            "instruction_lifter_stats": self.instruction_lifter.get_statistics(),
            "most_frequent_handlers": sorted(
                [(addr, info.frequency) for addr, info in self.handler_info.items()],
                key=lambda x: x[1],
                reverse=True,
            )[:10],
        }
