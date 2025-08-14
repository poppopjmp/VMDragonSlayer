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
Pattern Recognizer
=================

Unified pattern recognition system for VM bytecode analysis.

This module consolidates pattern recognition functionality from multiple
implementations into a single, production-ready recognizer.
"""

import logging
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from ...core.config import VMDragonSlayerConfig
from ...core.exceptions import (
    PatternAnalysisError,
)

logger = logging.getLogger(__name__)


class PatternConfidence(Enum):
    """Confidence levels for pattern recognition"""

    VERY_HIGH = 0.95
    HIGH = 0.80
    MEDIUM = 0.65
    LOW = 0.50
    VERY_LOW = 0.35


@dataclass
class SemanticPattern:
    """Semantic pattern definition for VM bytecode analysis"""

    name: str
    pattern_type: str
    signature: List[str]
    constraints: List[str] = field(default_factory=list)
    confidence_threshold: float = 0.7
    metadata: Dict[str, Any] = field(default_factory=dict)

    def matches(
        self, bytecode_sequence: List[int], context: Optional[Dict] = None
    ) -> Tuple[bool, float]:
        """Check if pattern matches bytecode sequence

        Args:
            bytecode_sequence: Sequence of bytecode instructions
            context: Optional context information

        Returns:
            Tuple of (is_match, confidence_score)
        """
        context = context or {}

        if len(bytecode_sequence) < len(self.signature):
            return False, 0.0

        confidence = 0.0
        matches = 0

        try:
            for i, expected in enumerate(self.signature):
                if i < len(bytecode_sequence):
                    actual = bytecode_sequence[i]
                    if self._compare_instruction(expected, actual, context):
                        matches += 1
                        confidence += 1.0 / len(self.signature)

            # Adjust with constraints only when constraints are defined
            if confidence > 0 and self.constraints:
                constraint_score = self._evaluate_constraints(
                    bytecode_sequence, context
                )
                confidence = (confidence + constraint_score) / 2.0

            is_match = confidence >= self.confidence_threshold
            return is_match, confidence

        except Exception as e:
            logger.error("Pattern matching error for %s: %s", self.name, e)
            return False, 0.0

    def _compare_instruction(self, expected: str, actual: int, context: Dict) -> bool:
        """Compare expected instruction pattern with actual bytecode"""
        try:
            if expected == "*":  # Wildcard
                return True
            elif expected.startswith("0x"):  # Exact hex match
                expected_val = int(expected, 16)
                return actual == expected_val
            elif expected.startswith("range:"):  # Range match
                range_spec = expected[6:]  # Remove "range:"
                min_val, max_val = (int(x, 16) for x in range_spec.split("-"))
                return min_val <= actual <= max_val
            elif expected.startswith("class:"):  # Instruction class match
                class_name = expected[6:]
                return self._check_instruction_class(actual, class_name, context)
            else:
                # Pattern matching (simplified)
                return str(actual) == expected
        except (ValueError, IndexError) as e:
            logger.debug("Instruction comparison error: %s", e)
            return False

    def _check_instruction_class(
        self, opcode: int, class_name: str, context: Dict
    ) -> bool:
        """Check if opcode belongs to instruction class"""
        instruction_classes = {
            "arithmetic": {0x51, 0x52, 0x53, 0x54, 0x55},  # ADD, SUB, MUL, XOR, AND
            "stack": {0x50, 0x5A, 0x5B},  # PUSH, POP, DUP
            "control": {0x56, 0x57, 0x58, 0x59},  # CMP, JMP, LOOP, etc.
            "memory": {0x60, 0x61, 0x62, 0x63},  # LOAD, STORE, etc.
        }
        return opcode in instruction_classes.get(class_name, set())

    def _evaluate_constraints(
        self, bytecode_sequence: List[int], context: Dict
    ) -> float:
        """Evaluate pattern constraints"""
        if not self.constraints:
            return 1.0

        satisfied = 0
        for constraint in self.constraints:
            if self._check_constraint(constraint, bytecode_sequence, context):
                satisfied += 1

        return satisfied / len(self.constraints)

    def _check_constraint(
        self, constraint: str, bytecode_sequence: List[int], context: Dict
    ) -> bool:
        """Check a single constraint"""
        try:
            if constraint.startswith("length:"):
                constraint_op = constraint[7:]
                if constraint_op.startswith(">="):
                    min_len = int(constraint_op[2:])
                    return len(bytecode_sequence) >= min_len
                elif constraint_op.startswith("<="):
                    max_len = int(constraint_op[2:])
                    return len(bytecode_sequence) <= max_len
                elif constraint_op.startswith("=="):
                    exact_len = int(constraint_op[2:])
                    return len(bytecode_sequence) == exact_len
                else:
                    min_len = int(constraint_op)
                    return len(bytecode_sequence) >= min_len
            elif constraint.startswith("context:"):
                key = constraint[8:]
                return key in context
            elif constraint.startswith("entropy:"):
                threshold = float(constraint[8:])
                entropy = self._calculate_entropy(bytecode_sequence)
                return entropy >= threshold
            else:
                return True
        except (ValueError, IndexError) as e:
            logger.debug("Constraint check error: %s", e)
            return False

    def _calculate_entropy(self, bytecode_sequence: List[int]) -> float:
        """Calculate entropy of bytecode sequence"""
        if not bytecode_sequence:
            return 0.0

        value_counts: Dict[int, int] = {}
        for value in bytecode_sequence:
            value_counts[value] = value_counts.get(value, 0) + 1

        total = len(bytecode_sequence)
        entropy = 0.0
        for count in value_counts.values():
            if count > 0:
                prob = count / total
                if prob > 0:
                    entropy -= prob * math.log2(prob)

        return entropy


@dataclass
class PatternMatch:
    """Result of pattern matching operation"""

    pattern_name: str
    confidence: float
    pattern_type: str
    matched_sequence: List[int]
    start_offset: int
    end_offset: int
    metadata: Dict[str, Any] = field(default_factory=dict)
    semantic_info: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "pattern_name": self.pattern_name,
            "confidence": self.confidence,
            "pattern_type": self.pattern_type,
            "matched_sequence": self.matched_sequence,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "metadata": self.metadata,
            "semantic_info": self.semantic_info,
        }


class FeatureExtractor:
    """Extract features for pattern recognition and ML classification"""

    def __init__(self) -> None:
        self.feature_cache: Dict[Any, List[float]] = {}

    def extract_features(
        self, bytecode_sequence: List[int], context: Optional[Dict] = None
    ) -> List[float]:
        """Extract features for pattern analysis

        Args:
            bytecode_sequence: Sequence of bytecode instructions
            context: Optional context information

        Returns:
            List of extracted features
        """
        context = context or {}
        cache_key = (tuple(bytecode_sequence), tuple(sorted(context.items())))

        if cache_key in self.feature_cache:
            return self.feature_cache[cache_key]

        features = []

        # Basic statistical features
        if bytecode_sequence:
            features.extend(
                [
                    len(bytecode_sequence),  # Length
                    sum(bytecode_sequence) / len(bytecode_sequence),  # Mean
                    min(bytecode_sequence),  # Min
                    max(bytecode_sequence),  # Max
                    len(set(bytecode_sequence)),  # Unique values
                    self._calculate_variance(bytecode_sequence),  # Variance
                ]
            )
        else:
            features.extend([0.0, 0.0, 0.0, 0.0, 0.0, 0.0])

        # Instruction class features
        features.extend(
            [
                self._count_arithmetic_opcodes(bytecode_sequence),
                self._count_control_flow_opcodes(bytecode_sequence),
                self._count_stack_operations(bytecode_sequence),
                self._count_memory_operations(bytecode_sequence),
            ]
        )

        # Pattern-based features
        features.extend(
            [
                self._entropy_score(bytecode_sequence),
                self._repetition_score(bytecode_sequence),
                self._transition_entropy(bytecode_sequence),
            ]
        )

        # Context features
        features.extend(
            [
                float(context.get("function_size", 0)),
                float(context.get("call_depth", 0)),
                float(context.get("has_loops", 0)),
                float(context.get("complexity_score", 0)),
            ]
        )

        self.feature_cache[cache_key] = features
        return features

    def _calculate_variance(self, sequence: List[int]) -> float:
        """Calculate variance of sequence"""
        if len(sequence) < 2:
            return 0.0

        mean = sum(sequence) / len(sequence)
        variance = sum((x - mean) ** 2 for x in sequence) / len(sequence)
        return variance

    def _count_arithmetic_opcodes(self, bytecode: List[int]) -> float:
        """Count arithmetic opcodes"""
        arithmetic_ops = {0x51, 0x52, 0x53, 0x54, 0x55}  # ADD, SUB, MUL, XOR, AND
        return float(sum(1 for op in bytecode if op in arithmetic_ops))

    def _count_control_flow_opcodes(self, bytecode: List[int]) -> float:
        """Count control flow opcodes"""
        control_ops = {0x56, 0x57, 0x58, 0x59}  # CMP, JMP, LOOP, etc.
        return float(sum(1 for op in bytecode if op in control_ops))

    def _count_stack_operations(self, bytecode: List[int]) -> float:
        """Count stack operations"""
        stack_ops = {0x50, 0x5A, 0x5B}  # PUSH, POP, DUP
        return float(sum(1 for op in bytecode if op in stack_ops))

    def _count_memory_operations(self, bytecode: List[int]) -> float:
        """Count memory operations"""
        memory_ops = {0x60, 0x61, 0x62, 0x63}  # LOAD, STORE, etc.
        return float(sum(1 for op in bytecode if op in memory_ops))

    def _entropy_score(self, bytecode: List[int]) -> float:
        """Calculate entropy score of bytecode"""
        if not bytecode:
            return 0.0

        value_counts: Dict[int, int] = {}
        for value in bytecode:
            value_counts[value] = value_counts.get(value, 0) + 1

        total = len(bytecode)
        entropy = 0.0
        for count in value_counts.values():
            if count > 0:
                prob = count / total
                if prob > 0:
                    entropy -= prob * math.log2(prob)

        return entropy

    def _repetition_score(self, bytecode: List[int]) -> float:
        """Calculate repetition score"""
        if len(bytecode) < 2:
            return 0.0

        repeated = 0
        for i in range(1, len(bytecode)):
            if bytecode[i] == bytecode[i - 1]:
                repeated += 1

        return repeated / (len(bytecode) - 1)

    def _transition_entropy(self, bytecode: List[int]) -> float:
        """Calculate transition entropy between opcodes"""
        if len(bytecode) < 2:
            return 0.0

        transitions: Dict[Tuple[int, int], int] = {}
        for i in range(len(bytecode) - 1):
            transition = (bytecode[i], bytecode[i + 1])
            transitions[transition] = transitions.get(transition, 0) + 1

        total_transitions = len(bytecode) - 1
        entropy = 0.0
        for count in transitions.values():
            prob = count / total_transitions
            if prob > 0:
                entropy -= prob * math.log2(prob)

        return entropy


class PatternRecognizer:
    """Main pattern recognition system for VM bytecode analysis"""

    def __init__(self, config: Optional[VMDragonSlayerConfig] = None) -> None:
        """Initialize pattern recognizer

        Args:
            config: VMDragonSlayer configuration
        """
        self.config = config or VMDragonSlayerConfig()
        self.patterns = {}  # type: Dict[str, SemanticPattern]
        self.pattern_hierarchy = {}  # type: Dict[str, List[str]]
        self.feature_extractor = FeatureExtractor()
        self.recognition_cache = {}  # type: Dict[Any, List[PatternMatch]]

        # Initialize with default patterns
        self._initialize_default_patterns()

        logger.info(
            "Pattern recognizer initialized with %d patterns", len(self.patterns)
        )

    def _initialize_default_patterns(self) -> None:
        """Initialize database with common VM patterns"""

        # Arithmetic operations
        self.add_pattern(
            SemanticPattern(
                name="VM_ADD",
                pattern_type="arithmetic",
                signature=[
                    "0x50",
                    "*",
                    "0x50",
                    "*",
                    "0x51",
                ],  # PUSH val1, PUSH val2, ADD
                constraints=["length:>=5"],
                metadata={
                    "description": "VM addition operation",
                    "semantic_equivalent": "val1 + val2",
                    "complexity": 2,
                },
            )
        )

        self.add_pattern(
            SemanticPattern(
                name="VM_SUB",
                pattern_type="arithmetic",
                signature=[
                    "0x50",
                    "*",
                    "0x50",
                    "*",
                    "0x52",
                ],  # PUSH val1, PUSH val2, SUB
                constraints=["length:>=5"],
                metadata={
                    "description": "VM subtraction operation",
                    "semantic_equivalent": "val1 - val2",
                    "complexity": 2,
                },
            )
        )

        self.add_pattern(
            SemanticPattern(
                name="VM_MUL",
                pattern_type="arithmetic",
                signature=[
                    "0x50",
                    "*",
                    "0x50",
                    "*",
                    "0x53",
                ],  # PUSH val1, PUSH val2, MUL
                constraints=["length:>=5"],
                metadata={
                    "description": "VM multiplication operation",
                    "semantic_equivalent": "val1 * val2",
                    "complexity": 3,
                },
            )
        )

        # Bitwise operations
        self.add_pattern(
            SemanticPattern(
                name="VM_XOR",
                pattern_type="bitwise",
                signature=[
                    "0x50",
                    "*",
                    "0x50",
                    "*",
                    "0x54",
                ],  # PUSH val1, PUSH val2, XOR
                constraints=["length:>=5"],
                metadata={
                    "description": "VM XOR operation",
                    "semantic_equivalent": "val1 ^ val2",
                    "complexity": 2,
                },
            )
        )

        # Control flow patterns
        self.add_pattern(
            SemanticPattern(
                name="VM_CONDITIONAL_JUMP",
                pattern_type="control_flow",
                signature=["0x56", "*", "0x57", "*"],  # CMP, conditional JMP
                constraints=["length:>=4"],
                metadata={
                    "description": "VM conditional jump",
                    "semantic_equivalent": "if (condition) goto address",
                    "complexity": 4,
                },
            )
        )

        # Obfuscation patterns
        self.add_pattern(
            SemanticPattern(
                name="MBA_ADDITION",
                pattern_type="obfuscation",
                signature=[
                    "0x50",
                    "*",
                    "0x50",
                    "*",
                    "0x54",
                    "0x50",
                    "*",
                    "0x55",
                    "0x51",
                ],
                constraints=["length:>=9"],
                confidence_threshold=0.8,
                metadata={
                    "description": "Mixed Boolean-Arithmetic addition obfuscation",
                    "semantic_equivalent": "(a ^ b) + 2 * (a & b)",
                    "deobfuscated": "a + b",
                    "complexity": 5,
                },
            )
        )

        # Create hierarchy
        self.pattern_hierarchy = {
            "arithmetic": ["VM_ADD", "VM_SUB", "VM_MUL"],
            "bitwise": ["VM_XOR"],
            "control_flow": ["VM_CONDITIONAL_JUMP"],
            "obfuscation": ["MBA_ADDITION"],
        }

    def add_pattern(self, pattern: SemanticPattern) -> None:
        """Add a pattern to the recognizer

        Args:
            pattern: Pattern to add
        """
        if not isinstance(pattern, SemanticPattern):
            raise PatternAnalysisError("Invalid pattern type")

        self.patterns[pattern.name] = pattern
        logger.debug("Added pattern: %s", pattern.name)

    def get_pattern(self, name: str) -> Optional[SemanticPattern]:
        """Get a pattern by name

        Args:
            name: Pattern name

        Returns:
            Pattern if found, None otherwise
        """
        return self.patterns.get(name)

    def get_patterns_by_category(self, category: str) -> List[SemanticPattern]:
        """Get all patterns in a category

        Args:
            category: Pattern category

        Returns:
            List of patterns in category
        """
        pattern_names = self.pattern_hierarchy.get(category, [])
        return [self.patterns[name] for name in pattern_names if name in self.patterns]

    async def recognize_patterns(
        self, bytecode_sequence: List[int], context: Optional[Dict] = None
    ) -> List[PatternMatch]:
        """Recognize patterns in bytecode sequence

        Args:
            bytecode_sequence: Sequence of bytecode instructions
            context: Optional context information

        Returns:
            List of pattern matches sorted by confidence
        """
        context = context or {}
        cache_key = (tuple(bytecode_sequence), tuple(sorted(context.items())))

        if cache_key in self.recognition_cache:
            return self.recognition_cache[cache_key]

        matches = []

        try:
            # Search for pattern matches
            for name, pattern in self.patterns.items():
                is_match, confidence = pattern.matches(bytecode_sequence, context)
                if is_match:
                    match = PatternMatch(
                        pattern_name=name,
                        confidence=confidence,
                        pattern_type=pattern.pattern_type,
                        matched_sequence=bytecode_sequence.copy(),
                        start_offset=0,
                        end_offset=len(bytecode_sequence),
                        metadata=pattern.metadata.copy(),
                        semantic_info={
                            "features": self.feature_extractor.extract_features(
                                bytecode_sequence, context
                            )
                        },
                    )
                    matches.append(match)

            # Sort by confidence descending
            matches.sort(key=lambda x: x.confidence, reverse=True)

            # Cache results
            self.recognition_cache[cache_key] = matches

            logger.debug(
                "Found %d pattern matches for sequence of length %d",
                len(matches),
                len(bytecode_sequence),
            )

        except Exception as e:
            logger.error("Pattern recognition error: %s", e)
            raise PatternAnalysisError(f"Pattern recognition failed: {e}") from e

        return matches

    def clear_cache(self) -> None:
        """Clear recognition cache"""
        self.recognition_cache.clear()
        self.feature_extractor.feature_cache.clear()
        logger.debug("Pattern recognition cache cleared")

    def get_statistics(self) -> Dict[str, Any]:
        """Get recognizer statistics

        Returns:
            Dictionary of statistics
        """
        return {
            "total_patterns": len(self.patterns),
            "pattern_categories": len(self.pattern_hierarchy),
            "cache_size": len(self.recognition_cache),
            "patterns_by_category": {
                category: len(patterns)
                for category, patterns in self.pattern_hierarchy.items()
            },
        }
