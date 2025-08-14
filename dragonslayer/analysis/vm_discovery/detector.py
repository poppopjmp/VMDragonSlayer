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
VMDragonSlayer VM Detection Module
=================================

Unified virtual machine detection and structure analysis.
Consolidates functionality from multiple VM detection implementations
into a single, clean, production-ready component.
"""

import hashlib
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

import numpy as np

from ...core.exceptions import InvalidDataError, VMDetectionError, handle_exception

logger = logging.getLogger(__name__)


class VMType(Enum):
    """Virtual machine architecture types"""

    STACK_BASED = "stack_based"
    REGISTER_BASED = "register_based"
    HYBRID = "hybrid"
    UNKNOWN = "unknown"


class HandlerType(Enum):
    """VM handler types"""

    ARITHMETIC = "arithmetic"
    LOGICAL = "logical"
    CONTROL_FLOW = "control_flow"
    MEMORY = "memory"
    STACK = "stack"
    REGISTER = "register"
    UNKNOWN = "unknown"


@dataclass
class VMHandler:
    """Represents a virtual machine handler"""

    address: int
    name: str
    handler_type: HandlerType
    bytecode: bytes
    size: int
    instructions: List[str] = field(default_factory=list)
    control_flow_targets: Set[int] = field(default_factory=set)
    data_dependencies: List[int] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert handler to dictionary"""
        return {
            "address": hex(self.address),
            "name": self.name,
            "type": self.handler_type.value,
            "size": self.size,
            "instructions": self.instructions,
            "control_flow_targets": [hex(addr) for addr in self.control_flow_targets],
            "data_dependencies": [hex(addr) for addr in self.data_dependencies],
            "confidence": self.confidence,
        }


@dataclass
class VMStructure:
    """Represents detected VM structure"""

    vm_type: VMType
    dispatcher_address: int
    handlers: List[VMHandler]
    bytecode_table: Optional[int] = None
    handler_table: Optional[int] = None
    vm_context_size: int = 0
    instruction_patterns: List[bytes] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert VM structure to dictionary"""
        return {
            "vm_type": self.vm_type.value,
            "dispatcher_address": hex(self.dispatcher_address),
            "bytecode_table": hex(self.bytecode_table) if self.bytecode_table else None,
            "handler_table": hex(self.handler_table) if self.handler_table else None,
            "vm_context_size": self.vm_context_size,
            "handlers": [handler.to_dict() for handler in self.handlers],
            "instruction_patterns": [
                pattern.hex() for pattern in self.instruction_patterns
            ],
            "confidence": self.confidence,
        }


class VMDetector:
    """
    Unified virtual machine detector.

    This class combines multiple VM detection techniques into a single,
    comprehensive detector that can identify various types of virtual
    machine implementations in binary code.

    Features:
    - Stack-based and register-based VM detection
    - Handler pattern recognition
    - Dispatcher identification
    - Control flow analysis
    - Bytecode structure analysis
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize VM detector.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(f"{__name__}.VMDetector")

        # VM detection patterns
        self.vm_patterns = self._load_vm_patterns()

        # Analysis cache
        self.analysis_cache = {}
        self.cache_enabled = self.config.get("enable_caching", True)

        # Detection thresholds
        self.confidence_threshold = self.config.get("confidence_threshold", 0.7)
        self.min_handlers = self.config.get("min_handlers", 3)

        self.logger.info("VM detector initialized")

    def _load_vm_patterns(self) -> Dict[str, List[bytes]]:
        """Load VM detection patterns"""
        patterns = {
            "vm_entry": [
                bytes([0x0F, 0x01, 0x0D]),  # VMCALL/VMLAUNCH
                bytes([0x50, 0x51, 0x52, 0x53]),  # PUSH registers
                bytes([0x9C, 0x60]),  # PUSHFD, PUSHA
            ],
            "dispatcher": [
                bytes([0x8B, 0x45, 0x08]),  # MOV EAX, [EBP+8]
                bytes([0xFF, 0xE0]),  # JMP EAX
                bytes([0xFF, 0x24, 0x85]),  # JMP [reg*4+offset]
                bytes([0x8B, 0x04, 0x8D]),  # MOV EAX, [ECX*4+offset]
            ],
            "handler_switch": [
                bytes([0x0F, 0xB6]),  # MOVZX
                bytes([0x8A, 0x06]),  # MOV AL, [ESI]
                bytes([0xAC]),  # LODSB
            ],
            "stack_operations": [
                bytes([0x58, 0x59, 0x5A, 0x5B]),  # POP registers
                bytes([0x61, 0x9D]),  # POPA, POPFD
                bytes([0x50, 0x51, 0x52]),  # PUSH sequence
            ],
            "indirect_jumps": [
                bytes([0xFF, 0xE0]),  # JMP EAX
                bytes([0xFF, 0xE1]),  # JMP ECX
                bytes([0xFF, 0xE2]),  # JMP EDX
                bytes([0xFF, 0x24]),  # JMP [scaled_index]
            ],
        }

        return patterns

    @handle_exception
    def detect_vm_structures(self, binary_data: bytes) -> Dict[str, Any]:
        """
        Detect VM structures in binary data.

        Args:
            binary_data: Binary data to analyze

        Returns:
            Dictionary containing detection results
        """
        if not isinstance(binary_data, (bytes, bytearray)):
            raise InvalidDataError("Binary data must be bytes or bytearray")

        if len(binary_data) == 0:
            raise InvalidDataError("Binary data cannot be empty")

        # Check cache
        if self.cache_enabled:
            cache_key = hashlib.sha256(binary_data).hexdigest()
            if cache_key in self.analysis_cache:
                self.logger.debug("Returning cached VM detection result")
                return self.analysis_cache[cache_key]

        self.logger.info(f"Starting VM structure detection on {len(binary_data)} bytes")

        try:
            # Perform multi-stage detection
            detection_result = self._perform_detection(binary_data)

            # Cache result
            if self.cache_enabled:
                self.analysis_cache[cache_key] = detection_result

            self.logger.info(
                f"VM detection completed: VM detected = {detection_result['vm_detected']}"
            )
            return detection_result

        except Exception as e:
            self.logger.error(f"VM structure detection failed: {e}")
            raise VMDetectionError(
                "Failed to detect VM structures",
                error_code="VM_DETECTION_FAILED",
                cause=e,
            ) from e

    def _perform_detection(self, binary_data: bytes) -> Dict[str, Any]:
        """Perform the actual VM detection process"""
        # Stage 1: Pattern-based detection
        pattern_results = self._detect_vm_patterns(binary_data)

        # Stage 2: Structure analysis
        structure_results = self._analyze_vm_structure(binary_data)

        # Stage 3: Handler detection
        handler_results = self._detect_handlers(binary_data)

        # Stage 4: Dispatcher identification
        dispatcher_results = self._identify_dispatcher(binary_data)

        # Combine results and calculate confidence
        combined_results = self._combine_detection_results(
            pattern_results, structure_results, handler_results, dispatcher_results
        )

        return combined_results

    def _detect_vm_patterns(self, binary_data: bytes) -> Dict[str, Any]:
        """Detect VM-specific patterns in binary data"""
        pattern_matches = defaultdict(list)
        total_matches = 0

        for pattern_type, patterns in self.vm_patterns.items():
            for pattern in patterns:
                matches = self._find_pattern_matches(binary_data, pattern)
                pattern_matches[pattern_type].extend(matches)
                total_matches += len(matches)

        # Calculate pattern confidence
        # Calibrate to avoid inflating confidence on random noise.
        # Use a bounded function of matches per kilobyte with diminishing returns.
        pattern_density = total_matches / len(binary_data) if binary_data else 0.0
        bytes_per_kb = max(len(binary_data) / 1024.0, 1.0)
        matches_per_kb = total_matches / bytes_per_kb
        # Logistic-like squashing to [0,1]: c = m / (m + k), with k controlling slope.
        k = 8.0  # need ~8 matches per KB to approach ~0.5 confidence
        pattern_confidence = matches_per_kb / (matches_per_kb + k)

        return {
            "patterns_found": dict(pattern_matches),
            "total_matches": total_matches,
            "pattern_density": pattern_density,
            "confidence": pattern_confidence,
        }

    def _find_pattern_matches(self, binary_data: bytes, pattern: bytes) -> List[int]:
        """Find all occurrences of a pattern in binary data"""
        matches = []
        start = 0

        while True:
            pos = binary_data.find(pattern, start)
            if pos == -1:
                break
            matches.append(pos)
            start = pos + 1

        return matches

    def _analyze_vm_structure(self, binary_data: bytes) -> Dict[str, Any]:
        """Analyze overall VM structure"""
        # Look for common VM structures
        structures = {
            "switch_tables": self._find_switch_tables(binary_data),
            "jump_tables": self._find_jump_tables(binary_data),
            "handler_arrays": self._find_handler_arrays(binary_data),
            "bytecode_sections": self._find_bytecode_sections(binary_data),
        }

        # Calculate structure confidence with conservative scaling
        structure_count = sum(len(struct_list) for struct_list in structures.values())
        structure_confidence = min(structure_count * 0.1, 1.0)

        return {
            "structures": structures,
            "structure_count": structure_count,
            "confidence": structure_confidence,
        }

    def _find_switch_tables(self, binary_data: bytes) -> List[Dict[str, Any]]:
        """Find switch table structures"""
        switch_tables = []

        # Look for patterns indicating switch tables
        # This is a simplified implementation
        for i in range(0, len(binary_data) - 16, 4):
            # Check for aligned pointer-like values
            values = []
            for j in range(4):
                if i + j * 4 + 3 < len(binary_data):
                    value = int.from_bytes(
                        binary_data[i + j * 4 : i + j * 4 + 4], "little"
                    )
                    values.append(value)

            # Simple heuristic: if values look like code addresses
            if len(values) >= 4 and self._values_look_like_addresses(values):
                switch_tables.append(
                    {
                        "offset": i,
                        "size": len(values) * 4,
                        "entries": len(values),
                        "values": values,
                    }
                )

        return switch_tables

    def _find_jump_tables(self, binary_data: bytes) -> List[Dict[str, Any]]:
        """Find jump table structures"""
        # Similar to switch tables but with different patterns
        return []  # Simplified for now

    def _find_handler_arrays(self, binary_data: bytes) -> List[Dict[str, Any]]:
        """Find handler array structures"""
        # Look for arrays of function pointers
        return []  # Simplified for now

    def _find_bytecode_sections(self, binary_data: bytes) -> List[Dict[str, Any]]:
        """Find bytecode sections"""
        # Look for sections that might contain VM bytecode
        bytecode_sections = []

        # Simple entropy-based detection
        chunk_size = 256
        for i in range(0, len(binary_data) - chunk_size, chunk_size // 2):
            chunk = binary_data[i : i + chunk_size]
            entropy = self._calculate_entropy(chunk)

            # Bytecode often has medium entropy (not random, not constant)
            if 3.0 < entropy < 6.0:
                bytecode_sections.append(
                    {"offset": i, "size": chunk_size, "entropy": entropy}
                )

        return bytecode_sections

    def _detect_handlers(self, binary_data: bytes) -> Dict[str, Any]:
        """Detect VM handlers"""
        handlers = []

        # Look for common handler patterns
        handler_patterns = [
            (b"\\x8B\\x45\\x08", HandlerType.MEMORY),  # MOV EAX, [EBP+8]
            (b"\\x50\\x51\\x52", HandlerType.STACK),  # PUSH sequence
            (b"\\x58\\x59\\x5A", HandlerType.STACK),  # POP sequence
            (b"\\x01\\xC0", HandlerType.ARITHMETIC),  # ADD EAX, EAX
            (b"\\x29\\xC0", HandlerType.ARITHMETIC),  # SUB EAX, EAX
            (b"\\x21\\xC0", HandlerType.LOGICAL),  # AND EAX, EAX
            (b"\\x09\\xC0", HandlerType.LOGICAL),  # OR EAX, EAX
        ]

        for i, (pattern, handler_type) in enumerate(handler_patterns):
            # Convert pattern to bytes (simplified)
            pattern_bytes = (
                pattern.replace(b"\\x", b"").decode("unicode_escape").encode("latin1")
            )

            matches = self._find_pattern_matches(binary_data, pattern_bytes)

            for match_offset in matches:
                handler = VMHandler(
                    address=match_offset,
                    name=f"handler_{i}_{match_offset:x}",
                    handler_type=handler_type,
                    bytecode=binary_data[match_offset : match_offset + 16],
                    size=16,
                    confidence=0.6,  # Base confidence
                )
                handlers.append(handler)

        # Remove duplicate handlers (same address)
        unique_handlers = {}
        for handler in handlers:
            if handler.address not in unique_handlers:
                unique_handlers[handler.address] = handler

        handlers = list(unique_handlers.values())

        # Calculate handler confidence with conservative scaling
        handler_confidence = min(len(handlers) * 0.05, 1.0)

        return {
            "handlers": handlers,
            "handler_count": len(handlers),
            "confidence": handler_confidence,
        }

    def _identify_dispatcher(self, binary_data: bytes) -> Dict[str, Any]:
        """Identify VM dispatcher"""
        dispatcher_candidates = []

        # Look for dispatcher patterns
        dispatcher_patterns = [
            b"\\xFF\\xE0",  # JMP EAX
            b"\\xFF\\x24\\x85",  # JMP [scaled_index]
            b"\\x8B\\x04\\x8D",  # MOV EAX, [ECX*4+offset]
        ]

        for pattern in dispatcher_patterns:
            # Convert pattern to bytes (simplified)
            pattern_bytes = (
                pattern.replace(b"\\x", b"").decode("unicode_escape").encode("latin1")
            )
            matches = self._find_pattern_matches(binary_data, pattern_bytes)

            for match in matches:
                dispatcher_candidates.append(
                    {"address": match, "pattern": pattern, "confidence": 0.7}
                )

        # Find most likely dispatcher
        best_dispatcher = None
        if dispatcher_candidates:
            # Simple heuristic: use first candidate
            best_dispatcher = dispatcher_candidates[0]

        dispatcher_confidence = 0.6 if best_dispatcher else 0.0

        return {
            "dispatcher": best_dispatcher,
            "candidates": dispatcher_candidates,
            "confidence": dispatcher_confidence,
        }

    def _combine_detection_results(
        self,
        pattern_results: Dict,
        structure_results: Dict,
        handler_results: Dict,
        dispatcher_results: Dict,
    ) -> Dict[str, Any]:
        """Combine all detection results into final assessment"""

        # Calculate overall confidence
        confidences = [
            pattern_results.get("confidence", 0.0),
            structure_results.get("confidence", 0.0),
            handler_results.get("confidence", 0.0),
            dispatcher_results.get("confidence", 0.0),
        ]

        overall_confidence = float(np.mean(confidences))
        vm_detected = bool(overall_confidence >= self.confidence_threshold)

        # Determine VM type
        vm_type = self._determine_vm_type(pattern_results, handler_results)

        # Create VM structure if detected
        vm_structure = None
        if vm_detected and handler_results["handlers"]:
            vm_structure = VMStructure(
                vm_type=vm_type,
                dispatcher_address=dispatcher_results.get("dispatcher", {}).get(
                    "address", 0
                ),
                handlers=handler_results["handlers"],
                confidence=overall_confidence,
            )

        return {
            "vm_detected": vm_detected,
            "confidence": overall_confidence,
            "vm_type": vm_type.value if vm_type else VMType.UNKNOWN.value,
            "vm_structure": vm_structure.to_dict() if vm_structure else None,
            "detection_details": {
                "patterns": pattern_results,
                "structures": structure_results,
                "handlers": {
                    "count": handler_results["handler_count"],
                    "confidence": handler_results["confidence"],
                },
                "dispatcher": dispatcher_results,
            },
            "analysis_summary": {
                "total_patterns_found": pattern_results.get("total_matches", 0),
                "structure_count": structure_results.get("structure_count", 0),
                "handler_count": handler_results.get("handler_count", 0),
                "dispatcher_found": dispatcher_results.get("dispatcher") is not None,
            },
        }

    def _determine_vm_type(
        self, pattern_results: Dict, handler_results: Dict
    ) -> VMType:
        """Determine the type of VM based on detection results"""
        stack_indicators = 0
        register_indicators = 0

        # Check patterns for VM type indicators
        patterns = pattern_results.get("patterns_found", {})

        if "stack_operations" in patterns and patterns["stack_operations"]:
            stack_indicators += len(patterns["stack_operations"])

        # Check handlers for type indicators
        handlers = handler_results.get("handlers", [])
        for handler in handlers:
            if handler.handler_type == HandlerType.STACK:
                stack_indicators += 1
            elif handler.handler_type == HandlerType.REGISTER:
                register_indicators += 1

        # Determine type
        if stack_indicators > register_indicators * 2:
            return VMType.STACK_BASED
        elif register_indicators > stack_indicators * 2:
            return VMType.REGISTER_BASED
        elif stack_indicators > 0 and register_indicators > 0:
            return VMType.HYBRID
        else:
            return VMType.UNKNOWN

    def _values_look_like_addresses(self, values: List[int]) -> bool:
        """Check if values look like code addresses"""
        if not values:
            return False

        # Simple heuristics
        for value in values:
            # Check if value is in reasonable range for addresses
            if not (0x400000 <= value <= 0x7FFFFFFF):
                return False

            # Check alignment (many architectures prefer aligned addresses)
            if value % 4 != 0:
                return False

        return True

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0

        # Count byte frequencies
        counts = Counter(data)
        length = len(data)

        # Calculate entropy
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            entropy -= probability * np.log2(probability)

        return entropy

    async def detect_vm_structures_async(self, binary_data: bytes) -> Dict[str, Any]:
        """Async version of VM structure detection"""
        import asyncio

        # Run detection in thread pool for CPU-intensive work
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.detect_vm_structures, binary_data)

    def analyze_binary(self, binary_data: bytes) -> Dict[str, Any]:
        """Compatibility method for binary analysis"""
        return self.detect_vm_structures(binary_data)

    def extract_handlers(self, binary_data: bytes) -> List[Dict[str, Any]]:
        """Extract VM handlers from binary data"""
        detection_result = self.detect_vm_structures(binary_data)

        if detection_result.get("vm_structure"):
            vm_structure = detection_result["vm_structure"]
            return vm_structure.get("handlers", [])

        return []

    def classify_instructions(self, binary_data: bytes) -> Dict[str, Any]:
        """Classify instructions in binary data"""
        # This would implement instruction classification
        # For now, return basic classification based on patterns
        pattern_results = self._detect_vm_patterns(binary_data)

        instruction_types = defaultdict(int)
        for pattern_type, matches in pattern_results.get("patterns_found", {}).items():
            instruction_types[pattern_type] = len(matches)

        return {
            "instruction_counts": dict(instruction_types),
            "total_instructions": sum(instruction_types.values()),
            "classification_confidence": pattern_results.get("confidence", 0.0),
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get detector statistics"""
        return {
            "cache_size": len(self.analysis_cache),
            "cache_enabled": self.cache_enabled,
            "confidence_threshold": self.confidence_threshold,
            "min_handlers": self.min_handlers,
            "pattern_count": sum(
                len(patterns) for patterns in self.vm_patterns.values()
            ),
        }

    def clear_cache(self) -> None:
        """Clear analysis cache"""
        self.analysis_cache.clear()
        self.logger.info("Analysis cache cleared")

    async def cleanup(self) -> None:
        """Cleanup detector resources"""
        self.clear_cache()
        self.logger.info("VM detector cleanup completed")
