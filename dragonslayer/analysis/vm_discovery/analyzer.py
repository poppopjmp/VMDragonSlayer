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
VM Discovery Structure Analyzer
==============================

Advanced analysis of virtual machine structures including control flow,
data dependencies, and instruction patterns.
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

import networkx as nx

from ...core.exceptions import InvalidDataError, VMDetectionError

logger = logging.getLogger(__name__)


@dataclass
class ControlFlowNode:
    """Represents a node in the control flow graph"""

    address: int
    instructions: List[str] = field(default_factory=list)
    predecessors: Set[int] = field(default_factory=set)
    successors: Set[int] = field(default_factory=set)
    node_type: str = "basic_block"  # basic_block, dispatcher, handler


@dataclass
class DataDependency:
    """Represents a data dependency between instructions"""

    source_address: int
    target_address: int
    dependency_type: str  # read, write, read_write
    variable: str


class StructureAnalyzer:
    """
    Analyzes VM structures for advanced pattern recognition.

    This class provides deep analysis of VM bytecode structures,
    control flow patterns, and data dependencies.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize structure analyzer"""
        self.config = config or {}
        self.logger = logging.getLogger(f"{__name__}.StructureAnalyzer")

        # Analysis configuration
        self.max_depth = self.config.get("max_analysis_depth", 10)
        self.enable_cfg = self.config.get("enable_cfg_analysis", True)
        self.enable_data_flow = self.config.get("enable_data_flow_analysis", True)

    def analyze_vm_structure(
        self, binary_data: bytes, vm_structure: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Perform detailed structure analysis on detected VM.

        Args:
            binary_data: Binary data containing the VM
            vm_structure: Detected VM structure from detector

        Returns:
            Detailed structure analysis results
        """
        if not binary_data:
            raise InvalidDataError("Binary data cannot be empty")

        if not vm_structure:
            raise InvalidDataError("VM structure cannot be empty")

        try:
            analysis_results = {}

            # Control flow analysis
            if self.enable_cfg:
                analysis_results["control_flow"] = self._analyze_control_flow(
                    binary_data, vm_structure
                )

            # Data flow analysis
            if self.enable_data_flow:
                analysis_results["data_flow"] = self._analyze_data_flow(
                    binary_data, vm_structure
                )

            # Handler relationship analysis
            analysis_results["handler_relationships"] = (
                self._analyze_handler_relationships(vm_structure)
            )

            # Complexity analysis
            analysis_results["complexity"] = self._analyze_complexity(vm_structure)

            # Pattern analysis
            analysis_results["patterns"] = self._analyze_instruction_patterns(
                binary_data, vm_structure
            )

            return {
                "analysis_complete": True,
                "analysis_results": analysis_results,
                "metadata": {
                    "binary_size": len(binary_data),
                    "handler_count": len(vm_structure.get("handlers", [])),
                    "analysis_depth": self.max_depth,
                },
            }

        except Exception as e:
            self.logger.error(f"Structure analysis failed: {e}")
            raise VMDetectionError(
                "Failed to analyze VM structure",
                error_code="STRUCTURE_ANALYSIS_FAILED",
                cause=e,
            )

    def _analyze_control_flow(
        self, binary_data: bytes, vm_structure: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze control flow patterns"""
        handlers = vm_structure.get("handlers", [])

        if not handlers:
            return {"cfg_nodes": [], "cfg_edges": [], "analysis": "no_handlers"}

        # Build control flow graph
        cfg = self._build_control_flow_graph(handlers)

        # Analyze graph properties
        analysis = {
            "node_count": len(cfg.nodes),
            "edge_count": len(cfg.edges),
            "strongly_connected_components": len(
                list(nx.strongly_connected_components(cfg))
            ),
            "cyclomatic_complexity": self._calculate_cyclomatic_complexity(cfg),
            "entry_points": self._find_entry_points(cfg),
            "exit_points": self._find_exit_points(cfg),
        }

        return {
            "cfg_nodes": [
                {"address": node, "type": cfg.nodes[node].get("type", "unknown")}
                for node in cfg.nodes
            ],
            "cfg_edges": [{"source": src, "target": dst} for src, dst in cfg.edges],
            "analysis": analysis,
        }

    def _build_control_flow_graph(self, handlers: List[Dict[str, Any]]) -> nx.DiGraph:
        """Build control flow graph from handlers"""
        cfg = nx.DiGraph()

        # Add handler nodes
        for handler in handlers:
            handler_addr = handler.get("address")
            if isinstance(handler_addr, str):
                handler_addr = int(handler_addr, 16)

            cfg.add_node(
                handler_addr,
                type=handler.get("type", "unknown"),
                size=handler.get("size", 0),
            )

        # Add edges based on control flow targets
        for handler in handlers:
            handler_addr = handler.get("address")
            if isinstance(handler_addr, str):
                handler_addr = int(handler_addr, 16)

            targets = handler.get("control_flow_targets", [])
            for target in targets:
                if isinstance(target, str):
                    target = int(target, 16)

                if target in cfg.nodes:
                    cfg.add_edge(handler_addr, target)

        return cfg

    def _calculate_cyclomatic_complexity(self, cfg: nx.DiGraph) -> int:
        """Calculate cyclomatic complexity of control flow graph"""
        if len(cfg.nodes) == 0:
            return 0

        # Cyclomatic complexity = E - N + 2P
        # E = number of edges, N = number of nodes, P = number of connected components
        edges = len(cfg.edges)
        nodes = len(cfg.nodes)
        components = nx.number_weakly_connected_components(cfg)

        return edges - nodes + 2 * components

    def _find_entry_points(self, cfg: nx.DiGraph) -> List[int]:
        """Find entry points in control flow graph"""
        entry_points = []
        for node in cfg.nodes:
            if cfg.in_degree(node) == 0:
                entry_points.append(node)
        return entry_points

    def _find_exit_points(self, cfg: nx.DiGraph) -> List[int]:
        """Find exit points in control flow graph"""
        exit_points = []
        for node in cfg.nodes:
            if cfg.out_degree(node) == 0:
                exit_points.append(node)
        return exit_points

    def _analyze_data_flow(
        self, binary_data: bytes, vm_structure: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze data flow patterns"""
        handlers = vm_structure.get("handlers", [])

        # Simple data flow analysis
        data_dependencies = []
        register_usage = defaultdict(list)
        memory_accesses = []

        for handler in handlers:
            handler_addr = handler.get("address")
            instructions = handler.get("instructions", [])

            # Analyze instructions for data dependencies
            for i, instruction in enumerate(instructions):
                # Simple pattern matching for common data operations
                if "mov" in instruction.lower():
                    # Parse MOV instruction for data dependency
                    data_dependencies.append(
                        {
                            "address": handler_addr,
                            "instruction_index": i,
                            "type": "data_move",
                            "instruction": instruction,
                        }
                    )

                if any(
                    reg in instruction.lower() for reg in ["eax", "ebx", "ecx", "edx"]
                ):
                    # Track register usage
                    for reg in ["eax", "ebx", "ecx", "edx"]:
                        if reg in instruction.lower():
                            register_usage[reg].append(
                                {
                                    "address": handler_addr,
                                    "instruction_index": i,
                                    "instruction": instruction,
                                }
                            )

                if "[" in instruction and "]" in instruction:
                    # Memory access detected
                    memory_accesses.append(
                        {
                            "address": handler_addr,
                            "instruction_index": i,
                            "type": "memory_access",
                            "instruction": instruction,
                        }
                    )

        return {
            "data_dependencies": data_dependencies,
            "register_usage": dict(register_usage),
            "memory_accesses": memory_accesses,
            "analysis_summary": {
                "total_dependencies": len(data_dependencies),
                "registers_used": len(register_usage),
                "memory_operations": len(memory_accesses),
            },
        }

    def _analyze_handler_relationships(
        self, vm_structure: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze relationships between handlers"""
        handlers = vm_structure.get("handlers", [])

        if len(handlers) < 2:
            return {"relationships": [], "analysis": "insufficient_handlers"}

        relationships = []
        handler_types = defaultdict(list)

        # Group handlers by type
        for handler in handlers:
            handler_type = handler.get("type", "unknown")
            handler_types[handler_type].append(handler)

        # Analyze type distributions
        type_distribution = {
            handler_type: len(handler_list)
            for handler_type, handler_list in handler_types.items()
        }

        # Find potential call relationships
        for handler in handlers:
            targets = handler.get("control_flow_targets", [])
            for target in targets:
                relationships.append(
                    {
                        "source": handler.get("address"),
                        "target": target,
                        "relationship_type": "control_flow",
                    }
                )

        return {
            "relationships": relationships,
            "type_distribution": type_distribution,
            "handler_groups": {k: len(v) for k, v in handler_types.items()},
            "analysis_summary": {
                "total_relationships": len(relationships),
                "handler_types": len(handler_types),
                "most_common_type": (
                    max(type_distribution.items(), key=lambda x: x[1])[0]
                    if type_distribution
                    else "none"
                ),
            },
        }

    def _analyze_complexity(self, vm_structure: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze VM complexity metrics"""
        handlers = vm_structure.get("handlers", [])

        if not handlers:
            return {"complexity_score": 0, "analysis": "no_handlers"}

        # Calculate various complexity metrics
        handler_count = len(handlers)
        total_instructions = sum(len(h.get("instructions", [])) for h in handlers)
        avg_handler_size = (
            total_instructions / handler_count if handler_count > 0 else 0
        )

        # Type diversity
        handler_types = {h.get("type", "unknown") for h in handlers}
        type_diversity = len(handler_types)

        # Control flow complexity
        total_targets = sum(len(h.get("control_flow_targets", [])) for h in handlers)
        avg_targets_per_handler = (
            total_targets / handler_count if handler_count > 0 else 0
        )

        # Calculate overall complexity score (0-100)
        complexity_score = min(
            100,
            (
                handler_count * 2
                + type_diversity * 10
                + avg_targets_per_handler * 5
                + avg_handler_size * 0.5
            ),
        )

        return {
            "complexity_score": complexity_score,
            "metrics": {
                "handler_count": handler_count,
                "total_instructions": total_instructions,
                "avg_handler_size": avg_handler_size,
                "type_diversity": type_diversity,
                "avg_targets_per_handler": avg_targets_per_handler,
            },
            "classification": self._classify_complexity(complexity_score),
        }

    def _classify_complexity(self, score: float) -> str:
        """Classify complexity score into categories"""
        if score < 20:
            return "simple"
        elif score < 50:
            return "moderate"
        elif score < 80:
            return "complex"
        else:
            return "highly_complex"

    def _analyze_instruction_patterns(
        self, binary_data: bytes, vm_structure: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze instruction patterns in VM"""
        handlers = vm_structure.get("handlers", [])

        # Collect all instructions
        all_instructions = []
        for handler in handlers:
            all_instructions.extend(handler.get("instructions", []))

        if not all_instructions:
            return {"patterns": [], "analysis": "no_instructions"}

        # Find common instruction patterns
        instruction_freq = defaultdict(int)
        instruction_pairs = defaultdict(int)

        for instruction in all_instructions:
            instruction_freq[instruction] += 1

        # Find instruction pairs (bigrams)
        for i in range(len(all_instructions) - 1):
            pair = (all_instructions[i], all_instructions[i + 1])
            instruction_pairs[pair] += 1

        # Get most common patterns
        most_common_instructions = sorted(
            instruction_freq.items(), key=lambda x: x[1], reverse=True
        )[:10]
        most_common_pairs = sorted(
            instruction_pairs.items(), key=lambda x: x[1], reverse=True
        )[:10]

        return {
            "patterns": {
                "most_common_instructions": [
                    {"instruction": inst, "count": count}
                    for inst, count in most_common_instructions
                ],
                "most_common_pairs": [
                    {"pair": list(pair), "count": count}
                    for pair, count in most_common_pairs
                ],
            },
            "statistics": {
                "total_instructions": len(all_instructions),
                "unique_instructions": len(instruction_freq),
                "unique_pairs": len(instruction_pairs),
                "avg_instruction_frequency": (
                    sum(instruction_freq.values()) / len(instruction_freq)
                    if instruction_freq
                    else 0
                ),
            },
        }

    def get_analysis_capabilities(self) -> List[str]:
        """Get list of analysis capabilities"""
        capabilities = [
            "complexity_analysis",
            "handler_relationships",
            "instruction_patterns",
        ]

        if self.enable_cfg:
            capabilities.append("control_flow_analysis")

        if self.enable_data_flow:
            capabilities.append("data_flow_analysis")

        return capabilities
