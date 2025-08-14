"""
Taint Analysis
=============

High-level taint analysis and VM handler tracking.

This module provides sophisticated analysis capabilities for understanding
VM bytecode and handler behavior through dynamic taint tracking.
"""

import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ...core.exceptions import AnalysisError, ConfigurationError
from ...core.config import VMDragonSlayerConfig
from .tracker import (
    TaintTracker, TaintInfo, TaintType, TaintScope, OperationType,
    TaintEvent, TaintPropagation, TaintEventAnalyzer
)

logger = logging.getLogger(__name__)


@dataclass
class VMHandlerSignature:
    """Signature of a VM handler extracted from taint analysis"""
    address: int
    handler_type: str
    taint_patterns: List[str] = field(default_factory=list)
    input_taints: Set[int] = field(default_factory=set)
    output_taints: Set[int] = field(default_factory=set)
    operation_sequence: List[str] = field(default_factory=list)
    confidence: float = 1.0
    frequency: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "address": hex(self.address),
            "handler_type": self.handler_type,
            "taint_patterns": self.taint_patterns,
            "input_taints": [hex(t) for t in self.input_taints],
            "output_taints": [hex(t) for t in self.output_taints],
            "operation_sequence": self.operation_sequence,
            "confidence": self.confidence,
            "frequency": self.frequency
        }


@dataclass
class TaintAnalysisResult:
    """Result of comprehensive taint analysis"""
    vm_handlers: List[VMHandlerSignature] = field(default_factory=list)
    data_flows: List[Dict[str, Any]] = field(default_factory=list)
    taint_statistics: Dict[str, Any] = field(default_factory=dict)
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "vm_handlers": [h.to_dict() for h in self.vm_handlers],
            "data_flows": self.data_flows,
            "taint_statistics": self.taint_statistics,
            "analysis_metadata": self.analysis_metadata
        }


class VMTaintAnalyzer:
    """High-level VM taint analysis engine"""
    
    def __init__(self, config: Optional[VMDragonSlayerConfig] = None):
        """Initialize VM taint analyzer
        
        Args:
            config: VMDragonSlayer configuration
        """
        self.config = config or VMDragonSlayerConfig()
        self.tracker = TaintTracker(config)
        self.event_analyzer = TaintEventAnalyzer()
        
        # Analysis state
        self.vm_handlers = {}  # address -> VMHandlerSignature
        self.bytecode_regions = set()  # Set of (start, end) tuples
        self.handler_call_graph = defaultdict(set)  # handler -> set of called handlers
        
        # Analysis parameters
        self.confidence_threshold = 0.7
        self.min_handler_frequency = 3
        
        logger.info("VM taint analyzer initialized")
    
    def add_bytecode_region(self, start_addr: int, end_addr: int, 
                           taint_label: str = "vm_bytecode"):
        """Add a VM bytecode region for analysis
        
        Args:
            start_addr: Start address of bytecode region
            end_addr: End address of bytecode region
            taint_label: Label for taint tracking
        """
        self.bytecode_regions.add((start_addr, end_addr))
        
        # Mark entire region as tainted
        for addr in range(start_addr, end_addr, 4):  # 4-byte alignment
            taint_info = TaintInfo(
                vector=0x1,
                labels={taint_label, "bytecode"},
                source_type=TaintType.VM_BYTECODE,
                address=addr
            )
            self.tracker.mark_tainted(addr, taint_info)
        
        logger.info("Added VM bytecode region: 0x%x - 0x%x", start_addr, end_addr)
    
    def track_vm_handler(self, handler_addr: int, handler_type: str = "unknown"):
        """Register a VM handler for tracking
        
        Args:
            handler_addr: Handler address
            handler_type: Type of handler (optional)
        """
        if handler_addr not in self.vm_handlers:
            signature = VMHandlerSignature(
                address=handler_addr,
                handler_type=handler_type
            )
            self.vm_handlers[handler_addr] = signature
            
            logger.debug("Registered VM handler at 0x%x: %s", handler_addr, handler_type)
    
    def analyze_handler_execution(self, handler_addr: int, 
                                execution_trace: List[Dict[str, Any]]) -> VMHandlerSignature:
        """Analyze VM handler execution trace
        
        Args:
            handler_addr: Handler address
            execution_trace: List of execution events
            
        Returns:
            Updated handler signature
        """
        if handler_addr not in self.vm_handlers:
            self.track_vm_handler(handler_addr)
        
        signature = self.vm_handlers[handler_addr]
        signature.frequency += 1
        
        # Analyze taint flows in execution trace
        for event in execution_trace:
            event_type = event.get('type', 'unknown')
            address = event.get('address', 0)
            
            if event_type == 'memory_read':
                taint_info = self.tracker.get_taint_info(address)
                if taint_info:
                    signature.input_taints.add(address)
                    signature.taint_patterns.append(f"read_tainted:{hex(address)}")
            
            elif event_type == 'memory_write':
                # Check if write uses tainted data
                src_addr = event.get('source_address')
                if src_addr and self.tracker.is_tainted(src_addr):
                    signature.output_taints.add(address)
                    signature.taint_patterns.append(f"write_tainted:{hex(address)}")
                    
                    # Propagate taint
                    self.tracker.propagate_taint(
                        src_addr, address, OperationType.WRITE
                    )
            
            elif event_type == 'arithmetic':
                op_type = event.get('operation', 'unknown')
                signature.operation_sequence.append(op_type)
                
                # Handle arithmetic taint propagation
                src1 = event.get('operand1_addr')
                src2 = event.get('operand2_addr')
                dst = event.get('result_addr')
                
                if src1 and dst and self.tracker.is_tainted(src1):
                    self.tracker.propagate_taint(
                        src1, dst, OperationType.ARITHMETIC
                    )
                elif src2 and dst and self.tracker.is_tainted(src2):
                    self.tracker.propagate_taint(
                        src2, dst, OperationType.ARITHMETIC
                    )
            
            elif event_type == 'control_flow':
                target = event.get('target_address')
                if target and target in self.vm_handlers:
                    # Record handler-to-handler call
                    self.handler_call_graph[handler_addr].add(target)
                    signature.operation_sequence.append(f"call:{hex(target)}")
        
        # Update confidence based on analysis
        signature.confidence = self._calculate_handler_confidence(signature)
        
        logger.debug("Analyzed handler 0x%x: %d events, confidence=%.2f", 
                    handler_addr, len(execution_trace), signature.confidence)
        
        return signature
    
    def _calculate_handler_confidence(self, signature: VMHandlerSignature) -> float:
        """Calculate confidence score for handler signature
        
        Args:
            signature: Handler signature
            
        Returns:
            Confidence score (0.0 - 1.0)
        """
        confidence = 1.0
        
        # Reduce confidence if no taint patterns
        if not signature.taint_patterns:
            confidence *= 0.5
        
        # Reduce confidence if low frequency
        if signature.frequency < self.min_handler_frequency:
            confidence *= 0.7
        
        # Reduce confidence if no clear input/output pattern
        if not signature.input_taints and not signature.output_taints:
            confidence *= 0.6
        
        # Boost confidence for complex operation sequences
        if len(signature.operation_sequence) > 5:
            confidence *= 1.1
        
        return min(confidence, 1.0)
    
    def analyze_data_flow(self) -> List[Dict[str, Any]]:
        """Analyze overall data flow patterns
        
        Returns:
            List of data flow patterns
        """
        data_flows = []
        
        # Analyze propagation chains
        chains = self.tracker.find_propagation_chains()
        
        for chain in chains:
            flow = {
                "type": "propagation_chain",
                "start_address": hex(chain['start']),
                "end_address": hex(chain['end']),
                "depth": chain['depth'],
                "operation": chain['operation'],
                "strength": chain.get('strength', 1.0)
            }
            data_flows.append(flow)
        
        # Analyze cross-handler flows
        for handler_addr, called_handlers in self.handler_call_graph.items():
            for called_addr in called_handlers:
                flow = {
                    "type": "handler_to_handler",
                    "source_handler": hex(handler_addr),
                    "target_handler": hex(called_addr),
                    "flow_type": "control_flow"
                }
                data_flows.append(flow)
        
        # Analyze bytecode to handler flows
        for start_addr, end_addr in self.bytecode_regions:
            for addr in range(start_addr, end_addr, 4):
                taint_info = self.tracker.get_taint_info(addr)
                if taint_info and taint_info.propagation_depth > 0:
                    flow = {
                        "type": "bytecode_to_execution",
                        "bytecode_address": hex(addr),
                        "propagation_depth": taint_info.propagation_depth,
                        "confidence": taint_info.confidence
                    }
                    data_flows.append(flow)
        
        logger.info("Analyzed %d data flow patterns", len(data_flows))
        return data_flows
    
    def run_comprehensive_analysis(self) -> TaintAnalysisResult:
        """Run comprehensive taint analysis
        
        Returns:
            Complete analysis results
        """
        start_time = time.time()
        
        logger.info("Starting comprehensive taint analysis")
        
        # Analyze data flows
        data_flows = self.analyze_data_flow()
        
        # Get handler signatures above confidence threshold
        qualified_handlers = [
            sig for sig in self.vm_handlers.values()
            if sig.confidence >= self.confidence_threshold
        ]
        
        # Get tracker statistics
        taint_stats = self.tracker.get_statistics()
        
        # Analyze event patterns
        event_patterns = self.event_analyzer.analyze_patterns()
        
        # Create comprehensive result
        result = TaintAnalysisResult(
            vm_handlers=qualified_handlers,
            data_flows=data_flows,
            taint_statistics={
                **taint_stats,
                "event_patterns": event_patterns
            },
            analysis_metadata={
                "analysis_time": time.time() - start_time,
                "total_handlers": len(self.vm_handlers),
                "qualified_handlers": len(qualified_handlers),
                "bytecode_regions": len(self.bytecode_regions),
                "confidence_threshold": self.confidence_threshold
            }
        )
        
        logger.info("Comprehensive analysis completed in %.2f seconds", 
                   result.analysis_metadata["analysis_time"])
        
        return result
    
    def export_results(self, output_path: str, result: TaintAnalysisResult):
        """Export analysis results to file
        
        Args:
            output_path: Output file path
            result: Analysis results to export
        """
        try:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(result.to_dict(), f, indent=2)
            
            logger.info("Exported analysis results to %s", output_path)
            
        except Exception as e:
            logger.error("Failed to export results: %s", e)
            raise AnalysisError(f"Result export failed: {e}")
    
    def load_execution_trace(self, trace_file: str) -> List[Dict[str, Any]]:
        """Load execution trace from file
        
        Args:
            trace_file: Path to trace file
            
        Returns:
            List of execution events
        """
        try:
            trace_path = Path(trace_file)
            
            if not trace_path.exists():
                raise FileNotFoundError(f"Trace file not found: {trace_file}")
            
            with open(trace_path, 'r', encoding='utf-8') as f:
                if trace_path.suffix.lower() == '.json':
                    trace_data = json.load(f)
                else:
                    # Parse line-based trace format
                    trace_data = []
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Parse trace line (simplified format)
                            if 'TAINTED_READ:' in line:
                                parts = line.split()
                                addr_part = [p for p in parts if p.startswith('addr=')]
                                if addr_part:
                                    addr = int(addr_part[0].split('=')[1], 16)
                                    trace_data.append({
                                        'type': 'memory_read',
                                        'address': addr
                                    })
                            elif 'TAINTED_WRITE:' in line:
                                parts = line.split()
                                addr_part = [p for p in parts if p.startswith('addr=')]
                                if addr_part:
                                    addr = int(addr_part[0].split('=')[1], 16)
                                    trace_data.append({
                                        'type': 'memory_write',
                                        'address': addr
                                    })
            
            logger.info("Loaded %d trace events from %s", len(trace_data), trace_file)
            return trace_data
            
        except Exception as e:
            logger.error("Failed to load trace file %s: %s", trace_file, e)
            raise AnalysisError(f"Trace loading failed: {e}")
    
    def simulate_vm_execution(self, bytecode: bytes, handler_map: Dict[int, int]) -> Dict[str, Any]:
        """Simulate VM execution with taint tracking
        
        Args:
            bytecode: VM bytecode to execute
            handler_map: Mapping of opcodes to handler addresses
            
        Returns:
            Simulation results
        """
        logger.info("Starting VM execution simulation")
        
        # Mark bytecode as tainted
        bytecode_start = 0x400000  # Simulated address
        for i, byte_val in enumerate(bytecode):
            addr = bytecode_start + i
            taint_info = TaintInfo(
                vector=1 << (i % 64),  # Unique taint vector per byte
                labels={f"bytecode_{i}", "vm_input"},
                source_type=TaintType.VM_BYTECODE,
                address=addr
            )
            self.tracker.mark_tainted(addr, taint_info)
        
        # Simulate execution
        pc = 0
        execution_trace = []
        
        while pc < len(bytecode):
            opcode = bytecode[pc]
            
            if opcode in handler_map:
                handler_addr = handler_map[opcode]
                
                # Track handler execution
                self.track_vm_handler(handler_addr, f"opcode_{opcode:02x}")
                
                # Simulate handler reading bytecode
                bytecode_addr = bytecode_start + pc
                if self.tracker.is_tainted(bytecode_addr):
                    # Propagate taint to handler execution
                    result_addr = 0x500000 + len(execution_trace)  # Simulated result address
                    self.tracker.propagate_taint(
                        bytecode_addr, result_addr, OperationType.VM_SPECIFIC
                    )
                    
                    execution_trace.append({
                        'type': 'vm_handler_execute',
                        'handler_address': handler_addr,
                        'opcode': opcode,
                        'bytecode_address': bytecode_addr,
                        'result_address': result_addr
                    })
                
                # Analyze handler execution
                self.analyze_handler_execution(handler_addr, execution_trace[-1:])
            
            pc += 1
        
        # Generate simulation report
        result = {
            "bytecode_length": len(bytecode),
            "execution_trace": execution_trace,
            "handlers_executed": len(set(h for h in handler_map.values())),
            "taint_statistics": self.tracker.get_statistics()
        }
        
        logger.info("VM execution simulation completed: %d instructions", len(execution_trace))
        return result
    
    def reset_analysis(self):
        """Reset analysis state"""
        self.tracker.clear_all()
        self.event_analyzer = TaintEventAnalyzer()
        self.vm_handlers.clear()
        self.bytecode_regions.clear()
        self.handler_call_graph.clear()
        
        logger.info("Reset taint analysis state")
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get summary of current analysis state
        
        Returns:
            Analysis summary
        """
        return {
            "tracker_summary": self.tracker.get_taint_summary(),
            "vm_handlers": len(self.vm_handlers),
            "qualified_handlers": sum(1 for h in self.vm_handlers.values() 
                                    if h.confidence >= self.confidence_threshold),
            "bytecode_regions": len(self.bytecode_regions),
            "handler_call_edges": sum(len(calls) for calls in self.handler_call_graph.values()),
            "analysis_events": len(self.event_analyzer.events)
        }
