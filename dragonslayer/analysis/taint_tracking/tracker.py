"""
Taint Tracker
============

Unified dynamic taint tracking for VM analysis.

This module consolidates DTT functionality and provides sophisticated
taint propagation and analysis capabilities.
"""

import logging
import time
from collections import defaultdict, deque
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


class TaintType(Enum):
    """Types of taint sources"""
    INPUT = "input"
    MEMORY = "memory"
    REGISTER = "register"
    CONSTANT = "constant"
    DERIVED = "derived"
    CONTROL_FLOW = "control_flow"
    VM_BYTECODE = "vm_bytecode"


class TaintScope(Enum):
    """Scope of taint tracking"""
    LOCAL = "local"
    FUNCTION = "function"
    GLOBAL = "global"
    MODULE = "module"


class OperationType(Enum):
    """Types of operations for taint propagation"""
    READ = "read"
    WRITE = "write"
    ARITHMETIC = "arithmetic"
    LOGICAL = "logical"
    COMPARISON = "comparison"
    CONTROL_FLOW = "control_flow"
    ROTATE = "rotate"
    SHIFT = "shift"
    COPY = "copy"
    VM_SPECIFIC = "vm_specific"


@dataclass
class TaintInfo:
    """Comprehensive taint information"""
    vector: int = 0  # 64-bit taint vector
    labels: Set[str] = field(default_factory=set)
    generation: int = 0
    source_type: TaintType = TaintType.INPUT
    propagation_depth: int = 0
    confidence: float = 1.0
    address: int = 0
    size: int = 4
    timestamp: float = field(default_factory=time.time)
    operation_history: List[str] = field(default_factory=list)
    
    @property
    def taint_vector(self) -> int:
        """Alias for vector for backwards compatibility"""
        return self.vector
    
    @taint_vector.setter
    def taint_vector(self, value: int):
        """Setter for taint_vector alias"""
        self.vector = value
    
    def is_tainted(self) -> bool:
        """Check if this represents tainted data"""
        return self.vector != 0
    
    def add_operation(self, operation: str):
        """Add operation to history"""
        self.operation_history.append(operation)
        if len(self.operation_history) > 50:  # Limit history size
            self.operation_history.pop(0)
    
    def decay_confidence(self, factor: float = 0.95):
        """Apply confidence decay for propagation"""
        self.confidence *= factor
    
    def clone(self) -> 'TaintInfo':
        """Create a deep copy of taint info"""
        return TaintInfo(
            vector=self.vector,
            labels=self.labels.copy(),
            generation=self.generation,
            source_type=self.source_type,
            propagation_depth=self.propagation_depth,
            confidence=self.confidence,
            address=self.address,
            size=self.size,
            timestamp=self.timestamp,
            operation_history=self.operation_history.copy()
        )


@dataclass
class TaintEvent:
    """Record of a taint operation"""
    event_type: str
    address: int
    taint_info: TaintInfo
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "event_type": self.event_type,
            "address": hex(self.address),
            "taint_vector": hex(self.taint_info.vector),
            "labels": list(self.taint_info.labels),
            "generation": self.taint_info.generation,
            "confidence": self.taint_info.confidence,
            "timestamp": self.timestamp,
            "metadata": self.metadata
        }


@dataclass
class TaintPropagation:
    """Result of taint propagation"""
    source_address: int
    target_address: int
    operation: OperationType
    source_taint: TaintInfo
    result_taint: TaintInfo
    propagation_strength: float = 1.0
    
    def get_taint_strength(self) -> float:
        """Get propagation strength"""
        return self.propagation_strength
    
    def get_taint_type(self) -> TaintType:
        """Get taint type"""
        return self.result_taint.source_type
    
    def get_address(self) -> int:
        """Get target address"""
        return self.target_address
    
    def get_taint_info(self) -> TaintInfo:
        """Get result taint info"""
        return self.result_taint


class TaintTracker:
    """Core taint tracking engine"""
    
    def __init__(self, config: Optional[VMDragonSlayerConfig] = None):
        """Initialize taint tracker
        
        Args:
            config: VMDragonSlayer configuration
        """
        self.config = config or VMDragonSlayerConfig()
        self.taint_map = {}  # address -> TaintInfo
        self.register_taint = {}  # register -> TaintInfo
        self.events = []  # List of TaintEvent
        self.propagations = []  # List of TaintPropagation
        
        # Statistics
        self.operation_stats = defaultdict(int)
        self.hot_regions = {}  # address -> access count
        self.max_generation = 0
        
        logger.info("Taint tracker initialized")
    
    def mark_tainted(self, address: int, taint_info: Optional[TaintInfo] = None) -> TaintInfo:
        """Mark an address as tainted
        
        Args:
            address: Memory address to mark
            taint_info: Taint information (optional)
            
        Returns:
            Created or updated taint info
        """
        if taint_info is None:
            taint_info = TaintInfo(
                vector=1,
                labels={"default"},
                address=address,
                source_type=TaintType.INPUT
            )
        
        self.taint_map[address] = taint_info
        
        # Record event
        event = TaintEvent(
            event_type="mark_tainted",
            address=address,
            taint_info=taint_info.clone()
        )
        self.events.append(event)
        
        self.operation_stats['mark_tainted'] += 1
        logger.debug("Marked address 0x%x as tainted", address)
        
        return taint_info
    
    def is_tainted(self, address: int) -> bool:
        """Check if address is tainted
        
        Args:
            address: Address to check
            
        Returns:
            True if tainted, False otherwise
        """
        taint_info = self.taint_map.get(address)
        return taint_info is not None and taint_info.is_tainted()
    
    def get_taint_info(self, address: int) -> Optional[TaintInfo]:
        """Get taint information for address
        
        Args:
            address: Address to query
            
        Returns:
            Taint info or None if not tainted
        """
        return self.taint_map.get(address)
    
    def clear_taint(self, address: int):
        """Clear taint from address
        
        Args:
            address: Address to clear
        """
        if address in self.taint_map:
            del self.taint_map[address]
            
            # Record event
            event = TaintEvent(
                event_type="clear_taint",
                address=address,
                taint_info=TaintInfo()  # Empty taint info
            )
            self.events.append(event)
            
            self.operation_stats['clear_taint'] += 1
            logger.debug("Cleared taint from address 0x%x", address)
    
    def propagate_taint(self, source_addr: int, target_addr: int, 
                       operation: OperationType, 
                       operation_specific_data: Optional[Dict[str, Any]] = None) -> Optional[TaintInfo]:
        """Propagate taint from source to target
        
        Args:
            source_addr: Source address
            target_addr: Target address  
            operation: Type of operation
            operation_specific_data: Additional operation data
            
        Returns:
            New taint info for target or None if no propagation
        """
        source_taint = self.get_taint_info(source_addr)
        if not source_taint or not source_taint.is_tainted():
            return None
        
        # Create propagated taint
        new_taint = source_taint.clone()
        new_taint.address = target_addr
        new_taint.generation += 1
        new_taint.propagation_depth += 1
        new_taint.source_type = TaintType.DERIVED
        new_taint.decay_confidence()
        new_taint.add_operation(f"{operation.value}:{hex(source_addr)}")
        
        # Handle specific operations
        if operation == OperationType.ROTATE and operation_specific_data:
            positions = operation_specific_data.get('positions', 0)
            left_rotate = operation_specific_data.get('left_rotate', True)
            new_taint = self._handle_rotate_taint(new_taint, positions, left_rotate)
        elif operation == OperationType.ARITHMETIC:
            new_taint.labels.add("arithmetic_result")
        elif operation == OperationType.CONTROL_FLOW:
            new_taint.source_type = TaintType.CONTROL_FLOW
            new_taint.labels.add("control_flow_influenced")
        
        # Store propagated taint
        self.taint_map[target_addr] = new_taint
        
        # Update statistics
        self.max_generation = max(self.max_generation, new_taint.generation)
        self.operation_stats['propagate_taint'] += 1
        self.operation_stats[operation.value] += 1
        
        # Record propagation
        propagation = TaintPropagation(
            source_address=source_addr,
            target_address=target_addr,
            operation=operation,
            source_taint=source_taint,
            result_taint=new_taint,
            propagation_strength=new_taint.confidence
        )
        self.propagations.append(propagation)
        
        # Record event
        event = TaintEvent(
            event_type="propagate",
            address=target_addr,
            taint_info=new_taint.clone(),
            metadata={
                "source_address": hex(source_addr),
                "operation": operation.value,
                "generation": new_taint.generation
            }
        )
        self.events.append(event)
        
        logger.debug("Propagated taint from 0x%x to 0x%x via %s", 
                    source_addr, target_addr, operation.value)
        
        return new_taint
    
    def _handle_rotate_taint(self, taint_info: TaintInfo, positions: int, 
                           left_rotate: bool = True) -> TaintInfo:
        """Handle taint propagation for rotation operations
        
        Args:
            taint_info: Original taint info
            positions: Number of positions to rotate
            left_rotate: True for left rotation
            
        Returns:
            Updated taint info
        """
        original_vector = taint_info.vector
        
        # 64-bit rotation
        positions = positions % 64
        if left_rotate:
            rotated_vector = ((original_vector << positions) |
                            (original_vector >> (64 - positions))) & 0xFFFFFFFFFFFFFFFF
        else:
            rotated_vector = ((original_vector >> positions) |
                            (original_vector << (64 - positions))) & 0xFFFFFFFFFFFFFFFF
        
        taint_info.vector = rotated_vector
        taint_info.labels.add("rotated")
        taint_info.add_operation(f"rotate_{positions}_{'left' if left_rotate else 'right'}")
        
        self.operation_stats['rotation_operations'] += 1
        
        logger.debug("Rotated taint vector: %016x -> %016x", 
                    original_vector, rotated_vector)
        
        return taint_info
    
    def propagate_rotate_carry(self, taint_info: TaintInfo, carry_flag_tainted: bool,
                              operation_type: str = "rotate") -> TaintInfo:
        """Handle complex rotation with carry flag propagation
        
        Args:
            taint_info: Original taint info
            carry_flag_tainted: Whether carry flag is tainted
            operation_type: Type of rotation operation
            
        Returns:
            Updated taint info
        """
        new_taint = taint_info.clone()
        new_vector = taint_info.vector
        
        if operation_type in ["rcl", "rcr"]:  # Rotate through carry
            if carry_flag_tainted:
                # Carry becomes part of the rotation chain
                new_vector = ((new_vector << 1) | (1 if carry_flag_tainted else 0)) & ((1 << 64) - 1)
        elif operation_type in ["rol", "ror"]:  # Simple rotate
            # Carry flag is set but doesn't participate in data
            pass  # Vector unchanged beyond normal rotation
        
        new_taint.vector = new_vector
        new_taint.generation += 1
        new_taint.source_type = TaintType.DERIVED
        new_taint.propagation_depth += 1
        new_taint.decay_confidence(0.98)  # Minimal confidence decay
        
        # Add carry flag label if involved
        if carry_flag_tainted:
            new_taint.labels.add("carry_flag_influenced")
        
        new_taint.add_operation(f"carry_rotate_{operation_type}")
        
        # Track complex propagation
        self.operation_stats['carry_propagations'] += 1
        
        logger.debug("Carry propagation: %s, carry_tainted: %s", 
                    operation_type, carry_flag_tainted)
        
        return new_taint
    
    def set_register_taint(self, register: str, taint_info: TaintInfo):
        """Set taint for a register
        
        Args:
            register: Register name
            taint_info: Taint information
        """
        self.register_taint[register] = taint_info.clone()
        
        # Record event
        event = TaintEvent(
            event_type="register_taint",
            address=0,  # No address for registers
            taint_info=taint_info.clone(),
            metadata={"register": register}
        )
        self.events.append(event)
        
        self.operation_stats['register_taint'] += 1
        logger.debug("Set taint for register %s", register)
    
    def get_register_taint(self, register: str) -> Optional[TaintInfo]:
        """Get taint info for register
        
        Args:
            register: Register name
            
        Returns:
            Taint info or None if not tainted
        """
        return self.register_taint.get(register)
    
    def is_register_tainted(self, register: str) -> bool:
        """Check if register is tainted
        
        Args:
            register: Register name
            
        Returns:
            True if tainted
        """
        taint_info = self.get_register_taint(register)
        return taint_info is not None and taint_info.is_tainted()
    
    def update_hot_regions(self, execution_counts: Dict[int, int]):
        """Update hot regions based on execution counts
        
        Args:
            execution_counts: Address to execution count mapping
        """
        self.hot_regions.update(execution_counts)
        
        # Keep only top regions to limit memory usage
        if len(self.hot_regions) > 1000:
            sorted_regions = sorted(self.hot_regions.items(), 
                                  key=lambda x: x[1], reverse=True)
            self.hot_regions = dict(sorted_regions[:1000])
    
    def get_taint_density(self) -> float:
        """Calculate current taint density
        
        Returns:
            Ratio of tainted to total tracked addresses
        """
        if not self.events:
            return 0.0
        
        tainted_events = sum(1 for e in self.events 
                           if e.taint_info.is_tainted())
        return tainted_events / len(self.events)
    
    def find_propagation_chains(self) -> List[Dict[str, Any]]:
        """Find taint propagation chains
        
        Returns:
            List of propagation chains
        """
        chains = []
        
        # Group propagations by generation
        generation_map = defaultdict(list)
        for prop in self.propagations:
            generation_map[prop.result_taint.generation].append(prop)
        
        # Build chains
        for generation in sorted(generation_map.keys()):
            props = generation_map[generation]
            for prop in props:
                chain = {
                    'start': prop.source_address,
                    'end': prop.target_address,
                    'depth': prop.result_taint.propagation_depth,
                    'generation': generation,
                    'operation': prop.operation.value,
                    'strength': prop.propagation_strength
                }
                chains.append(chain)
        
        return chains
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive tracking statistics
        
        Returns:
            Statistics dictionary
        """
        return {
            "taint_locations": len(self.taint_map),
            "register_taints": len(self.register_taint),
            "total_events": len(self.events),
            "total_propagations": len(self.propagations),
            "max_generation": self.max_generation,
            "taint_density": self.get_taint_density(),
            "operation_stats": dict(self.operation_stats),
            "hot_regions_count": len(self.hot_regions),
            "avg_confidence": sum(t.confidence for t in self.taint_map.values()) / max(1, len(self.taint_map))
        }
    
    def clear_all(self):
        """Clear all taint tracking data"""
        self.taint_map.clear()
        self.register_taint.clear()
        self.events.clear()
        self.propagations.clear()
        self.operation_stats.clear()
        self.hot_regions.clear()
        self.max_generation = 0
        
        logger.info("Cleared all taint tracking data")
    
    def export_events(self) -> List[Dict[str, Any]]:
        """Export all events as dictionaries
        
        Returns:
            List of event dictionaries
        """
        return [event.to_dict() for event in self.events]
    
    def get_taint_summary(self) -> Dict[str, Any]:
        """Get summary of current taint state
        
        Returns:
            Taint summary
        """
        return {
            "total_tainted_addresses": len(self.taint_map),
            "tainted_registers": len(self.register_taint),
            "unique_labels": len(set().union(*(t.labels for t in self.taint_map.values()))),
            "source_types": list(set(t.source_type.value for t in self.taint_map.values())),
            "confidence_distribution": {
                "high": sum(1 for t in self.taint_map.values() if t.confidence > 0.8),
                "medium": sum(1 for t in self.taint_map.values() if 0.5 < t.confidence <= 0.8),
                "low": sum(1 for t in self.taint_map.values() if t.confidence <= 0.5)
            }
        }


# Alias for backwards compatibility with existing code
EnhancedVMTaintTracker = TaintTracker


class TaintEventAnalyzer:
    """Analyze taint propagation patterns and events"""
    
    def __init__(self):
        self.events = []
        self.stats = defaultdict(int)
    
    def add_event(self, event_type: str, address: int, taint_info: TaintInfo):
        """Add taint event for analysis
        
        Args:
            event_type: Type of event
            address: Associated address
            taint_info: Taint information
        """
        event = TaintEvent(
            event_type=event_type,
            address=address,
            taint_info=taint_info.clone()
        )
        self.events.append(event)
        self.stats[event_type] += 1
    
    def analyze_patterns(self) -> Dict[str, Any]:
        """Analyze taint propagation patterns
        
        Returns:
            Pattern analysis results
        """
        patterns = {
            'total_events': len(self.events),
            'event_types': dict(self.stats),
            'taint_density': self._calculate_taint_density(),
            'propagation_chains': self._find_propagation_chains(),
            'temporal_patterns': self._analyze_temporal_patterns()
        }
        return patterns
    
    def _calculate_taint_density(self) -> float:
        """Calculate taint density in analysis"""
        if not self.events:
            return 0.0
        
        tainted_events = sum(1 for e in self.events 
                           if e.taint_info.vector != 0)
        return tainted_events / len(self.events)
    
    def _find_propagation_chains(self) -> List[Dict[str, Any]]:
        """Find taint propagation chains"""
        chains = []
        # Simplified chain detection
        for i, event in enumerate(self.events):
            if event.event_type == 'propagate' and i > 0:
                chain = {
                    'start': self.events[i-1].address,
                    'end': event.address,
                    'depth': event.taint_info.propagation_depth,
                    'generation': event.taint_info.generation
                }
                chains.append(chain)
        return chains
    
    def _analyze_temporal_patterns(self) -> Dict[str, Any]:
        """Analyze temporal patterns in taint events"""
        if len(self.events) < 2:
            return {"intervals": [], "frequency": 0}
        
        # Calculate time intervals between events
        intervals = []
        for i in range(1, len(self.events)):
            interval = self.events[i].timestamp - self.events[i-1].timestamp
            intervals.append(interval)
        
        return {
            "intervals": intervals,
            "avg_interval": sum(intervals) / len(intervals),
            "frequency": len(self.events) / (self.events[-1].timestamp - self.events[0].timestamp)
        }
