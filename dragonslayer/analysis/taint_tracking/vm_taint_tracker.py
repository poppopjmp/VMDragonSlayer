"""
Enhanced VM Taint Tracker
Advanced dynamic taint tracking for VM-protected code analysis.
"""

import time
import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import threading
from collections import defaultdict

logger = logging.getLogger(__name__)

class TaintType(Enum):
    """Types of taint sources"""
    INPUT = "input"
    MEMORY = "memory"
    REGISTER = "register"
    CONSTANT = "constant"
    DERIVED = "derived"

@dataclass
class TaintInfo:
    """Enhanced taint information with 64-bit vector support"""
    vector: int = 0  # 64-bit taint vector (renamed from taint_vector for compatibility)
    labels: Set[str] = None  # Detailed taint labels
    generation: int = 0  # Temporal tracking
    source_type: TaintType = TaintType.CONSTANT
    propagation_depth: int = 0
    confidence: float = 1.0
    # Additional fields for test compatibility
    address: int = 0
    size: int = 4
    taint_vector: int = 0  # Alias for vector
    
    def __post_init__(self):
        if self.labels is None:
            self.labels = set()
        elif not isinstance(self.labels, set):
            self.labels = set(self.labels) if self.labels else set()
        
        # Sync vector and taint_vector
        if self.taint_vector != 0 and self.vector == 0:
            self.vector = self.taint_vector
        elif self.vector != 0 and self.taint_vector == 0:
            self.taint_vector = self.vector
    
    def is_tainted(self) -> bool:
        """Check if this location is tainted"""
        return self.vector != 0 or self.taint_vector != 0

class TaintEventAnalyzer:
    """Process and analyze taint events"""
    
    def __init__(self):
        self.events = []
        self.stats = defaultdict(int)
    
    def add_event(self, event_type: str, address: int, taint_info: TaintInfo):
        """Add taint event for analysis"""
        event = {
            'type': event_type,
            'address': address,
            'taint': taint_info,
            'timestamp': time.time()
        }
        self.events.append(event)
        self.stats[event_type] += 1
    
    def analyze_patterns(self) -> Dict[str, Any]:
        """Analyze taint propagation patterns"""
        patterns = {
            'total_events': len(self.events),
            'event_types': dict(self.stats),
            'taint_density': self._calculate_taint_density(),
            'propagation_chains': self._find_propagation_chains()
        }
        return patterns
    
    def _calculate_taint_density(self) -> float:
        """Calculate taint density in analysis"""
        if not self.events:
            return 0.0
        
        tainted_events = sum(1 for e in self.events 
                           if e['taint'].vector != 0)
        return tainted_events / len(self.events)
    
    def _find_propagation_chains(self) -> List[Dict[str, Any]]:
        """Find taint propagation chains"""
        chains = []
        # Simplified chain detection
        for i, event in enumerate(self.events):
            if event['type'] == 'propagate' and i > 0:
                chain = {
                    'start': self.events[i-1]['address'],
                    'end': event['address'],
                    'depth': event['taint'].propagation_depth
                }
                chains.append(chain)
        return chains

class EnhancedVMTaintTracker:
    """Advanced VM taint tracking with adaptive instrumentation"""
    
    def __init__(self, config = None):
        # Handle both dict config and string config file paths
        if isinstance(config, str):
            # Config file path provided
            import json
            try:
                with open(config, 'r') as f:
                    self.config = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                self.config = {}
        elif isinstance(config, dict):
            self.config = config
        else:
            self.config = {}
            
        self.analyzer = TaintEventAnalyzer()
        self.taint_map = {}  # address -> TaintInfo
        self.instrumentation_points = set()
        self.hot_regions = set()
        self.generation_counter = 0
        self.performance_stats = {
            'instructions_processed': 0,
            'taint_operations': 0,
            'instrumentation_overhead': 0.0
        }
        
        # Adaptive instrumentation settings
        self.instrumentation_threshold = self.config.get('instrumentation_threshold', 0.7)
        self.hot_region_threshold = self.config.get('hot_region_threshold', 1000)
        
        # Initialize missing attributes for compatibility
        self.taint_generation_regions = []
        self.execution_frequency = {}
        self.address_taint_history = {}
        self.vm_dispatcher_regions = []
        self.vm_handler_regions = []
        self.operation_stats = {'rotation_operations': 0, 'carry_propagations': 0}
        
    def should_instrument(self, address: int, instruction: str = None) -> bool:
        """Adaptive instrumentation decision"""
        # Check if near taint source
        if self.near_taint_source(address):
            return True
        
        # Check if in hot region (reduce instrumentation)
        if self.in_hot_region(address):
            return self.taint_probability(address) > self.instrumentation_threshold
        
        # Consider instruction type for better decisions
        if instruction:
            key_instrs = ['mov', 'add', 'sub', 'xor']
            if any(instr in instruction.lower() for instr in key_instrs):
                return True
            # Don't instrument non-key instructions by default
            return False
        
        # Default is no instrumentation for unknown regions without context
        return False
    
    def near_taint_source(self, address: int) -> bool:
        """Check if address is near a taint source (optimization heuristic)"""
        
        # Check if within proximity of known taint sources
        for taint_addr in self.taint_map:
            distance = abs(address - taint_addr)
            if distance < 50:  # Within 50 bytes
                return True
        
        # Check if in taint generation region
        for region_start, region_end in self.taint_generation_regions:
            if region_start <= address <= region_end:
                return True
        
        return False
    
    def in_hot_region(self, address: int) -> bool:
        """Check if address is in a hot execution region (performance optimization)"""
        
        # Check execution frequency
        exec_count = self.execution_frequency.get(address, 0)
        if exec_count > self.hot_region_threshold:
            return True
        
        # Check if in known hot spots
        for hot_start, hot_end in self.hot_regions:
            if hot_start <= address <= hot_end:
                return True
        
        return False
    
    def taint_probability(self, address: int) -> float:
        """Calculate probability of taint at address (adaptive thresholding)"""
        
        # Base probability from historical data
        base_prob = self.address_taint_history.get(address, 0.5)
        
        # Adjust based on nearby taint activity
        nearby_taint = sum(1 for addr in self.taint_map
                          if abs(addr - address) < 50)
        
        proximity_boost = min(0.3, nearby_taint * 0.05)
        
        # Adjust based on execution context
        context_factor = 1.0
        if self.in_vm_dispatcher_region(address):
            context_factor = 1.2
        elif self.in_handler_region(address):
            context_factor = 1.1
        
        final_probability = min(1.0, (base_prob + proximity_boost) * context_factor)
        
        return final_probability
    
    def rotate_taint(self, taint_info: TaintInfo, rotation_bits: int, 
                    left_rotate: bool = True) -> TaintInfo:
        """Handle complex taint propagation for bitwise rotation instructions"""
        
        if not taint_info.is_tainted():
            return taint_info
        
        # Get the original taint vector
        original_vector = taint_info.vector
        
        # Perform bit rotation on taint vector
        if left_rotate:
            # Left rotation
            rotated_vector = ((original_vector << rotation_bits) | 
                            (original_vector >> (64 - rotation_bits))) & ((1 << 64) - 1)
        else:
            # Right rotation  
            rotated_vector = ((original_vector >> rotation_bits) | 
                            (original_vector << (64 - rotation_bits))) & ((1 << 64) - 1)
        
        # Create new taint info with rotated vector
        rotated_taint = TaintInfo(
            vector=rotated_vector,
            labels=taint_info.labels.copy(),
            generation=taint_info.generation + 1,
            source_type=TaintType.DERIVED,
            propagation_depth=taint_info.propagation_depth + 1,
            confidence=taint_info.confidence * 0.95,  # Slight confidence decay
            address=taint_info.address,
            size=taint_info.size
        )
        
        # Update taint vector alias
        rotated_taint.taint_vector = rotated_vector
        
        # Track rotation operation
        self.operation_stats['rotation_operations'] += 1
        
        logger.debug(f"Rotated taint vector: {original_vector:016x} -> {rotated_vector:016x}")
        
        return rotated_taint
    
    def in_vm_dispatcher_region(self, address: int) -> bool:
        """Check if address is in VM dispatcher region"""
        
        for dispatcher_start, dispatcher_end in self.vm_dispatcher_regions:
            if dispatcher_start <= address <= dispatcher_end:
                return True
        return False
    
    def in_handler_region(self, address: int) -> bool:
        """Check if address is in VM handler region"""
        
        for handler_start, handler_end in self.vm_handler_regions:
            if handler_start <= address <= handler_end:
                return True
        return False 
    
    def mark_tainted(self, address: int, taint_type: TaintType = TaintType.INPUT,
                     labels: Set[str] = None, confidence: float = 1.0):
        """Mark a memory/register location as tainted (alias for add_taint)"""
        if not isinstance(address, int) or address < 0:
            raise TypeError("Address must be a non-negative integer")
        self.add_taint(address, taint_type, labels, confidence)

    def add_taint(self, address: int, taint_type: TaintType = TaintType.INPUT,
                  labels: Set[str] = None, confidence: float = 1.0):
        """Add taint to memory/register location"""
        if not isinstance(address, int) or address < 0:
            raise TypeError("Address must be a non-negative integer")
        self.generation_counter += 1
        
        taint_info = TaintInfo(
            vector=1 << (self.generation_counter % 64),  # Rotate through 64 bits
            labels=labels or set(),
            generation=self.generation_counter,
            source_type=taint_type,
            propagation_depth=0,
            confidence=confidence
        )
        
        self.taint_map[address] = taint_info
        self.analyzer.add_event('add_taint', address, taint_info)
        self.performance_stats['taint_operations'] += 1
    
    def propagate_taint(self, src_addr: int, dst_addr: int,
                       operation: str = "copy") -> bool:
        """Propagate taint from source to destination"""
        if not isinstance(src_addr, int) or src_addr < 0:
            raise TypeError("Source address must be a non-negative integer")
        if not isinstance(dst_addr, int) or dst_addr < 0:
            raise TypeError("Destination address must be a non-negative integer")
        
        if src_addr not in self.taint_map:
            return False
        
        src_taint = self.taint_map[src_addr]
        
        # Create derived taint
        dst_taint = TaintInfo(
            vector=src_taint.vector,
            labels=src_taint.labels.copy(),
            generation=src_taint.generation,
            source_type=TaintType.DERIVED,
            propagation_depth=src_taint.propagation_depth + 1,
            confidence=src_taint.confidence * 0.95  # Slight confidence decay
        )
        
        # Handle specific operations
        if operation == "rotate":
            dst_taint = self.propagate_rotate_carry(src_taint, dst_taint)
        elif operation == "arithmetic":
            dst_taint.labels.add("arithmetic_derived")
        
        self.taint_map[dst_addr] = dst_taint
        self.analyzer.add_event('propagate', dst_addr, dst_taint)
        self.performance_stats['taint_operations'] += 1
        
        return True
    
    def propagate_rotate_carry(self, taint_info: TaintInfo, carry_flag_tainted: bool,
                              operation_type: str = "rotate") -> TaintInfo:
        """
        Handle complex taint propagation for rotating instructions with carry flag
        This implements the claimed carry flag propagation functionality
        """
        
        if not taint_info.is_tainted() and not carry_flag_tainted:
            return taint_info
        
        # Start with original taint vector
        new_vector = taint_info.vector
        
        # If carry flag is tainted, it affects the result
        if carry_flag_tainted:
            # Carry flag influence - propagate to least significant bit
            carry_influence = 1  # Single bit for carry
            new_vector |= carry_influence
        
        # Apply operation-specific propagation rules
        if operation_type in ["rcl", "rcr"]:  # Rotate through carry
            # Carry flag participates in rotation
            if carry_flag_tainted:
                # Carry becomes part of the rotation chain
                new_vector = ((new_vector << 1) | (1 if carry_flag_tainted else 0)) & ((1 << 64) - 1)
        elif operation_type in ["rol", "ror"]:  # Simple rotate
            # Carry flag is set but doesn't participate in data
            pass  # Vector unchanged beyond normal rotation
        
        # Create new taint info with enhanced propagation
        result_taint = TaintInfo(
            vector=new_vector,
            labels=taint_info.labels.copy(),
            generation=taint_info.generation + 1,
            source_type=TaintType.DERIVED,
            propagation_depth=taint_info.propagation_depth + 1,
            confidence=taint_info.confidence * 0.98,  # Minimal confidence decay
            address=taint_info.address,
            size=taint_info.size
        )
        
        # Add carry flag label if involved
        if carry_flag_tainted:
            result_taint.labels.add("carry_flag_influenced")
        
        # Track complex propagation
        self.operation_stats['carry_propagations'] += 1
        
        logger.debug(f"Carry propagation: {operation_type}, carry_tainted: {carry_flag_tainted}")
        
        return result_taint

    def rotate_taint(self, taint_info, positions: int,
                     left_rotate: bool = True) -> 'TaintInfo':
        """Rotate taint vector bits"""
        if isinstance(taint_info, TaintInfo):
            taint_vector = taint_info.vector
        else:
            taint_vector = taint_info
        
        # 64-bit rotation
        positions = positions % 64
        if left_rotate:
            rotated = ((taint_vector << positions) |
                       (taint_vector >> (64 - positions))) & 0xFFFFFFFFFFFFFFFF
        else:
            rotated = ((taint_vector >> positions) |
                       (taint_vector << (64 - positions))) & 0xFFFFFFFFFFFFFFFF
        
        if isinstance(taint_info, TaintInfo):
            # Create new TaintInfo with rotated vector
            return TaintInfo(
                vector=rotated,
                labels=taint_info.labels.copy(),
                generation=taint_info.generation + 1,  # Increment generation
                source_type=TaintType.DERIVED,  # Mark as derived
                propagation_depth=taint_info.propagation_depth,
                confidence=taint_info.confidence,
                address=taint_info.address,
                size=taint_info.size
            )
        else:
            return rotated
    
    def check_taint(self, address: int) -> bool:
        """Check if a specific address is tainted (alias for is_tainted)"""
        return self.is_tainted(address)
    
    def is_tainted(self, address: int) -> bool:
        """Check if location is tainted"""
        if not isinstance(address, int) or address < 0:
            raise TypeError("Address must be a non-negative integer")
        return (address in self.taint_map and
                self.taint_map[address].vector != 0)
    
    def get_taint_info(self, address: int) -> Optional[TaintInfo]:
        """Get detailed taint information"""
        return self.taint_map.get(address)
    
    def clear_taint(self, address: int):
        """Clear taint from location"""
        if not isinstance(address, int) or address < 0:
            raise TypeError("Address must be a non-negative integer")
        if address in self.taint_map:
            del self.taint_map[address]
            self.analyzer.add_event('clear_taint', address,
                                    TaintInfo(0, set(), 0, TaintType.CONSTANT,
                                              0, 0.0))
    
    def update_hot_regions(self, execution_counts: Dict[int, int]):
        """Update hot execution regions for adaptive instrumentation"""
        self.hot_regions.clear()
        for address, count in execution_counts.items():
            if count > self.hot_region_threshold:
                self.hot_regions.add(address)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get performance and analysis statistics"""
        return {
            'taint_locations': len(self.taint_map),
            'propagations': self.performance_stats.get('taint_operations', 0),
            'hot_regions': len(getattr(self, 'hot_regions', set())),
            'instrumentation_points': len(getattr(self,
                                                   'instrumentation_points',
                                                   set())),
            'analysis_patterns': getattr(self.analyzer, 'analyze_patterns',
                                         lambda: {})()
        }
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        return {
            **self.performance_stats,
            'taint_locations': len(self.taint_map),
            'hot_regions': len(self.hot_regions),
            'instrumentation_points': len(self.instrumentation_points),
            'analysis_patterns': self.analyzer.analyze_patterns()
        }
    
    def export_taint_graph(self) -> Dict[str, Any]:
        """Export taint propagation graph"""
        graph = {
            'nodes': [],
            'edges': []
        }
        
        # Add taint nodes
        for address, taint in self.taint_map.items():
            node = {
                'id': address,
                'type': taint.source_type.value,
                'generation': taint.generation,
                'confidence': taint.confidence,
                'labels': list(taint.labels)
            }
            graph['nodes'].append(node)
        
        # Add propagation edges from events
        for event in self.analyzer.events:
            if event['type'] == 'propagate':
                edge = {
                    'source': event['address'] - 1,  # Simplified
                    'target': event['address'],
                    'type': 'propagation'
                }
                graph['edges'].append(edge)
        
        return graph


class TaintSet:
    """Simple taint set implementation for compatibility"""
    
    def __init__(self, initial_taint: Set[str] = None):
        self.taint_labels = initial_taint or set()
        # address -> TaintInfo mapping for test compatibility
        self.taint_map = {}
    
    def add(self, label: str):
        """Add taint label"""
        self.taint_labels.add(label)
    
    def add_taint(self, taint_info: TaintInfo):
        """Add taint info (for test compatibility)"""
        if hasattr(taint_info, 'address'):
            self.taint_map[taint_info.address] = taint_info
        self.taint_labels.update(taint_info.labels)
    
    def is_tainted(self, address: int) -> bool:
        """Check if address is tainted"""
        return address in self.taint_map
    
    def union(self, other: 'TaintSet') -> 'TaintSet':
        """Union with another taint set"""
        result = TaintSet()
        result.taint_labels = self.taint_labels.union(other.taint_labels)
        result.taint_map.update(self.taint_map)
        result.taint_map.update(other.taint_map)
        return result
    
    def __len__(self) -> int:
        return len(self.taint_labels)
    
    def __iter__(self):
        return iter(self.taint_labels)


def create_enhanced_tracker(config: Dict[str, Any] = None
                            ) -> EnhancedVMTaintTracker:
    """Factory function to create enhanced taint tracker"""
    return EnhancedVMTaintTracker(config)


# Alias for backward compatibility
VMTaintTracker = EnhancedVMTaintTracker


# Test function for validation
def test_enhanced_tracker():
    """Test the enhanced taint tracker functionality"""
    tracker = create_enhanced_tracker()
    
    # Test basic taint operations
    tracker.add_taint(0x1000, TaintType.INPUT, {"user_input"})
    tracker.propagate_taint(0x1000, 0x1004, "copy")
    tracker.propagate_taint(0x1004, 0x1008, "rotate")
    
    # Test taint queries
    assert tracker.is_tainted(0x1000)
    assert tracker.is_tainted(0x1004)
    assert tracker.is_tainted(0x1008)
    
    # Test performance stats
    stats = tracker.get_performance_stats()
    assert stats['taint_operations'] >= 3
    assert stats['taint_locations'] >= 3
    
    # Test taint graph export
    graph = tracker.export_taint_graph()
    assert len(graph['nodes']) >= 3
    
    logger.info("Enhanced taint tracker test passed")
    return True


def main():
    """Main DTT tool entry point"""
    import argparse
    import json
    
    parser = argparse.ArgumentParser(
        description="Enhanced Dynamic Taint Tracking Tool")
    parser.add_argument("--start-address",
                        help="Starting address (hex)", default="0x1000")
    parser.add_argument("--taint-source",
                        help="Taint source address (hex, "
                             "alias for start-address)")
    parser.add_argument("--max-steps", type=int,
                        help="Maximum execution steps", default=10000)
    parser.add_argument("--output", help="Output report file",
                        default="dtt_report.json")
    parser.add_argument("--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--demo", action="store_true",
                        help="Run demo mode")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.demo:
        print("Enhanced Dynamic Taint Tracking - Demo Mode")
        return test_enhanced_tracker()
    
    # Initialize tracker
    tracker = EnhancedVMTaintTracker()
    
    # Parse start address (handle both --start-address and --taint-source)
    try:
        if args.taint_source:
            start_addr = int(args.taint_source, 16)
        else:
            start_addr = int(args.start_address, 16)
    except ValueError:
        addr_arg = args.taint_source or args.start_address
        logger.error("Invalid address: %s", addr_arg)
        return 1
    
    # Demo execution
    print("Enhanced Dynamic Taint Tracking")
    print(f"Starting analysis at address: {hex(start_addr)}")
    
    # Add some demo taint sources
    tracker.mark_tainted(start_addr, TaintInfo(vector=0x1, labels={"input"}))
    tracker.mark_tainted(start_addr + 4,
                         TaintInfo(vector=0x2, labels={"memory"}))
    
    # Generate demo report
    stats = tracker.get_statistics()
    
    # Generate trace information for test compatibility
    trace_entries = []
    for addr, taint_info in tracker.taint_map.items():
        if taint_info.is_tainted():
            trace_entries.append({
                "address": hex(addr),
                "taint_vector": taint_info.vector,
                "labels": list(taint_info.labels),
                "generation": taint_info.generation
            })
    
    # Generate tainted data summary
    tainted_data = {
        "total_locations": len(trace_entries),
        "taint_vectors": [entry["taint_vector"] for entry in trace_entries],
        "labels_summary": {}
    }
    
    # Count label frequencies
    for entry in trace_entries:
        for label in entry["labels"]:
            count = tainted_data["labels_summary"].get(label, 0)
            tainted_data["labels_summary"][label] = count + 1
    
    report = {
        "start_address": hex(start_addr),
        "max_steps": args.max_steps,
        "statistics": stats,
        "trace": trace_entries,
        "tainted_data": tainted_data,
        "timestamp": time.time()
    }
    
    # Save report
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    
    # Print summary
    print("\nDynamic Taint Tracking Results:")
    print(f"Taint locations tracked: {stats['taint_locations']}")
    print(f"Propagations performed: {stats['propagations']}")
    print(f"Report saved to: {args.output}")
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
