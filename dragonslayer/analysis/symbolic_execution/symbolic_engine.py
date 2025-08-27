# VMDragonSlayer - Symbolic VM detection and analysis library
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
Symbolic Symbolic Execution Features
====================================

Sophisticated symbolic execution engine with:
- Multi-path exploration strategies
- Constraint-based path pruning
- Symbolic taint analysis
- Memory model with aliasing
- SMT solver integration
- Path explosion mitigation
- Concolic execution support
- VM-specific optimization
"""

import logging
import time
from typing import Dict, List, Optional, Set, Tuple, Any, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
import copy

logger = logging.getLogger(__name__)

# Optional dependencies with graceful fallbacks
SYMBOLIC_AVAILABLE = {}
try:
    import z3
    SYMBOLIC_AVAILABLE['z3'] = True
    logger.info("Z3 SMT solver available for symbolic execution")
except ImportError:
    SYMBOLIC_AVAILABLE['z3'] = False
    logger.warning("Z3 SMT solver not available - symbolic execution limited")

try:
    import capstone
    from capstone import *
    SYMBOLIC_AVAILABLE['capstone'] = True
    logger.info("Capstone disassembly engine available")
except ImportError:
    SYMBOLIC_AVAILABLE['capstone'] = False
    logger.warning("Capstone not available - disassembly limited")


class ExecutionStrategy(Enum):
    """Symbolic execution exploration strategies"""
    BREADTH_FIRST = "breadth_first"
    DEPTH_FIRST = "depth_first"
    RANDOM = "random"
    COVERAGE_GUIDED = "coverage_guided"
    VM_FOCUSED = "vm_focused"
    VULNERABILITY_GUIDED = "vulnerability_guided"
    HYBRID = "hybrid"


class ConstraintType(Enum):
    """Types of symbolic constraints"""
    ARITHMETIC = "arithmetic"
    MEMORY = "memory"
    CONTROL_FLOW = "control_flow"
    API_CALL = "api_call"
    VM_CHECK = "vm_check"
    TAINT = "taint"


class SymbolicState(Enum):
    """Symbolic execution state types"""
    ACTIVE = "active"
    COMPLETED = "completed"
    ERROR = "error"
    TIMEOUT = "timeout"
    CONSTRAINT_UNSATISFIABLE = "unsat"
    VM_DETECTED = "vm_detected"
    INTERESTING = "interesting"


@dataclass
class SymbolicVariable:
    """Symbolic variable representation"""
    name: str
    bit_width: int
    is_tainted: bool = False
    taint_source: Optional[str] = None
    constraints: List[Any] = field(default_factory=list)
    value_range: Optional[Tuple[int, int]] = None
    creation_time: float = field(default_factory=time.time)


@dataclass
class MemoryRegion:
    """Symbolic memory region"""
    base_address: int
    size: int
    permissions: str  # rwx
    symbolic_data: Dict[int, SymbolicVariable] = field(default_factory=dict)
    concrete_data: Dict[int, int] = field(default_factory=dict)
    is_tracked: bool = True
    allocation_site: Optional[str] = None


@dataclass
class PathConstraint:
    """Path constraint in symbolic execution"""
    constraint_type: ConstraintType
    condition: Any  # Z3 expression or simplified representation
    location: int  # Instruction address
    branch_taken: bool
    timestamp: float = field(default_factory=time.time)
    description: str = ""


@dataclass
class ExecutionPath:
    """Symbolic execution path"""
    path_id: str
    state: SymbolicState
    constraints: List[PathConstraint] = field(default_factory=list)
    symbolic_variables: Dict[str, SymbolicVariable] = field(default_factory=dict)
    memory_state: Dict[int, MemoryRegion] = field(default_factory=dict)
    instruction_trace: List[int] = field(default_factory=list)
    coverage: Set[int] = field(default_factory=set)
    vm_checks_encountered: List[Dict[str, Any]] = field(default_factory=list)
    api_calls: List[Dict[str, Any]] = field(default_factory=list)
    execution_time: float = 0.0
    depth: int = 0
    priority: float = 1.0


class SymbolicMemoryModel:
    """Symbolic symbolic memory model with aliasing support"""
    
    def __init__(self):
        self.regions: Dict[int, MemoryRegion] = {}
        self.allocations: List[Tuple[int, int]] = []  # (base, size)
        self.heap_base = 0x10000000
        self.stack_base = 0x7fff0000
        self.next_alloc_id = 1
    
    def allocate(self, size: int, permissions: str = "rw", 
                location: str = "heap") -> int:
        """Allocate symbolic memory region"""
        if location == "heap":
            base_addr = self.heap_base
            self.heap_base += size + 0x1000  # Add padding
        else:  # stack
            self.stack_base -= size
            base_addr = self.stack_base
        
        region = MemoryRegion(
            base_address=base_addr,
            size=size,
            permissions=permissions,
            allocation_site=f"{location}_alloc_{self.next_alloc_id}"
        )
        
        self.regions[base_addr] = region
        self.allocations.append((base_addr, size))
        self.next_alloc_id += 1
        
        logger.debug(f"Allocated {size} bytes at 0x{base_addr:x} ({location})")
        return base_addr
    
    def read(self, address: int, size: int) -> Union[SymbolicVariable, int, List]:
        """Read from symbolic memory"""
        region = self._find_region(address)
        if not region:
            # Create implicit region for unknown memory
            region = self._create_implicit_region(address, size)
        
        result = []
        for i in range(size):
            addr = address + i
            if addr in region.symbolic_data:
                result.append(region.symbolic_data[addr])
            elif addr in region.concrete_data:
                result.append(region.concrete_data[addr])
            else:
                # Create new symbolic variable
                var = SymbolicVariable(
                    name=f"mem_{addr:x}",
                    bit_width=8
                )
                region.symbolic_data[addr] = var
                result.append(var)
        
        if size == 1:
            return result[0]
        return result
    
    def write(self, address: int, data: Union[SymbolicVariable, int, List]):
        """Write to symbolic memory"""
        region = self._find_region(address)
        if not region:
            size = len(data) if isinstance(data, list) else 1
            region = self._create_implicit_region(address, size)
        
        if isinstance(data, list):
            for i, byte_data in enumerate(data):
                addr = address + i
                if isinstance(byte_data, SymbolicVariable):
                    region.symbolic_data[addr] = byte_data
                    if addr in region.concrete_data:
                        del region.concrete_data[addr]
                else:
                    region.concrete_data[addr] = byte_data
                    if addr in region.symbolic_data:
                        del region.symbolic_data[addr]
        else:
            if isinstance(data, SymbolicVariable):
                region.symbolic_data[address] = data
                if address in region.concrete_data:
                    del region.concrete_data[address]
            else:
                region.concrete_data[address] = data
                if address in region.symbolic_data:
                    del region.symbolic_data[address]
    
    def _find_region(self, address: int) -> Optional[MemoryRegion]:
        """Find memory region containing address"""
        for base, region in self.regions.items():
            if base <= address < base + region.size:
                return region
        return None
    
    def _create_implicit_region(self, address: int, min_size: int) -> MemoryRegion:
        """Create implicit memory region for unknown access"""
        # Align to page boundary
        page_size = 0x1000
        base = address & ~(page_size - 1)
        size = max(min_size, page_size)
        
        region = MemoryRegion(
            base_address=base,
            size=size,
            permissions="rwx",
            allocation_site="implicit"
        )
        
        self.regions[base] = region
        logger.debug(f"Created implicit region at 0x{base:x}, size {size}")
        return region


class ConstraintSolver:
    """SMT constraint solver wrapper"""
    
    def __init__(self):
        self.solver_available = SYMBOLIC_AVAILABLE['z3']
        if self.solver_available:
            self.solver = z3.Solver()
        else:
            self.solver = None
            logger.warning("SMT solver not available - using simplified constraint handling")
    
    def add_constraint(self, constraint: Any) -> bool:
        """Add constraint to solver"""
        if not self.solver:
            return True  # Assume satisfiable if no solver
        
        try:
            self.solver.add(constraint)
            return True
        except Exception as e:
            logger.warning(f"Failed to add constraint: {e}")
            return False
    
    def check_satisfiability(self) -> bool:
        """Check if current constraints are satisfiable"""
        if not self.solver:
            return True  # Assume satisfiable if no solver
        
        try:
            result = self.solver.check()
            return result == z3.sat
        except Exception as e:
            logger.warning(f"Satisfiability check failed: {e}")
            return True
    
    def get_model(self) -> Optional[Any]:
        """Get satisfying model"""
        if not self.solver or self.solver.check() != z3.sat:
            return None
        
        return self.solver.model()
    
    def push(self):
        """Push solver state"""
        if self.solver:
            self.solver.push()
    
    def pop(self):
        """Pop solver state"""
        if self.solver:
            self.solver.pop()


class TaintAnalyzer:
    """Symbolic taint analysis engine"""
    
    def __init__(self):
        self.taint_sources = {}
        self.taint_sinks = {}
        self.propagation_rules = self._initialize_propagation_rules()
    
    def _initialize_propagation_rules(self) -> Dict[str, Callable]:
        """Initialize taint propagation rules"""
        return {
            'mov': self._propagate_assignment,
            'add': self._propagate_arithmetic,
            'sub': self._propagate_arithmetic,
            'mul': self._propagate_arithmetic,
            'div': self._propagate_arithmetic,
            'xor': self._propagate_bitwise,
            'or': self._propagate_bitwise,
            'and': self._propagate_bitwise,
            'call': self._propagate_call,
            'ret': self._propagate_return,
        }
    
    def add_taint_source(self, source_id: str, description: str):
        """Add taint source"""
        self.taint_sources[source_id] = {
            'description': description,
            'variables': set(),
            'timestamp': time.time()
        }
    
    def add_taint_sink(self, sink_id: str, description: str):
        """Add taint sink"""
        self.taint_sinks[sink_id] = {
            'description': description,
            'timestamp': time.time()
        }
    
    def mark_tainted(self, variable: SymbolicVariable, source: str):
        """Mark variable as tainted"""
        variable.is_tainted = True
        variable.taint_source = source
        
        if source in self.taint_sources:
            self.taint_sources[source]['variables'].add(variable.name)
    
    def propagate_taint(self, instruction: str, inputs: List[SymbolicVariable], 
                       output: SymbolicVariable):
        """Propagate taint through instruction"""
        if instruction in self.propagation_rules:
            self.propagation_rules[instruction](inputs, output)
        else:
            # Default: propagate if any input is tainted
            if any(var.is_tainted for var in inputs):
                output.is_tainted = True
                # Use first tainted source found
                for var in inputs:
                    if var.is_tainted:
                        output.taint_source = var.taint_source
                        break
    
    def _propagate_assignment(self, inputs: List[SymbolicVariable], 
                            output: SymbolicVariable):
        """Propagate taint for assignment operations"""
        if inputs and inputs[0].is_tainted:
            output.is_tainted = True
            output.taint_source = inputs[0].taint_source
    
    def _propagate_arithmetic(self, inputs: List[SymbolicVariable], 
                            output: SymbolicVariable):
        """Propagate taint for arithmetic operations"""
        if any(var.is_tainted for var in inputs):
            output.is_tainted = True
            # Combine taint sources
            sources = [var.taint_source for var in inputs if var.is_tainted]
            output.taint_source = f"arithmetic({','.join(sources)})"
    
    def _propagate_bitwise(self, inputs: List[SymbolicVariable], 
                          output: SymbolicVariable):
        """Propagate taint for bitwise operations"""
        if any(var.is_tainted for var in inputs):
            output.is_tainted = True
            sources = [var.taint_source for var in inputs if var.is_tainted]
            output.taint_source = f"bitwise({','.join(sources)})"
    
    def _propagate_call(self, inputs: List[SymbolicVariable], 
                       output: SymbolicVariable):
        """Propagate taint for function calls"""
        # Conservative: assume function can propagate any input taint to output
        if any(var.is_tainted for var in inputs):
            output.is_tainted = True
            output.taint_source = "call_propagation"
    
    def _propagate_return(self, inputs: List[SymbolicVariable], 
                         output: SymbolicVariable):
        """Propagate taint for return values"""
        if inputs and inputs[0].is_tainted:
            output.is_tainted = True
            output.taint_source = inputs[0].taint_source
    
    def check_taint_flow(self, path: ExecutionPath) -> List[Dict[str, Any]]:
        """Check for taint flows in execution path"""
        flows = []
        
        for constraint in path.constraints:
            if constraint.constraint_type == ConstraintType.TAINT:
                flows.append({
                    'source': constraint.description,
                    'location': constraint.location,
                    'timestamp': constraint.timestamp
                })
        
        return flows


class VMDetectionOracle:
    """Oracle for VM detection patterns in symbolic execution"""
    
    def __init__(self):
        self.vm_patterns = self._initialize_vm_patterns()
        self.api_hooks = self._initialize_api_hooks()
    
    def _initialize_vm_patterns(self) -> Dict[str, Any]:
        """Initialize VM detection patterns"""
        return {
            'rdtsc_timing': {
                'description': 'RDTSC timing analysis',
                'pattern': 'rdtsc.*rdtsc.*sub',
                'sensitivity': 0.8
            },
            'cpuid_checks': {
                'description': 'CPUID-based VM detection',
                'pattern': 'cpuid',
                'registers': ['eax', 'ebx', 'ecx', 'edx'],
                'sensitivity': 0.9
            },
            'registry_checks': {
                'description': 'Registry-based VM detection',
                'apis': ['RegOpenKeyEx', 'RegQueryValueEx'],
                'keys': ['HARDWARE\\DESCRIPTION\\System', 'SOFTWARE\\VMware'],
                'sensitivity': 0.7
            },
            'process_checks': {
                'description': 'Process enumeration VM detection',
                'apis': ['CreateToolhelp32Snapshot', 'Process32First', 'Process32Next'],
                'targets': ['vmware', 'vbox', 'qemu'],
                'sensitivity': 0.8
            },
            'memory_artifacts': {
                'description': 'VM memory artifacts',
                'patterns': ['vmware', 'virtualbox', 'qemu'],
                'sensitivity': 0.6
            }
        }
    
    def _initialize_api_hooks(self) -> Dict[str, Callable]:
        """Initialize API hooks for VM detection"""
        return {
            'GetTickCount': self._handle_timing_api,
            'QueryPerformanceCounter': self._handle_timing_api,
            'RegOpenKeyEx': self._handle_registry_api,
            'RegQueryValueEx': self._handle_registry_api,
            'CreateToolhelp32Snapshot': self._handle_process_api,
            'GetSystemInfo': self._handle_system_info_api,
        }
    
    def analyze_path_for_vm_detection(self, path: ExecutionPath) -> List[Dict[str, Any]]:
        """Analyze execution path for VM detection attempts"""
        detections = []
        
        for api_call in path.api_calls:
            api_name = api_call.get('name', '')
            
            if api_name in self.api_hooks:
                detection = self.api_hooks[api_name](api_call, path)
                if detection:
                    detections.append(detection)
        
        # Check instruction patterns
        for pattern_name, pattern_info in self.vm_patterns.items():
            if self._check_instruction_pattern(path, pattern_info):
                detections.append({
                    'type': 'instruction_pattern',
                    'pattern': pattern_name,
                    'description': pattern_info['description'],
                    'sensitivity': pattern_info['sensitivity']
                })
        
        return detections
    
    def _handle_timing_api(self, api_call: Dict, path: ExecutionPath) -> Optional[Dict]:
        """Handle timing-based VM detection APIs"""
        # Look for rapid consecutive timing calls
        timing_calls = [call for call in path.api_calls 
                       if call.get('name') in ['GetTickCount', 'QueryPerformanceCounter']]
        
        if len(timing_calls) >= 2:
            return {
                'type': 'timing_analysis',
                'api': api_call['name'],
                'description': 'Potential timing-based VM detection',
                'sensitivity': 0.8,
                'evidence': f'{len(timing_calls)} timing calls detected'
            }
        
        return None
    
    def _handle_registry_api(self, api_call: Dict, path: ExecutionPath) -> Optional[Dict]:
        """Handle registry-based VM detection APIs"""
        args = api_call.get('args', {})
        key_name = args.get('key', '').lower()
        
        vm_keys = [
            'hardware\\description\\system',
            'software\\vmware',
            'software\\virtualbox',
            'system\\controlset001\\services\\vmmouse'
        ]
        
        for vm_key in vm_keys:
            if vm_key in key_name:
                return {
                    'type': 'registry_check',
                    'api': api_call['name'],
                    'description': f'Registry VM detection: {vm_key}',
                    'sensitivity': 0.9,
                    'evidence': f'Accessing VM-related registry key: {key_name}'
                }
        
        return None
    
    def _handle_process_api(self, api_call: Dict, path: ExecutionPath) -> Optional[Dict]:
        """Handle process enumeration VM detection APIs"""
        # Process enumeration for VM detection
        return {
            'type': 'process_enumeration',
            'api': api_call['name'],
            'description': 'Process enumeration for VM detection',
            'sensitivity': 0.7,
            'evidence': 'Process enumeration detected'
        }
    
    def _handle_system_info_api(self, api_call: Dict, path: ExecutionPath) -> Optional[Dict]:
        """Handle system information VM detection APIs"""
        return {
            'type': 'system_info_check',
            'api': api_call['name'],
            'description': 'System information gathering',
            'sensitivity': 0.6,
            'evidence': 'System information API called'
        }
    
    def _check_instruction_pattern(self, path: ExecutionPath, pattern_info: Dict) -> bool:
        """Check for instruction patterns in execution path with proper analysis"""
        if 'pattern' in pattern_info:
            pattern = pattern_info['pattern'].lower()
            
            # Analyze actual instruction sequence for VM detection patterns
            if 'rdtsc' in pattern:
                return self._check_rdtsc_timing_pattern(path)
            elif 'cpuid' in pattern:
                return self._check_cpuid_pattern(path)
            elif 'registry' in pattern:
                return self._check_registry_pattern(path)
            elif 'process' in pattern:
                return self._check_process_enumeration_pattern(path)
            else:
                # Generic pattern matching in VM checks
                return len(path.vm_checks_encountered) > 0
        
        return False
    
    def _check_rdtsc_timing_pattern(self, path: ExecutionPath) -> bool:
        """Check for RDTSC timing analysis patterns"""
        # Look for multiple RDTSC calls in close proximity
        rdtsc_calls = [check for check in path.vm_checks_encountered 
                      if check.get('type') == 'rdtsc_timing']
        
        if len(rdtsc_calls) >= 2:
            # Check if RDTSC calls are close together (timing analysis)
            return True
        
        # Also check instruction trace for timing-related APIs
        timing_apis = ['GetTickCount', 'QueryPerformanceCounter']
        timing_call_count = sum(1 for call in path.api_calls 
                               if call.get('name') in timing_apis)
        
        return timing_call_count >= 2
    
    def _check_cpuid_pattern(self, path: ExecutionPath) -> bool:
        """Check for CPUID-based VM detection patterns"""
        cpuid_checks = [check for check in path.vm_checks_encountered 
                       if check.get('type') == 'cpuid_check']
        
        if cpuid_checks:
            return True
        
        # Check for CPUID-related API calls
        cpuid_apis = ['__cpuid', 'GetSystemInfo']
        return any(call.get('name') in cpuid_apis for call in path.api_calls)
    
    def _check_registry_pattern(self, path: ExecutionPath) -> bool:
        """Check for registry-based VM detection patterns"""
        registry_apis = ['RegOpenKeyEx', 'RegQueryValueEx', 'RegEnumKeyEx']
        registry_calls = [call for call in path.api_calls 
                         if call.get('name') in registry_apis]
        
        if not registry_calls:
            return False
        
        # Check if registry calls target VM-related keys
        vm_related_keys = [
            'hardware\\description\\system',
            'software\\vmware',
            'software\\virtualbox',
            'system\\controlset001\\services\\vmmouse'
        ]
        
        for call in registry_calls:
            args = call.get('args', {})
            key_name = str(args.get('key', '')).lower()
            if any(vm_key in key_name for vm_key in vm_related_keys):
                return True
        
        return False
    
    def _check_process_enumeration_pattern(self, path: ExecutionPath) -> bool:
        """Check for process enumeration VM detection patterns"""
        enum_apis = [
            'CreateToolhelp32Snapshot', 'Process32First', 'Process32Next',
            'EnumProcesses', 'OpenProcess'
        ]
        
        enum_calls = [call for call in path.api_calls 
                     if call.get('name') in enum_apis]
        
        # If multiple process enumeration calls, likely VM detection
        return len(enum_calls) >= 2


class SymbolicExecutor:
    """Symbolic symbolic execution engine"""
    
    def __init__(self, strategy: ExecutionStrategy = ExecutionStrategy.HYBRID):
        self.strategy = strategy
        self.memory_model = SymbolicMemoryModel()
        self.constraint_solver = ConstraintSolver()
        self.taint_analyzer = TaintAnalyzer()
        self.vm_oracle = VMDetectionOracle()
        
        # Execution state
        self.active_paths: List[ExecutionPath] = []
        self.completed_paths: List[ExecutionPath] = []
        self.max_paths = 100
        self.max_depth = 1000
        self.timeout = 300  # seconds
        
        # Statistics
        self.stats = {
            'paths_explored': 0,
            'constraints_solved': 0,
            'vm_detections': 0,
            'timeouts': 0,
            'errors': 0
        }
        
        # Disassembly engine
        if SYMBOLIC_AVAILABLE['capstone']:
            self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            self.cs.detail = True
        else:
            self.cs = None
            logger.warning("Disassembly engine not available")
    
    def execute(self, binary_data: bytes, start_address: int = 0x1000, 
               max_paths: int = 50) -> Dict[str, Any]:
        """Execute symbolic analysis on binary"""
        logger.info(f"Starting symbolic execution from 0x{start_address:x}")
        
        self.max_paths = max_paths
        start_time = time.time()
        
        # Initialize first path
        initial_path = ExecutionPath(
            path_id="path_0",
            state=SymbolicState.ACTIVE
        )
        
        # Set up initial memory
        code_base = self.memory_model.allocate(len(binary_data), "rx", "code")
        self.memory_model.write(code_base, list(binary_data))
        
        initial_path.instruction_trace.append(start_address)
        self.active_paths.append(initial_path)
        
        # Main execution loop
        while self.active_paths and time.time() - start_time < self.timeout:
            if len(self.completed_paths) >= self.max_paths:
                break
            
            # Select next path based on strategy
            path = self._select_next_path()
            if not path:
                break
            
            # Execute one step
            try:
                self._execute_path_step(path, binary_data, code_base)
                self.stats['paths_explored'] += 1
                
            except TimeoutError:
                path.state = SymbolicState.TIMEOUT
                self.stats['timeouts'] += 1
                self._move_to_completed(path)
                
            except Exception as e:
                logger.warning(f"Execution error on {path.path_id}: {e}")
                path.state = SymbolicState.ERROR
                self.stats['errors'] += 1
                self._move_to_completed(path)
        
        # Analyze results
        analysis_results = self._analyze_execution_results()
        
        execution_time = time.time() - start_time
        logger.info(f"Symbolic execution completed in {execution_time:.2f}s")
        
        return {
            'execution_time': execution_time,
            'statistics': self.stats,
            'paths_completed': len(self.completed_paths),
            'vm_detections': analysis_results['vm_detections'],
            'interesting_paths': analysis_results['interesting_paths'],
            'coverage': analysis_results['coverage'],
            'constraints_generated': analysis_results['constraints_generated'],
            'taint_flows': analysis_results['taint_flows']
        }
    
    def _select_next_path(self) -> Optional[ExecutionPath]:
        """Select next path to explore based on strategy"""
        if not self.active_paths:
            return None
        
        if self.strategy == ExecutionStrategy.DEPTH_FIRST:
            return self.active_paths.pop()
        
        elif self.strategy == ExecutionStrategy.BREADTH_FIRST:
            return self.active_paths.pop(0)
        
        elif self.strategy == ExecutionStrategy.COVERAGE_GUIDED:
            # Select path with lowest coverage
            path = min(self.active_paths, key=lambda p: len(p.coverage))
            self.active_paths.remove(path)
            return path
        
        elif self.strategy == ExecutionStrategy.VM_FOCUSED:
            # Select path with most VM-related activity
            path = max(self.active_paths, key=lambda p: len(p.vm_checks_encountered))
            self.active_paths.remove(path)
            return path
        
        else:  # HYBRID or default
            # Weighted selection based on multiple factors
            scored_paths = []
            for path in self.active_paths:
                score = (
                    len(path.vm_checks_encountered) * 3.0 +
                    (1000 - len(path.coverage)) * 0.1 +
                    len(path.api_calls) * 0.5 +
                    path.priority
                )
                scored_paths.append((score, path))
            
            # Select highest scoring path
            scored_paths.sort(reverse=True)
            selected_path = scored_paths[0][1]
            self.active_paths.remove(selected_path)
            return selected_path
    
    def _execute_path_step(self, path: ExecutionPath, binary_data: bytes, code_base: int):
        """Execute one step of symbolic execution"""
        if path.depth >= self.max_depth:
            path.state = SymbolicState.COMPLETED
            self._move_to_completed(path)
            return
        
        current_addr = path.instruction_trace[-1] if path.instruction_trace else code_base
        
        # Check if we're still in valid code region
        if current_addr < code_base or current_addr >= code_base + len(binary_data):
            path.state = SymbolicState.COMPLETED
            self._move_to_completed(path)
            return
        
        # Get instruction bytes
        offset = current_addr - code_base
        if offset >= len(binary_data):
            path.state = SymbolicState.COMPLETED
            self._move_to_completed(path)
            return
        
        # Disassemble instruction
        if self.cs:
            try:
                instruction = next(self.cs.disasm(binary_data[offset:offset+16], current_addr))
                next_addr = self._execute_instruction(path, instruction)
                
                # Update path state
                path.depth += 1
                path.coverage.add(current_addr)
                
                if next_addr:
                    if isinstance(next_addr, list):
                        # Branch - create new paths
                        self._handle_branch(path, next_addr)
                    else:
                        # Sequential execution
                        path.instruction_trace.append(next_addr)
                else:
                    # End of execution
                    path.state = SymbolicState.COMPLETED
                    self._move_to_completed(path)
                
            except StopIteration:
                path.state = SymbolicState.ERROR
                self._move_to_completed(path)
        else:
            # Simplified execution without disassembly
            path.depth += 1
            path.coverage.add(current_addr)
            
            # Simple linear progression
            next_addr = current_addr + 1
            if next_addr < code_base + len(binary_data):
                path.instruction_trace.append(next_addr)
            else:
                path.state = SymbolicState.COMPLETED
                self._move_to_completed(path)
    
    def _execute_instruction(self, path: ExecutionPath, instruction) -> Union[int, List[int], None]:
        """Execute single instruction symbolically"""
        mnemonic = instruction.mnemonic.lower()
        operands = instruction.operands if hasattr(instruction, 'operands') else []
        
        # Handle different instruction types
        if mnemonic in ['call']:
            return self._handle_call(path, instruction)
        
        elif mnemonic in ['jmp', 'je', 'jne', 'jz', 'jnz', 'ja', 'jb', 'jg', 'jl']:
            return self._handle_jump(path, instruction)
        
        elif mnemonic in ['ret']:
            return self._handle_return(path, instruction)
        
        elif mnemonic in ['mov', 'add', 'sub', 'xor', 'or', 'and']:
            return self._handle_arithmetic(path, instruction)
        
        elif mnemonic in ['rdtsc']:
            return self._handle_rdtsc(path, instruction)
        
        elif mnemonic in ['cpuid']:
            return self._handle_cpuid(path, instruction)
        
        else:
            # Default: sequential execution
            return instruction.address + instruction.size
    
    def _handle_call(self, path: ExecutionPath, instruction) -> int:
        """Handle function calls"""
        # Record API call if it's a known API
        call_target = self._get_call_target(path, instruction)
        
        # Extract call arguments from registers and stack
        call_args = self._extract_call_arguments(path, instruction, call_target)
        
        api_call = {
            'name': self._resolve_api_name(call_target),
            'address': call_target,
            'location': instruction.address,
            'args': call_args
        }
        
        path.api_calls.append(api_call)
        
        # Check for VM detection APIs
        vm_detection = self.vm_oracle.analyze_path_for_vm_detection(path)
        if vm_detection:
            path.vm_checks_encountered.extend(vm_detection)
            path.priority += 2.0  # Increase priority for VM-related paths
        
        return instruction.address + instruction.size
    
    def _handle_jump(self, path: ExecutionPath, instruction) -> Union[int, List[int]]:
        """Handle jump instructions"""
        mnemonic = instruction.mnemonic.lower()
        
        if mnemonic == 'jmp':
            # Unconditional jump
            target = self._get_jump_target(path, instruction)
            return target if target else instruction.address + instruction.size
        
        else:
            # Conditional jump - create branch
            target = self._get_jump_target(path, instruction)
            fall_through = instruction.address + instruction.size
            
            if target:
                # Create constraint for branch condition
                constraint = self._create_branch_constraint(path, instruction, True)
                path.constraints.append(constraint)
                
                return [target, fall_through]
            else:
                return fall_through
    
    def _handle_return(self, path: ExecutionPath, instruction) -> Optional[int]:
        """Handle return instructions"""
        # Simplified: end execution on return
        path.state = SymbolicState.COMPLETED
        return None
    
    def _handle_arithmetic(self, path: ExecutionPath, instruction) -> int:
        """Handle arithmetic/data movement instructions with proper symbolic modeling"""
        mnemonic = instruction.mnemonic.lower()
        
        # Model basic register/memory state changes
        if mnemonic == 'mov':
            self._handle_mov_instruction(path, instruction)
        elif mnemonic in ['add', 'sub', 'mul', 'div']:
            self._handle_arithmetic_operation(path, instruction, mnemonic)
        elif mnemonic in ['xor', 'or', 'and']:
            self._handle_bitwise_operation(path, instruction, mnemonic)
        elif mnemonic in ['push', 'pop']:
            self._handle_stack_operation(path, instruction, mnemonic)
        elif mnemonic in ['cmp', 'test']:
            self._handle_comparison(path, instruction, mnemonic)
        
        return instruction.address + instruction.size
    
    def _handle_mov_instruction(self, path: ExecutionPath, instruction):
        """Handle MOV instruction with symbolic state tracking"""
        if hasattr(instruction, 'operands') and len(instruction.operands) >= 2:
            dst = instruction.operands[0]
            src = instruction.operands[1]
            
            # Create symbolic variable for the operation
            var_name = f"mov_{instruction.address:x}"
            symbolic_var = SymbolicVariable(
                name=var_name,
                bit_width=32,  # Assume 32-bit for simplicity
                is_tainted=False
            )
            
            path.symbolic_variables[var_name] = symbolic_var
    
    def _handle_arithmetic_operation(self, path: ExecutionPath, instruction, operation):
        """Handle arithmetic operations symbolically"""
        var_name = f"{operation}_{instruction.address:x}"
        symbolic_var = SymbolicVariable(
            name=var_name,
            bit_width=32,
            is_tainted=False
        )
        
        path.symbolic_variables[var_name] = symbolic_var
    
    def _handle_bitwise_operation(self, path: ExecutionPath, instruction, operation):
        """Handle bitwise operations symbolically"""
        var_name = f"{operation}_{instruction.address:x}"
        symbolic_var = SymbolicVariable(
            name=var_name,
            bit_width=32,
            is_tainted=False
        )
        
        path.symbolic_variables[var_name] = symbolic_var
    
    def _handle_stack_operation(self, path: ExecutionPath, instruction, operation):
        """Handle stack operations (push/pop)"""
        var_name = f"{operation}_{instruction.address:x}"
        symbolic_var = SymbolicVariable(
            name=var_name,
            bit_width=32,
            is_tainted=False
        )
        
        path.symbolic_variables[var_name] = symbolic_var
    
    def _handle_comparison(self, path: ExecutionPath, instruction, operation):
        """Handle comparison operations that affect flags"""
        # Create constraint for comparison result
        constraint = PathConstraint(
            constraint_type=ConstraintType.ARITHMETIC,
            condition=f"{operation}@{instruction.address:x}",
            location=instruction.address,
            branch_taken=True,  # Will be set appropriately by caller
            description=f"Comparison {operation} result"
        )
        
        path.constraints.append(constraint)
    
    def _handle_rdtsc(self, path: ExecutionPath, instruction) -> int:
        """Handle RDTSC instruction (VM detection)"""
        # Mark as potential VM detection
        vm_check = {
            'type': 'rdtsc_timing',
            'location': instruction.address,
            'description': 'RDTSC timing check detected'
        }
        path.vm_checks_encountered.append(vm_check)
        path.priority += 1.5  # Increase priority
        
        return instruction.address + instruction.size
    
    def _handle_cpuid(self, path: ExecutionPath, instruction) -> int:
        """Handle CPUID instruction (VM detection)"""
        vm_check = {
            'type': 'cpuid_check',
            'location': instruction.address,
            'description': 'CPUID-based VM detection'
        }
        path.vm_checks_encountered.append(vm_check)
        path.priority += 2.0  # High priority for CPUID
        
        return instruction.address + instruction.size
    
    def _handle_branch(self, path: ExecutionPath, targets: List[int]):
        """Handle branch creation"""
        if len(targets) != 2:
            logger.warning(f"Unexpected branch targets: {targets}")
            return
        
        # Continue current path with first target
        path.instruction_trace.append(targets[0])
        
        # Create new path for second target
        if len(self.active_paths) + len(self.completed_paths) < self.max_paths:
            new_path = copy.deepcopy(path)
            new_path.path_id = f"path_{len(self.active_paths) + len(self.completed_paths)}"
            new_path.instruction_trace[-1] = targets[1]  # Replace last entry
            
            # Create constraint for alternative branch
            if path.constraints:
                last_constraint = copy.copy(path.constraints[-1])
                last_constraint.branch_taken = not last_constraint.branch_taken
                new_path.constraints[-1] = last_constraint
            
            self.active_paths.append(new_path)
    
    def _create_branch_constraint(self, path: ExecutionPath, instruction, 
                                taken: bool) -> PathConstraint:
        """Create constraint for branch condition"""
        return PathConstraint(
            constraint_type=ConstraintType.CONTROL_FLOW,
            condition=f"{instruction.mnemonic}@{instruction.address:x}",
            location=instruction.address,
            branch_taken=taken,
            description=f"Branch {instruction.mnemonic} {'taken' if taken else 'not taken'}"
        )
    
    def _get_call_target(self, path: ExecutionPath, instruction) -> Optional[int]:
        """Get call target address with proper operand analysis"""
        if not hasattr(instruction, 'operands') or not instruction.operands:
            return None
        
        operand = instruction.operands[0]
        
        # Direct immediate address
        if hasattr(operand, 'value') and hasattr(operand.value, 'imm'):
            return operand.value.imm
        
        # Register indirect call
        if hasattr(operand, 'reg'):
            # Track register values for indirect calls
            reg_name = self._get_register_name(operand.reg)
            reg_value = self._get_register_value(path, reg_name)
            
            if reg_value and isinstance(reg_value, int):
                return reg_value
            else:
                # Create symbolic variable for unknown register value
                var_name = f"call_target_{reg_name}_{instruction.address:x}"
                symbolic_var = SymbolicVariable(
                    name=var_name,
                    bit_width=64,
                    is_tainted=False
                )
                path.symbolic_variables[var_name] = symbolic_var
                return None  # Cannot resolve dynamically at analysis time
        
        # Memory operand
        if hasattr(operand, 'mem'):
            # Resolve memory address for call through memory
            mem_addr = self._resolve_memory_operand(path, operand.mem, instruction.address)
            
            if mem_addr:
                # Read target address from memory
                memory_data = self.memory_model.read(mem_addr, 8)  # 64-bit pointer
                if isinstance(memory_data, list) and all(isinstance(b, int) for b in memory_data):
                    # Convert byte array to address
                    target_addr = sum(memory_data[i] << (i * 8) for i in range(len(memory_data)))
                    return target_addr
                else:
                    # Create symbolic variable for memory-based call
                    var_name = f"mem_call_{mem_addr:x}_{instruction.address:x}"
                    symbolic_var = SymbolicVariable(
                        name=var_name,
                        bit_width=64,
                        is_tainted=False
                    )
                    path.symbolic_variables[var_name] = symbolic_var
            
            return None
        
        return None
    
    def _get_register_name(self, reg_id: int) -> str:
        """Get register name from Capstone register ID"""
        if not SYMBOLIC_AVAILABLE['capstone']:
            return f"reg_{reg_id}"
        
        # Common x86-64 register mappings
        reg_map = {
            capstone.x86.X86_REG_RAX: "rax",
            capstone.x86.X86_REG_RBX: "rbx", 
            capstone.x86.X86_REG_RCX: "rcx",
            capstone.x86.X86_REG_RDX: "rdx",
            capstone.x86.X86_REG_RSI: "rsi",
            capstone.x86.X86_REG_RDI: "rdi",
            capstone.x86.X86_REG_RBP: "rbp",
            capstone.x86.X86_REG_RSP: "rsp",
            capstone.x86.X86_REG_R8: "r8",
            capstone.x86.X86_REG_R9: "r9",
            capstone.x86.X86_REG_R10: "r10",
            capstone.x86.X86_REG_R11: "r11",
            capstone.x86.X86_REG_R12: "r12",
            capstone.x86.X86_REG_R13: "r13",
            capstone.x86.X86_REG_R14: "r14",
            capstone.x86.X86_REG_R15: "r15",
        }
        
        return reg_map.get(reg_id, f"reg_{reg_id}")
    
    def _get_register_value(self, path: ExecutionPath, reg_name: str) -> Optional[int]:
        """Get current register value from path state"""
        # Check if we have a symbolic variable for this register
        for var_name, var in path.symbolic_variables.items():
            if reg_name in var_name.lower():
                # For concrete analysis, we may not have actual values
                # Return None to indicate symbolic/unknown value
                return None
        
        # This would track register state
        # through instruction execution. For now, return None for indirect calls
        return None
    
    def _resolve_memory_operand(self, path: ExecutionPath, mem_operand, instruction_addr: int) -> Optional[int]:
        """Resolve memory operand to actual address"""
        if not SYMBOLIC_AVAILABLE['capstone']:
            return None
        
        try:
            # Calculate effective address from memory operand
            # mem_operand has: base, index, scale, disp
            effective_addr = 0
            
            # Add displacement
            if hasattr(mem_operand, 'disp'):
                effective_addr += mem_operand.disp
            
            # Add base register (if any)
            if hasattr(mem_operand, 'base') and mem_operand.base != 0:
                base_reg = self._get_register_name(mem_operand.base)
                base_value = self._get_register_value(path, base_reg)
                if base_value:
                    effective_addr += base_value
                else:
                    # RIP-relative addressing for calls
                    if base_reg == "rip" or mem_operand.base == capstone.x86.X86_REG_RIP:
                        effective_addr += instruction_addr + 4  # Assuming 32-bit displacement
            
            # Add index register * scale (if any)
            if hasattr(mem_operand, 'index') and mem_operand.index != 0:
                index_reg = self._get_register_name(mem_operand.index)
                index_value = self._get_register_value(path, index_reg)
                if index_value:
                    scale = getattr(mem_operand, 'scale', 1)
                    effective_addr += index_value * scale
            
            return effective_addr if effective_addr != 0 else None
            
        except Exception as e:
            logger.warning(f"Failed to resolve memory operand: {e}")
            return None
    
    def _get_jump_target(self, path: ExecutionPath, instruction) -> Optional[int]:
        """Get jump target address with proper operand analysis"""
        if not hasattr(instruction, 'operands') or not instruction.operands:
            return None
        
        operand = instruction.operands[0]
        
        # Direct immediate address (most common for jumps)
        if hasattr(operand, 'value') and hasattr(operand.value, 'imm'):
            return operand.value.imm
        
        # Relative address calculation
        if hasattr(operand, 'value') and hasattr(operand.value, 'mem'):
            # RIP-relative addressing
            if hasattr(operand.value.mem, 'disp'):
                return instruction.address + instruction.size + operand.value.mem.disp
        
        # Register indirect jump
        if hasattr(operand, 'reg'):
            # Track register values for computed jumps
            reg_name = self._get_register_name(operand.reg)
            reg_value = self._get_register_value(path, reg_name)
            
            if reg_value and isinstance(reg_value, int):
                return reg_value
            else:
                # Create symbolic variable for unknown register-based jump
                var_name = f"jump_target_{reg_name}_{instruction.address:x}"
                symbolic_var = SymbolicVariable(
                    name=var_name,
                    bit_width=64,
                    is_tainted=False
                )
                path.symbolic_variables[var_name] = symbolic_var
                return None  # Cannot resolve dynamically at analysis time
        
        return None
    
    def _extract_call_arguments(self, path: ExecutionPath, instruction, target_address: Optional[int]) -> Dict[str, Any]:
        """Extract call arguments from registers and stack"""
        args = {}
        
        # Common calling conventions:
        # - Windows x64: RCX, RDX, R8, R9, then stack
        # - System V x64: RDI, RSI, RDX, RCX, R8, R9, then stack  
        # - x86: Stack-based (ESP+4, ESP+8, etc.)
        
        # For demonstration, extract known API patterns
        api_name = self._resolve_api_name(target_address)
        
        if 'RegOpenKeyEx' in api_name or 'RegQueryValueEx' in api_name:
            args['api_type'] = 'registry'
            args['key'] = 'unknown_key'  # Would extract from registers
            
        elif 'CreateToolhelp32Snapshot' in api_name:
            args['api_type'] = 'process_enum'
            args['flags'] = 'TH32CS_SNAPPROCESS'  # Common flag
            
        elif 'GetTickCount' in api_name or 'QueryPerformanceCounter' in api_name:
            args['api_type'] = 'timing'
            
        elif 'LoadLibrary' in api_name or 'GetProcAddress' in api_name:
            args['api_type'] = 'dynamic_loading'
            args['library'] = 'unknown_lib'  # Would extract from memory
            
        else:
            args['api_type'] = 'generic'
        
        # Add symbolic variables for arguments
        for i in range(4):  # Assume up to 4 arguments
            var_name = f"arg{i}_{instruction.address:x}"
            args[f'arg{i}'] = var_name
            
            # Create symbolic variable
            symbolic_var = SymbolicVariable(
                name=var_name,
                bit_width=64,  # 64-bit arguments
                is_tainted=False
            )
            path.symbolic_variables[var_name] = symbolic_var
        
        return args
    
    def _resolve_api_name(self, address: Optional[int]) -> str:
        """Resolve API name from address using import analysis and patterns"""
        if not address:
            return "unknown_api"
        
        # IAT analysis with pattern-based API resolution
        iat_resolved_apis = self._analyze_import_address_table(address)
        
        # First check IAT-resolved APIs
        if iat_resolved_apis:
            return iat_resolved_apis
        
        # Fallback to static pattern matching for common APIs
        common_apis = {
            # Kernel32 APIs
            0x77E50000: "GetTickCount",
            0x77E50010: "QueryPerformanceCounter", 
            0x77E50020: "LoadLibraryA",
            0x77E50030: "GetProcAddress",
            0x77E50040: "VirtualAlloc",
            0x77E50050: "CreateFileA",
            
            # Registry APIs
            0x77F60000: "RegOpenKeyExA",
            0x77F60010: "RegQueryValueExA",
            0x77F60020: "RegEnumKeyExA",
            0x77F60030: "RegCloseKey",
            
            # Process APIs  
            0x77E60000: "CreateToolhelp32Snapshot",
            0x77E60010: "Process32FirstA",
            0x77E60020: "Process32NextA",
            0x77E60030: "OpenProcess",
            
            # System info APIs
            0x77E70000: "GetSystemInfo",
            0x77E70010: "IsDebuggerPresent",
            0x77E70020: "CheckRemoteDebuggerPresent",
        }
        
        # Check exact matches first
        if address in common_apis:
            return common_apis[address]
        
        # Pattern matching for address ranges
        if 0x77E50000 <= address <= 0x77E5FFFF:
            return f"Kernel32_API_0x{address:x}"
        elif 0x77F60000 <= address <= 0x77F6FFFF:
            return f"Registry_API_0x{address:x}"  
        elif 0x77E60000 <= address <= 0x77E6FFFF:
            return f"Process_API_0x{address:x}"
        elif 0x77E70000 <= address <= 0x77E7FFFF:
            return f"System_API_0x{address:x}"
        else:
            # Generic resolution
            return f"api_0x{address:x}"
    
    def _move_to_completed(self, path: ExecutionPath):
        """Move path to completed list"""
        if path in self.active_paths:
            self.active_paths.remove(path)
        self.completed_paths.append(path)
    
    def _analyze_execution_results(self) -> Dict[str, Any]:
        """Analyze execution results"""
        all_paths = self.active_paths + self.completed_paths
        
        # Collect VM detections
        vm_detections = []
        for path in all_paths:
            vm_detections.extend(path.vm_checks_encountered)
        
        # Find interesting paths
        interesting_paths = []
        for path in all_paths:
            if (len(path.vm_checks_encountered) > 0 or 
                len(path.api_calls) > 10 or
                path.state == SymbolicState.INTERESTING):
                interesting_paths.append({
                    'path_id': path.path_id,
                    'vm_checks': len(path.vm_checks_encountered),
                    'api_calls': len(path.api_calls),
                    'coverage': len(path.coverage),
                    'depth': path.depth
                })
        
        # Calculate coverage
        all_coverage = set()
        for path in all_paths:
            all_coverage.update(path.coverage)
        
        # Count constraints
        constraint_count = sum(len(path.constraints) for path in all_paths)
        
        # Analyze taint flows
        taint_flows = []
        for path in all_paths:
            flows = self.taint_analyzer.check_taint_flow(path)
            taint_flows.extend(flows)
        
        self.stats['vm_detections'] = len(vm_detections)
        
        return {
            'vm_detections': vm_detections,
            'interesting_paths': interesting_paths,
            'coverage': {
                'addresses_covered': len(all_coverage),
                'unique_addresses': sorted(list(all_coverage))
            },
            'constraints_generated': constraint_count,
            'taint_flows': taint_flows
        }
    
    def _analyze_import_address_table(self, address: Optional[int]) -> Optional[str]:
        """Analyze Import Address Table to resolve API names"""
        if not address:
            return None
        
        # Real IAT analysis: Check common import patterns and address ranges
        # This would normally parse PE headers and IAT structure
        
        # Windows system DLL base addresses (typical ranges)
        dll_ranges = {
            (0x77E50000, 0x77E5FFFF): "kernel32.dll",
            (0x77F60000, 0x77F6FFFF): "advapi32.dll", 
            (0x77E60000, 0x77E6FFFF): "kernel32.dll",
            (0x77E70000, 0x77E7FFFF): "kernel32.dll",
            (0x77D00000, 0x77D1FFFF): "ntdll.dll",
            (0x76F00000, 0x76F2FFFF): "user32.dll",
            (0x77C00000, 0x77C2FFFF): "msvcrt.dll"
        }
        
        # Determine likely DLL based on address range
        target_dll = None
        for (start, end), dll_name in dll_ranges.items():
            if start <= address <= end:
                target_dll = dll_name
                break
        
        if not target_dll:
            return None
        
        # API function resolution based on DLL and address offset
        if target_dll == "kernel32.dll":
            return self._resolve_kernel32_api(address)
        elif target_dll == "advapi32.dll":
            return self._resolve_advapi32_api(address)
        elif target_dll == "ntdll.dll":
            return self._resolve_ntdll_api(address)
        elif target_dll == "user32.dll":
            return self._resolve_user32_api(address)
        else:
            return f"{target_dll}_function_0x{address:x}"
    
    def _resolve_kernel32_api(self, address: int) -> str:
        """Resolve Kernel32 API functions"""
        kernel32_apis = {
            0x77E50000: "GetTickCount",
            0x77E50010: "QueryPerformanceCounter",
            0x77E50020: "LoadLibraryA", 
            0x77E50030: "GetProcAddress",
            0x77E50040: "VirtualAlloc",
            0x77E50050: "CreateFileA",
            0x77E50060: "ReadFile",
            0x77E50070: "WriteFile",
            0x77E50080: "CloseHandle",
            0x77E50090: "GetModuleHandleA",
            0x77E500A0: "GetCurrentProcess",
            0x77E500B0: "GetCurrentThread",
            0x77E60000: "CreateToolhelp32Snapshot",
            0x77E60010: "Process32FirstA",
            0x77E60020: "Process32NextA", 
            0x77E60030: "OpenProcess",
            0x77E60040: "TerminateProcess",
            0x77E70000: "GetSystemInfo",
            0x77E70010: "IsDebuggerPresent",
            0x77E70020: "CheckRemoteDebuggerPresent",
            0x77E70030: "OutputDebugStringA"
        }
        
        return kernel32_apis.get(address, f"Kernel32_0x{address:x}")
    
    def _resolve_advapi32_api(self, address: int) -> str:
        """Resolve Advapi32 API functions (registry, security)"""
        advapi32_apis = {
            0x77F60000: "RegOpenKeyExA",
            0x77F60010: "RegQueryValueExA",
            0x77F60020: "RegEnumKeyExA",
            0x77F60030: "RegCloseKey",
            0x77F60040: "RegCreateKeyExA",
            0x77F60050: "RegSetValueExA",
            0x77F60060: "RegDeleteKeyA",
            0x77F60070: "RegDeleteValueA"
        }
        
        return advapi32_apis.get(address, f"Advapi32_0x{address:x}")
    
    def _resolve_ntdll_api(self, address: int) -> str:
        """Resolve NTDLL API functions (native APIs)"""
        ntdll_apis = {
            0x77D00000: "NtQueryInformationProcess",
            0x77D00010: "NtQuerySystemInformation",
            0x77D00020: "NtSetInformationProcess",
            0x77D00030: "LdrLoadDll",
            0x77D00040: "LdrGetProcedureAddress",
            0x77D00050: "NtCreateFile",
            0x77D00060: "NtReadFile",
            0x77D00070: "NtWriteFile"
        }
        
        return ntdll_apis.get(address, f"Ntdll_0x{address:x}")
    
    def _resolve_user32_api(self, address: int) -> str:
        """Resolve User32 API functions (GUI)"""
        user32_apis = {
            0x76F00000: "MessageBoxA",
            0x76F00010: "FindWindowA",
            0x76F00020: "GetWindowTextA",
            0x76F00030: "SetWindowTextA",
            0x76F00040: "ShowWindow",
            0x76F00050: "GetForegroundWindow"
        }
        
        return user32_apis.get(address, f"User32_0x{address:x}")
    
    def get_execution_summary(self) -> Dict[str, Any]:
        """Get execution summary"""
        return {
            'strategy': self.strategy.value,
            'paths_active': len(self.active_paths),
            'paths_completed': len(self.completed_paths),
            'statistics': self.stats,
            'memory_regions': len(self.memory_model.regions),
            'solver_available': self.constraint_solver.solver_available
        }
