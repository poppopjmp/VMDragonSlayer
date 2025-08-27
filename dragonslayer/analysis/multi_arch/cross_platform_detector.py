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
Multi-Architecture Support
==========================

Cross-platform VM detection supporting multiple CPU architectures:
- x86/x64 (Intel/AMD)
- ARM32/ARM64 (AArch32/AArch64)
- MIPS32/MIPS64
- PowerPC
- RISC-V
- SPARC
"""

import logging
import struct
from typing import Dict, List, Optional, Set, Any, Union
from dataclasses import dataclass
from enum import Enum
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class Architecture(Enum):
    """Supported CPU architectures"""
    X86 = "x86"
    X64 = "x64"
    ARM32 = "arm32"
    ARM64 = "arm64"
    MIPS32 = "mips32"
    MIPS64 = "mips64"
    POWERPC32 = "ppc32"
    POWERPC64 = "ppc64"
    RISCV32 = "riscv32"
    RISCV64 = "riscv64"
    SPARC = "sparc"
    SPARC64 = "sparc64"


class Endianness(Enum):
    """Byte order"""
    LITTLE = "little"
    BIG = "big"


@dataclass
class ArchitectureProfile:
    """Architecture-specific configuration"""
    arch: Architecture
    endianness: Endianness
    word_size: int  # in bytes
    instruction_alignment: int
    max_instruction_size: int
    common_registers: List[str]
    stack_pointer: str
    frame_pointer: str
    return_address_register: Optional[str] = None
    
    # VM-specific characteristics
    vm_dispatcher_patterns: List[bytes] = None
    vm_handler_signatures: List[bytes] = None
    virtualization_instructions: Set[str] = None
    
    def __post_init__(self):
        if self.vm_dispatcher_patterns is None:
            self.vm_dispatcher_patterns = []
        if self.vm_handler_signatures is None:
            self.vm_handler_signatures = []
        if self.virtualization_instructions is None:
            self.virtualization_instructions = set()


class ArchitectureDetector:
    """Automatic architecture detection from binary data"""
    
    def __init__(self):
        self.magic_signatures = self._initialize_magic_signatures()
        self.instruction_patterns = self._initialize_instruction_patterns()
    
    def _initialize_magic_signatures(self) -> Dict[Architecture, List[bytes]]:
        """Magic bytes for different architectures"""
        return {
            Architecture.X86: [
                b'\x7fELF\x01\x01',     # ELF 32-bit LSB
                b'MZ',                  # PE/DOS header
            ],
            Architecture.X64: [
                b'\x7fELF\x02\x01',     # ELF 64-bit LSB
                b'MZ\x90\x00\x03',     # PE64 header
            ],
            Architecture.ARM32: [
                b'\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00',  # ARM ELF
            ],
            Architecture.ARM64: [
                b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xb7\x00',  # AArch64 ELF
            ],
            Architecture.MIPS32: [
                b'\x7fELF\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x08',  # MIPS ELF BE
                b'\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x08\x00',  # MIPS ELF LE
            ],
            Architecture.POWERPC32: [
                b'\x7fELF\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x14',  # PowerPC ELF
            ]
        }
    
    def _initialize_instruction_patterns(self) -> Dict[Architecture, List[bytes]]:
        """Common instruction patterns for each architecture"""
        return {
            Architecture.X86: [
                b'\x55\x8b\xec',       # push ebp; mov ebp, esp
                b'\x83\xec',           # sub esp, imm8
                b'\xc3',               # ret
            ],
            Architecture.X64: [
                b'\x48\x89\x5c\x24',   # mov [rsp+...], rbx
                b'\x48\x83\xec',       # sub rsp, imm8
                b'\xc3',               # ret
            ],
            Architecture.ARM32: [
                b'\x1e\xff\x2f\xe1',   # bx lr
                b'\x04\xe0\x2d\xe5',   # push {lr}
                b'\x04\xe0\x9d\xe4',   # pop {lr}
            ],
            Architecture.ARM64: [
                b'\xc0\x03\x5f\xd6',   # ret
                b'\xff\x03\x01\xd1',   # sub sp, sp, #64
                b'\xff\x43\x00\x91',   # add sp, sp, #16
            ],
            Architecture.MIPS32: [
                b'\x08\x00\xe0\x03',   # jr ra
                b'\x25\x08\x20\x00',   # move at, zero
                b'\x21\x10\x80\x00',   # move v0, a0
            ]
        }
    
    def detect_architecture(self, binary_data: bytes) -> Optional[ArchitectureProfile]:
        """Detect architecture from binary data"""
        if len(binary_data) < 64:
            return None
        
        # Check magic signatures first
        detected_arch = self._check_magic_signatures(binary_data)
        if detected_arch:
            return self._create_architecture_profile(detected_arch, binary_data)
        
        # Fallback to instruction pattern analysis
        detected_arch = self._analyze_instruction_patterns(binary_data)
        if detected_arch:
            return self._create_architecture_profile(detected_arch, binary_data)
        
        return None
    
    def _check_magic_signatures(self, data: bytes) -> Optional[Architecture]:
        """Check for magic bytes/signatures"""
        for arch, signatures in self.magic_signatures.items():
            for signature in signatures:
                if data.startswith(signature):
                    return arch
        return None
    
    def _analyze_instruction_patterns(self, data: bytes) -> Optional[Architecture]:
        """Analyze instruction patterns to determine architecture"""
        pattern_scores = {}
        
        for arch, patterns in self.instruction_patterns.items():
            score = 0
            for pattern in patterns:
                count = data.count(pattern)
                score += count
            pattern_scores[arch] = score
        
        if pattern_scores:
            best_match = max(pattern_scores, key=pattern_scores.get)
            if pattern_scores[best_match] > 0:
                return best_match
        
        return None
    
    def _create_architecture_profile(self, arch: Architecture, data: bytes) -> ArchitectureProfile:
        """Create architecture profile with detected parameters"""
        endianness = self._detect_endianness(data)
        
        # Architecture-specific profiles
        profiles = {
            Architecture.X86: ArchitectureProfile(
                arch=Architecture.X86,
                endianness=Endianness.LITTLE,
                word_size=4,
                instruction_alignment=1,
                max_instruction_size=15,
                common_registers=['eax', 'ebx', 'ecx', 'edx', 'esp', 'ebp', 'esi', 'edi'],
                stack_pointer='esp',
                frame_pointer='ebp',
                vm_dispatcher_patterns=[
                    b'\xff\x24\x85',      # jmp [eax*4+disp32]
                    b'\x8b\x04\x85',      # mov eax, [eax*4+disp32]
                ]
            ),
            Architecture.X64: ArchitectureProfile(
                arch=Architecture.X64,
                endianness=Endianness.LITTLE,
                word_size=8,
                instruction_alignment=1,
                max_instruction_size=15,
                common_registers=['rax', 'rbx', 'rcx', 'rdx', 'rsp', 'rbp', 'rsi', 'rdi'],
                stack_pointer='rsp',
                frame_pointer='rbp',
                vm_dispatcher_patterns=[
                    b'\x48\xff\x24\xc5',  # jmp [rax*8+disp32]
                    b'\x48\x8b\x04\xc5',  # mov rax, [rax*8+disp32]
                ]
            ),
            Architecture.ARM32: ArchitectureProfile(
                arch=Architecture.ARM32,
                endianness=endianness,
                word_size=4,
                instruction_alignment=4,
                max_instruction_size=4,
                common_registers=['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc'],
                stack_pointer='sp',
                frame_pointer='r11',
                return_address_register='lr',
                vm_dispatcher_patterns=[
                    b'\x00\xf0\x90\xe5',  # ldr pc, [r0, r0]
                    b'\x82\x00\xa0\xe1',  # mov r0, r2, lsl #1
                ]
            ),
            Architecture.ARM64: ArchitectureProfile(
                arch=Architecture.ARM64,
                endianness=Endianness.LITTLE,
                word_size=8,
                instruction_alignment=4,
                max_instruction_size=4,
                common_registers=['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15', 'x16', 'x17', 'x18', 'x19', 'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'x30', 'sp'],
                stack_pointer='sp',
                frame_pointer='x29',
                return_address_register='x30',
                vm_dispatcher_patterns=[
                    b'\x00\x00\x40\xf9',  # ldr x0, [x0]
                    b'\x00\x00\x1f\xd6',  # br x0
                ]
            ),
            Architecture.MIPS32: ArchitectureProfile(
                arch=Architecture.MIPS32,
                endianness=endianness,
                word_size=4,
                instruction_alignment=4,
                max_instruction_size=4,
                common_registers=['$zero', '$at', '$v0', '$v1', '$a0', '$a1', '$a2', '$a3', '$t0', '$t1', '$t2', '$t3', '$t4', '$t5', '$t6', '$t7', '$s0', '$s1', '$s2', '$s3', '$s4', '$s5', '$s6', '$s7', '$t8', '$t9', '$k0', '$k1', '$gp', '$sp', '$fp', '$ra'],
                stack_pointer='$sp',
                frame_pointer='$fp',
                return_address_register='$ra',
                vm_dispatcher_patterns=[
                    b'\x08\x00\x20\x00',  # jr $at (big endian)
                    b'\x00\x20\x00\x08',  # jr $at (little endian)
                ]
            )
        }
        
        return profiles.get(arch, self._create_generic_profile(arch, endianness))
    
    def _detect_endianness(self, data: bytes) -> Endianness:
        """Detect byte order from binary data"""
        if len(data) >= 4:
            # Check ELF header
            if data.startswith(b'\x7fELF'):
                if len(data) > 5:
                    return Endianness.LITTLE if data[5] == 1 else Endianness.BIG
        
        # Default to little endian (most common)
        return Endianness.LITTLE
    
    def _create_generic_profile(self, arch: Architecture, endianness: Endianness) -> ArchitectureProfile:
        """Create generic profile for unknown architectures"""
        return ArchitectureProfile(
            arch=arch,
            endianness=endianness,
            word_size=4,  # Default
            instruction_alignment=4,
            max_instruction_size=8,
            common_registers=[],
            stack_pointer='sp',
            frame_pointer='fp'
        )


class CrossArchitectureVMDetector:
    """VM detection engine supporting multiple architectures"""
    
    def __init__(self):
        self.arch_detector = ArchitectureDetector()
        self.vm_patterns = self._initialize_cross_arch_patterns()
        self.disassemblers = self._initialize_disassemblers()
    
    def _initialize_cross_arch_patterns(self) -> Dict[Architecture, Dict[str, List[bytes]]]:
        """Initialize VM patterns for each architecture"""
        return {
            Architecture.X86: {
                'vm_entry': [
                    b'\x60\x9c',                    # pushad; pushfd
                    b'\xe8\x00\x00\x00\x00\x58',   # call $+5; pop eax
                ],
                'vm_dispatcher': [
                    b'\xff\x24\x85',               # jmp [eax*4+disp32]
                    b'\xff\xe0',                    # jmp eax
                ],
                'vm_exit': [
                    b'\x9d\x61',                    # popfd; popad
                    b'\xc3',                        # ret
                ]
            },
            Architecture.ARM32: {
                'vm_entry': [
                    b'\x00\x48\x2d\xe9',           # push {r11, lr}
                    b'\x0d\xb0\xa0\xe1',           # mov r11, sp
                ],
                'vm_dispatcher': [
                    b'\x00\xf0\x90\xe5',           # ldr pc, [r0, r0]
                    b'\x10\xff\x2f\xe1',           # bx r0
                ],
                'vm_exit': [
                    b'\x00\x88\xbd\xe8',           # pop {r11, pc}
                    b'\x1e\xff\x2f\xe1',           # bx lr
                ]
            },
            Architecture.ARM64: {
                'vm_entry': [
                    b'\xff\x43\x00\xd1',           # sub sp, sp, #16
                    b'\xfd\x7b\x00\xa9',           # stp x29, x30, [sp]
                ],
                'vm_dispatcher': [
                    b'\x00\x00\x40\xf9',           # ldr x0, [x0]
                    b'\x00\x00\x1f\xd6',           # br x0
                ],
                'vm_exit': [
                    b'\xfd\x7b\x40\xa9',           # ldp x29, x30, [sp]
                    b'\xff\x43\x00\x91',           # add sp, sp, #16
                    b'\xc0\x03\x5f\xd6',           # ret
                ]
            },
            Architecture.MIPS32: {
                'vm_entry': [
                    b'\x27\xbd\xff\xf0',           # addiu sp, sp, -16
                    b'\xaf\xbf\x00\x0c',           # sw ra, 12(sp)
                ],
                'vm_dispatcher': [
                    b'\x08\x00\x20\x00',           # jr at
                    b'\x00\x00\x00\x00',           # nop (delay slot)
                ],
                'vm_exit': [
                    b'\x8f\xbf\x00\x0c',           # lw ra, 12(sp)
                    b'\x27\xbd\x00\x10',           # addiu sp, sp, 16
                    b'\x03\xe0\x00\x08',           # jr ra
                ]
            }
        }
    
    def _initialize_disassemblers(self) -> Dict[Architecture, Any]:
        """Initialize architecture-specific disassemblers"""
        disassemblers = {}
        
        try:
            import capstone as cs
            
            disassemblers[Architecture.X86] = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
            disassemblers[Architecture.X64] = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
            disassemblers[Architecture.ARM32] = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_ARM)
            disassemblers[Architecture.ARM64] = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)
            disassemblers[Architecture.MIPS32] = cs.Cs(cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32)
            
            # Enable detailed instruction info
            for disasm in disassemblers.values():
                disasm.detail = True
                
            logger.info("Capstone disassemblers initialized for cross-architecture support")
            
        except ImportError:
            logger.warning("Capstone not available - disassembly features limited")
        
        return disassemblers
    
    def detect_vm_protection(self, binary_data: bytes) -> Dict[str, Any]:
        """Detect VM protection across all supported architectures"""
        # First detect the architecture
        arch_profile = self.arch_detector.detect_architecture(binary_data)
        if not arch_profile:
            return {'error': 'Unable to detect architecture'}
        
        logger.info(f"Detected architecture: {arch_profile.arch.value}")
        
        # Perform architecture-specific VM detection
        vm_results = self._detect_vm_for_architecture(binary_data, arch_profile)
        
        # Add cross-architecture analysis
        cross_arch_results = self._perform_cross_architecture_analysis(binary_data)
        
        return {
            'detected_architecture': arch_profile.arch.value,
            'endianness': arch_profile.endianness.value,
            'word_size': arch_profile.word_size,
            'vm_detection_results': vm_results,
            'cross_architecture_analysis': cross_arch_results,
            'confidence_score': self._calculate_confidence_score(vm_results, cross_arch_results)
        }
    
    def _detect_vm_for_architecture(self, data: bytes, profile: ArchitectureProfile) -> Dict[str, Any]:
        """Perform VM detection for specific architecture"""
        arch = profile.arch
        patterns = self.vm_patterns.get(arch, {})
        
        results = {
            'vm_entry_patterns': [],
            'vm_dispatcher_patterns': [],
            'vm_exit_patterns': [],
            'vm_handler_candidates': [],
            'instruction_analysis': {}
        }
        
        # Search for VM patterns
        for pattern_type, pattern_list in patterns.items():
            matches = []
            for pattern in pattern_list:
                offset = 0
                while offset < len(data) - len(pattern):
                    if data[offset:offset+len(pattern)] == pattern:
                        matches.append({
                            'offset': offset,
                            'pattern': pattern.hex(),
                            'context': data[max(0, offset-16):offset+len(pattern)+16].hex()
                        })
                        offset += len(pattern)
                    else:
                        offset += 1
            results[pattern_type] = matches
        
        # Perform disassembly if available
        if arch in self.disassemblers:
            results['instruction_analysis'] = self._analyze_instructions(
                data, self.disassemblers[arch], profile
            )
        
        return results
    
    def _perform_cross_architecture_analysis(self, data: bytes) -> Dict[str, Any]:
        """Analyze binary for multi-architecture VM characteristics"""
        results = {
            'architecture_mixing': False,
            'emulation_layers': [],
            'vm_nesting_evidence': [],
            'polymorphic_indicators': []
        }
        
        # Check for multiple architecture signatures
        arch_signatures = {}
        for arch, signatures in self.arch_detector.magic_signatures.items():
            for signature in signatures:
                if signature in data:
                    if arch not in arch_signatures:
                        arch_signatures[arch] = []
                    arch_signatures[arch].append(signature)
        
        if len(arch_signatures) > 1:
            results['architecture_mixing'] = True
            results['mixed_architectures'] = list(arch_signatures.keys())
        
        # Look for emulation layer indicators
        emulation_patterns = [
            b'qemu',
            b'bochs',
            b'vmware',
            b'virtualbox',
            b'kvm',
            b'xen'
        ]
        
        for pattern in emulation_patterns:
            if pattern.lower() in data.lower():
                results['emulation_layers'].append(pattern.decode('ascii', errors='ignore'))
        
        return results
    
    def _analyze_instructions(self, data: bytes, disasm: Any, profile: ArchitectureProfile) -> Dict[str, Any]:
        """Analyze instructions for VM characteristics"""
        analysis = {
            'total_instructions': 0,
            'vm_suspicious_instructions': [],
            'control_flow_anomalies': [],
            'register_usage_patterns': {}
        }
        
        try:
            # Disassemble first 1KB for analysis
            sample_size = min(1024, len(data))
            instructions = list(disasm.disasm(data[:sample_size], 0))
            analysis['total_instructions'] = len(instructions)
            
            # Analyze for VM characteristics
            for insn in instructions:
                # Check for suspicious patterns
                if self._is_vm_suspicious_instruction(insn, profile):
                    analysis['vm_suspicious_instructions'].append({
                        'address': insn.address,
                        'mnemonic': insn.mnemonic,
                        'op_str': insn.op_str,
                        'bytes': insn.bytes.hex()
                    })
                
                # Analyze control flow
                if self._is_control_flow_anomaly(insn):
                    analysis['control_flow_anomalies'].append({
                        'address': insn.address,
                        'instruction': f"{insn.mnemonic} {insn.op_str}"
                    })
        
        except Exception as e:
            logger.warning(f"Instruction analysis failed: {e}")
            analysis['error'] = str(e)
        
        return analysis
    
    def _is_vm_suspicious_instruction(self, insn: Any, profile: ArchitectureProfile) -> bool:
        """Check if instruction is suspicious for VM protection"""
        # Architecture-specific suspicious patterns
        if profile.arch in [Architecture.X86, Architecture.X64]:
            suspicious_mnemonics = {'jmp', 'call', 'ret', 'push', 'pop'}
            # Check for indirect jumps/calls (common in VM dispatchers)
            if insn.mnemonic in suspicious_mnemonics and '[' in insn.op_str:
                return True
        
        elif profile.arch in [Architecture.ARM32, Architecture.ARM64]:
            # ARM suspicious patterns
            if insn.mnemonic in {'br', 'blr', 'bx'} and 'r' in insn.op_str:
                return True
        
        elif profile.arch in [Architecture.MIPS32, Architecture.MIPS64]:
            # MIPS suspicious patterns
            if insn.mnemonic in {'jr', 'jalr'} and '$' in insn.op_str:
                return True
        
        return False
    
    def _is_control_flow_anomaly(self, insn: Any) -> bool:
        """Detect control flow anomalies that might indicate VM protection"""
        # Look for unusual control flow patterns
        anomalous_patterns = [
            'jmp eax',      # Indirect jump to register
            'call eax',     # Indirect call to register
            'ret 4',        # Non-standard return
            'jmp [eax',     # Memory indirect jump
        ]
        
        full_insn = f"{insn.mnemonic} {insn.op_str}"
        return any(pattern in full_insn for pattern in anomalous_patterns)
    
    def _calculate_confidence_score(self, vm_results: Dict, cross_arch_results: Dict) -> float:
        """Calculate overall confidence score for VM detection"""
        score = 0.0
        
        # Score based on VM pattern matches
        pattern_types = ['vm_entry_patterns', 'vm_dispatcher_patterns', 'vm_exit_patterns']
        for pattern_type in pattern_types:
            if pattern_type in vm_results and vm_results[pattern_type]:
                score += 0.2
        
        # Score based on instruction analysis
        if 'instruction_analysis' in vm_results:
            insn_analysis = vm_results['instruction_analysis']
            if insn_analysis.get('vm_suspicious_instructions'):
                score += 0.3
            if insn_analysis.get('control_flow_anomalies'):
                score += 0.2
        
        # Score based on cross-architecture indicators
        if cross_arch_results.get('architecture_mixing'):
            score += 0.1
        if cross_arch_results.get('emulation_layers'):
            score += 0.1
        
        return min(1.0, score)


class ArchitectureSpecificOptimizer:
    """Optimize analysis based on target architecture"""
    
    def __init__(self):
        self.optimization_profiles = self._create_optimization_profiles()
    
    def _create_optimization_profiles(self) -> Dict[Architecture, Dict[str, Any]]:
        """Create optimization profiles for each architecture"""
        return {
            Architecture.X86: {
                'preferred_analysis_methods': ['pattern_matching', 'disassembly', 'emulation'],
                'analysis_depth': 'deep',
                'performance_priority': 'accuracy',
                'special_considerations': ['segment_registers', 'x87_fpu']
            },
            Architecture.X64: {
                'preferred_analysis_methods': ['pattern_matching', 'disassembly', 'symbolic_execution'],
                'analysis_depth': 'deep',
                'performance_priority': 'balanced',
                'special_considerations': ['rip_relative', 'extended_registers']
            },
            Architecture.ARM32: {
                'preferred_analysis_methods': ['pattern_matching', 'basic_block_analysis'],
                'analysis_depth': 'medium',
                'performance_priority': 'performance',
                'special_considerations': ['thumb_mode', 'conditional_execution']
            },
            Architecture.ARM64: {
                'preferred_analysis_methods': ['pattern_matching', 'control_flow_analysis'],
                'analysis_depth': 'medium',
                'performance_priority': 'balanced',
                'special_considerations': ['aarch64_features', 'crypto_extensions']
            },
            Architecture.MIPS32: {
                'preferred_analysis_methods': ['pattern_matching'],
                'analysis_depth': 'basic',
                'performance_priority': 'performance',
                'special_considerations': ['delay_slots', 'branch_likely']
            }
        }
    
    def optimize_analysis_for_architecture(self, arch: Architecture, binary_data: bytes) -> Dict[str, Any]:
        """Optimize analysis parameters for specific architecture"""
        profile = self.optimization_profiles.get(arch, {})
        
        optimization = {
            'recommended_methods': profile.get('preferred_analysis_methods', ['pattern_matching']),
            'analysis_timeout': self._calculate_timeout(arch, len(binary_data)),
            'memory_limit': self._calculate_memory_limit(arch),
            'threading_strategy': self._get_threading_strategy(arch),
            'special_handling': profile.get('special_considerations', [])
        }
        
        return optimization
    
    def _calculate_timeout(self, arch: Architecture, binary_size: int) -> float:
        """Calculate appropriate timeout for architecture"""
        base_timeout = 30.0  # seconds
        
        # Adjust based on architecture complexity
        complexity_multipliers = {
            Architecture.X86: 1.5,
            Architecture.X64: 1.3,
            Architecture.ARM32: 1.0,
            Architecture.ARM64: 1.1,
            Architecture.MIPS32: 0.8,
            Architecture.MIPS64: 0.9
        }
        
        multiplier = complexity_multipliers.get(arch, 1.0)
        size_factor = min(2.0, binary_size / (1024 * 1024))  # Max 2x for large binaries
        
        return base_timeout * multiplier * size_factor
    
    def _calculate_memory_limit(self, arch: Architecture) -> int:
        """Calculate memory limit in MB for architecture"""
        base_memory = 256  # MB
        
        memory_multipliers = {
            Architecture.X64: 2.0,
            Architecture.ARM64: 1.5,
            Architecture.MIPS64: 1.5,
            Architecture.POWERPC64: 1.5
        }
        
        multiplier = memory_multipliers.get(arch, 1.0)
        return int(base_memory * multiplier)
    
    def _get_threading_strategy(self, arch: Architecture) -> str:
        """Get optimal threading strategy for architecture"""
        # Some architectures benefit more from parallel analysis
        high_parallel_archs = {Architecture.X86, Architecture.X64, Architecture.ARM64}
        
        if arch in high_parallel_archs:
            return 'high_parallel'
        else:
            return 'low_parallel'
