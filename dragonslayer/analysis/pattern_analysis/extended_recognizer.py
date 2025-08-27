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
Extended VM Detection Patterns
==============================

Extended pattern recognition for modern VM protection systems including:
- VMProtect 3.x/4.x patterns
- Themida/WinLicense obfuscation
- Code Virtualizer patterns
- Custom VM implementations
- Metamorphic and polymorphic VM engines
"""

import logging
import struct
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass
from enum import Enum
import re

logger = logging.getLogger(__name__)


class VMType(Enum):
    """Extended VM protection types"""
    VMPROTECT_3X = "vmprotect_3x"
    VMPROTECT_4X = "vmprotect_4x"
    THEMIDA = "themida"
    WINLICENSE = "winlicense"
    CODE_VIRTUALIZER = "code_virtualizer"
    CUSTOM_VM = "custom_vm"
    METAMORPHIC_VM = "metamorphic_vm"
    POLYMORPHIC_VM = "polymorphic_vm"
    NESTED_VM = "nested_vm"
    HYBRID_PROTECTION = "hybrid_protection"


@dataclass
class ExtendedPattern:
    """Extended VM pattern definition"""
    name: str
    vm_type: VMType
    pattern_bytes: bytes
    mask: Optional[bytes] = None
    entropy_threshold: float = 0.0
    context_patterns: List[bytes] = None
    architectural_requirements: Set[str] = None
    confidence_weight: float = 1.0
    metamorphic_variants: List[bytes] = None
    
    def __post_init__(self):
        if self.context_patterns is None:
            self.context_patterns = []
        if self.architectural_requirements is None:
            self.architectural_requirements = {"x86", "x64"}
        if self.metamorphic_variants is None:
            self.metamorphic_variants = []


class ExtendedPatternMatcher:
    """Extended pattern matching engine with metamorphic support"""
    
    def __init__(self):
        self.patterns = self._initialize_extended_patterns()
        self.metamorphic_engine = MetamorphicPatternEngine()
        self.context_analyzer = ContextualAnalyzer()
        
    def _initialize_extended_patterns(self) -> List[ExtendedPattern]:
        """Initialize database of advanced VM patterns"""
        patterns = []
        
        # VMProtect 3.x advanced patterns
        patterns.extend(self._get_vmprotect_3x_patterns())
        
        # VMProtect 4.x patterns
        patterns.extend(self._get_vmprotect_4x_patterns())
        
        # Themida advanced patterns
        patterns.extend(self._get_themida_extended_patterns())
        
        # Code Virtualizer patterns
        patterns.extend(self._get_code_virtualizer_patterns())
        
        # Custom VM patterns
        patterns.extend(self._get_custom_vm_patterns())
        
        # Metamorphic VM patterns
        patterns.extend(self._get_metamorphic_patterns())
        
        return patterns
    
    def _get_vmprotect_3x_patterns(self) -> List[ExtendedPattern]:
        """VMProtect 3.x specific advanced patterns"""
        return [
            ExtendedPattern(
                name="VMProtect 3.x Handler Dispatcher",
                vm_type=VMType.VMPROTECT_3X,
                pattern_bytes=b'\x8B\x45\x00\x8B\x4D\x04\x03\xC1\x89\x45\x00',
                mask=b'\xFF\xFF\x00\xFF\xFF\x00\xFF\xFF\xFF\xFF\x00',
                entropy_threshold=7.2,
                context_patterns=[
                    b'\x50\x51\x52\x53\x56\x57',  # pushad variant
                    b'\x9C\x60'  # pushfd + pushad
                ],
                confidence_weight=0.95
            ),
            ExtendedPattern(
                name="VMProtect 3.x Stack Machine Operation",
                vm_type=VMType.VMPROTECT_3X,
                pattern_bytes=b'\x8B\x75\xFC\x8B\x7D\xF8\x03\xF7\x89\x75\xFC',
                entropy_threshold=6.8,
                confidence_weight=0.88
            ),
            ExtendedPattern(
                name="VMProtect 3.x Mutation Engine",
                vm_type=VMType.VMPROTECT_3X,
                pattern_bytes=b'\x8B\xC0\x35\x00\x00\x00\x00\x89\xC0',
                mask=b'\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF',
                metamorphic_variants=[
                    b'\x89\xC0\x35\x00\x00\x00\x00\x8B\xC0',
                    b'\x31\xC0\x35\x00\x00\x00\x00\x31\xC0'
                ],
                confidence_weight=0.92
            )
        ]
    
    def _get_vmprotect_4x_patterns(self) -> List[ExtendedPattern]:
        """VMProtect 4.x advanced patterns with enhanced obfuscation"""
        return [
            ExtendedPattern(
                name="VMProtect 4.x Enhanced Dispatcher",
                vm_type=VMType.VMPROTECT_4X,
                pattern_bytes=b'\x48\x8B\x45\x00\x48\x8B\x4D\x08\x48\x03\xC1',
                mask=b'\xFF\xFF\xFF\x00\xFF\xFF\xFF\x00\xFF\xFF\xFF',
                entropy_threshold=7.5,
                architectural_requirements={"x64"},
                confidence_weight=0.96
            ),
            ExtendedPattern(
                name="VMProtect 4.x Control Flow Obfuscation",
                vm_type=VMType.VMPROTECT_4X,
                pattern_bytes=b'\x48\x89\xE0\x48\x83\xC0\x08\x48\x89\x04\x24',
                entropy_threshold=7.0,
                confidence_weight=0.89
            )
        ]
    
    def _get_themida_extended_patterns(self) -> List[ExtendedPattern]:
        """Themida/WinLicense advanced obfuscation patterns"""
        return [
            ExtendedPattern(
                name="Themida Advanced VM Entry",
                vm_type=VMType.THEMIDA_ADVANCED,
                pattern_bytes=b'\x60\x9C\x8B\x74\x24\x24\x8B\x7C\x24\x28',
                entropy_threshold=6.5,
                context_patterns=[
                    b'\xE8\x00\x00\x00\x00\x58',  # call $+5, pop eax
                ],
                confidence_weight=0.91
            ),
            ExtendedPattern(
                name="Themida Polymorphic Decoder",
                vm_type=VMType.THEMIDA_ADVANCED,
                pattern_bytes=b'\x8B\x45\x00\x33\x45\x04\x89\x45\x00',
                mask=b'\xFF\xFF\x00\xFF\xFF\x00\xFF\xFF\x00',
                metamorphic_variants=[
                    b'\x8B\x4D\x00\x33\x4D\x04\x89\x4D\x00',
                    b'\x8B\x55\x00\x33\x55\x04\x89\x55\x00'
                ],
                confidence_weight=0.87
            )
        ]
    
    def _get_code_virtualizer_patterns(self) -> List[ExtendedPattern]:
        """Code Virtualizer specific patterns"""
        return [
            ExtendedPattern(
                name="Code Virtualizer VM Handler",
                vm_type=VMType.CODE_VIRTUALIZER,
                pattern_bytes=b'\x8B\x45\x08\x8B\x4D\x0C\x8B\x55\x10\x03\xC1',
                entropy_threshold=6.9,
                confidence_weight=0.90
            ),
            ExtendedPattern(
                name="Code Virtualizer Stack Manipulation",
                vm_type=VMType.CODE_VIRTUALIZER,
                pattern_bytes=b'\x89\x45\xFC\x8B\x45\xFC\x05\x04\x00\x00\x00',
                confidence_weight=0.85
            )
        ]
    
    def _get_custom_vm_patterns(self) -> List[ExtendedPattern]:
        """Patterns for custom VM implementations"""
        return [
            ExtendedPattern(
                name="Generic Custom VM Dispatcher",
                vm_type=VMType.CUSTOM_VM,
                pattern_bytes=b'\xFF\x24\x85\x00\x00\x00\x00',
                mask=b'\xFF\xFF\xFF\x00\x00\x00\x00',
                entropy_threshold=5.5,
                confidence_weight=0.75
            ),
            ExtendedPattern(
                name="Custom VM Bytecode Interpreter",
                vm_type=VMType.CUSTOM_VM,
                pattern_bytes=b'\x8A\x06\x46\x88\x45\xFF\x0F\xB6\x45\xFF',
                entropy_threshold=6.0,
                confidence_weight=0.80
            )
        ]
    
    def _get_metamorphic_patterns(self) -> List[ExtendedPattern]:
        """Metamorphic VM engine patterns"""
        return [
            ExtendedPattern(
                name="Metamorphic Engine Signature",
                vm_type=VMType.METAMORPHIC_VM,
                pattern_bytes=b'\x8B\xC0\x8B\xC0\x8B\xC0',  # Base pattern
                metamorphic_variants=[
                    b'\x89\xC0\x89\xC0\x89\xC0',  # mov variants
                    b'\x8B\xC8\x8B\xC1\x8B\xC8',  # register switching
                    b'\x50\x58\x50\x58\x50\x58'   # push/pop equivalent
                ],
                entropy_threshold=4.0,
                confidence_weight=0.70
            )
        ]
    
    def scan_advanced_patterns(self, binary_data: bytes, architecture: str = "x86") -> Dict[str, Any]:
        """Scan for advanced VM protection patterns"""
        results = {
            'patterns_found': [],
            'vm_types_detected': set(),
            'confidence_scores': {},
            'metamorphic_evidence': [],
            'contextual_matches': []
        }
        
        for pattern in self.patterns:
            if architecture not in pattern.architectural_requirements:
                continue
                
            matches = self._find_pattern_matches(binary_data, pattern)
            if matches:
                results['patterns_found'].extend(matches)
                results['vm_types_detected'].add(pattern.vm_type)
                
                # Calculate confidence score
                base_confidence = pattern.confidence_weight
                entropy_bonus = self._calculate_entropy_bonus(binary_data, matches, pattern)
                context_bonus = self._analyze_context(binary_data, matches, pattern)
                
                total_confidence = min(1.0, base_confidence + entropy_bonus + context_bonus)
                results['confidence_scores'][pattern.name] = total_confidence
                
                # Check for metamorphic variants
                if pattern.metamorphic_variants:
                    metamorphic_matches = self._find_metamorphic_matches(
                        binary_data, pattern.metamorphic_variants
                    )
                    if metamorphic_matches:
                        results['metamorphic_evidence'].append({
                            'pattern_name': pattern.name,
                            'variants_found': len(metamorphic_matches),
                            'matches': metamorphic_matches
                        })
        
        return results
    
    def _find_pattern_matches(self, data: bytes, pattern: ExtendedPattern) -> List[Dict]:
        """Find matches for a specific advanced pattern"""
        matches = []
        pattern_bytes = pattern.pattern_bytes
        mask = pattern.mask
        
        i = 0
        while i < len(data) - len(pattern_bytes):
            if self._match_with_mask(data[i:i+len(pattern_bytes)], pattern_bytes, mask):
                match_info = {
                    'offset': i,
                    'pattern_name': pattern.name,
                    'vm_type': pattern.vm_type.value,
                    'bytes_matched': data[i:i+len(pattern_bytes)],
                    'entropy': self._calculate_local_entropy(data[i:i+64])
                }
                matches.append(match_info)
                i += len(pattern_bytes)  # Skip past this match
            else:
                i += 1
        
        return matches
    
    def _match_with_mask(self, data: bytes, pattern: bytes, mask: Optional[bytes]) -> bool:
        """Match pattern with optional mask"""
        if len(data) != len(pattern):
            return False
            
        if mask is None:
            return data == pattern
            
        for i in range(len(pattern)):
            if (data[i] & mask[i]) != (pattern[i] & mask[i]):
                return False
        
        return True
    
    def _find_metamorphic_matches(self, data: bytes, variants: List[bytes]) -> List[Dict]:
        """Find metamorphic variant matches"""
        matches = []
        for variant in variants:
            i = 0
            while i < len(data) - len(variant):
                if data[i:i+len(variant)] == variant:
                    matches.append({
                        'offset': i,
                        'variant_bytes': variant,
                        'similarity_score': self._calculate_similarity(variant, variants[0])
                    })
                    i += len(variant)
                else:
                    i += 1
        return matches
    
    def _calculate_entropy_bonus(self, data: bytes, matches: List[Dict], pattern: ExtendedPattern) -> float:
        """Calculate entropy-based confidence bonus"""
        if not matches or pattern.entropy_threshold == 0:
            return 0.0
            
        avg_entropy = sum(match['entropy'] for match in matches) / len(matches)
        if avg_entropy >= pattern.entropy_threshold:
            return min(0.1, (avg_entropy - pattern.entropy_threshold) / 10.0)
        return 0.0
    
    def _analyze_context(self, data: bytes, matches: List[Dict], pattern: ExtendedPattern) -> float:
        """Analyze contextual patterns around matches"""
        if not pattern.context_patterns:
            return 0.0
            
        context_bonus = 0.0
        for match in matches:
            offset = match['offset']
            # Check 100 bytes before and after
            context_start = max(0, offset - 100)
            context_end = min(len(data), offset + len(pattern.pattern_bytes) + 100)
            context_data = data[context_start:context_end]
            
            for context_pattern in pattern.context_patterns:
                if context_pattern in context_data:
                    context_bonus += 0.05
                    break
        
        return min(0.15, context_bonus)
    
    def _calculate_local_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy for local data"""
        if not data:
            return 0.0
            
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability).bit_length() / 2
        
        return entropy
    
    def _calculate_similarity(self, variant: bytes, reference: bytes) -> float:
        """Calculate similarity score between metamorphic variants"""
        if len(variant) != len(reference):
            return 0.0
            
        matches = sum(1 for a, b in zip(variant, reference) if a == b)
        return matches / len(reference)


class MetamorphicPatternEngine:
    """Engine for detecting metamorphic VM patterns"""
    
    def __init__(self):
        self.transformation_rules = self._load_transformation_rules()
    
    def _load_transformation_rules(self) -> Dict[str, List[bytes]]:
        """Load metamorphic transformation rules"""
        return {
            'nop_equivalents': [
                b'\x90',           # nop
                b'\x8B\xC0',       # mov eax, eax
                b'\x8B\xC9',       # mov ecx, ecx
                b'\x8B\xD2',       # mov edx, edx
            ],
            'register_swaps': [
                b'\x8B\xC0',       # mov eax, eax
                b'\x8B\xC8',       # mov ecx, eax
                b'\x8B\xD0',       # mov edx, eax
            ],
            'stack_operations': [
                b'\x50\x58',       # push eax; pop eax
                b'\x51\x59',       # push ecx; pop ecx
                b'\x52\x5A',       # push edx; pop edx
            ]
        }
    
    def detect_metamorphic_patterns(self, data: bytes) -> Dict[str, Any]:
        """Detect metamorphic transformation patterns"""
        results = {
            'transformation_evidence': [],
            'pattern_variants': [],
            'mutation_complexity': 0.0
        }
        
        # Analyze for transformation evidence
        for transform_type, patterns in self.transformation_rules.items():
            matches = []
            for pattern in patterns:
                offset = 0
                while offset < len(data) - len(pattern):
                    if data[offset:offset+len(pattern)] == pattern:
                        matches.append(offset)
                        offset += len(pattern)
                    else:
                        offset += 1
            
            if matches:
                results['transformation_evidence'].append({
                    'type': transform_type,
                    'occurrences': len(matches),
                    'locations': matches[:10]  # First 10 locations
                })
        
        # Calculate mutation complexity
        total_transformations = sum(
            len(evidence['locations']) 
            for evidence in results['transformation_evidence']
        )
        results['mutation_complexity'] = min(1.0, total_transformations / 100.0)
        
        return results


class ContextualAnalyzer:
    """Contextual analysis for VM pattern validation"""
    
    def analyze_vm_context(self, data: bytes, matches: List[Dict]) -> Dict[str, Any]:
        """Analyze contextual information around VM pattern matches"""
        context_analysis = {
            'function_boundaries': [],
            'control_flow_patterns': [],
            'data_flow_analysis': [],
            'anomaly_scores': {}
        }
        
        for match in matches:
            offset = match['offset']
            
            # Analyze function boundaries
            func_start = self._find_function_prologue(data, offset)
            if func_start:
                context_analysis['function_boundaries'].append({
                    'match_offset': offset,
                    'function_start': func_start,
                    'distance': offset - func_start
                })
            
            # Analyze control flow
            control_flow = self._analyze_control_flow(data, offset)
            if control_flow:
                context_analysis['control_flow_patterns'].append(control_flow)
            
            # Calculate anomaly score
            anomaly_score = self._calculate_anomaly_score(data, offset)
            context_analysis['anomaly_scores'][offset] = anomaly_score
        
        return context_analysis
    
    def _find_function_prologue(self, data: bytes, offset: int) -> Optional[int]:
        """Find nearest function prologue before offset"""
        # Look for common function prologues
        prologues = [
            b'\x55\x8B\xEC',           # push ebp; mov ebp, esp
            b'\x55\x89\xE5',           # push ebp; mov ebp, esp (AT&T)
            b'\x48\x89\x5C\x24',       # mov [rsp+...], rbx (x64)
            b'\x48\x83\xEC'            # sub rsp, ... (x64)
        ]
        
        search_start = max(0, offset - 1000)  # Search up to 1000 bytes back
        
        for prologue in prologues:
            pos = data.rfind(prologue, search_start, offset)
            if pos != -1:
                return pos
        
        return None
    
    def _analyze_control_flow(self, data: bytes, offset: int) -> Optional[Dict]:
        """Analyze control flow patterns around offset"""
        # Look for jumps, calls, returns in nearby code
        control_instructions = {
            b'\xE8': 'call',
            b'\xE9': 'jmp', 
            b'\x74': 'je',
            b'\x75': 'jne',
            b'\xEB': 'jmp_short',
            b'\xC3': 'ret'
        }
        
        window_start = max(0, offset - 50)
        window_end = min(len(data), offset + 50)
        window_data = data[window_start:window_end]
        
        instructions_found = []
        for i, byte_val in enumerate(window_data):
            byte_seq = bytes([byte_val])
            if byte_seq in control_instructions:
                instructions_found.append({
                    'instruction': control_instructions[byte_seq],
                    'offset': window_start + i,
                    'distance_from_match': (window_start + i) - offset
                })
        
        if instructions_found:
            return {
                'instructions': instructions_found,
                'control_density': len(instructions_found) / len(window_data)
            }
        
        return None
    
    def _calculate_anomaly_score(self, data: bytes, offset: int) -> float:
        """Calculate anomaly score for code region"""
        window_size = 64
        start = max(0, offset - window_size // 2)
        end = min(len(data), start + window_size)
        window_data = data[start:end]
        
        if not window_data:
            return 0.0
        
        # Calculate various anomaly indicators
        entropy = self._calculate_entropy(window_data)
        instruction_density = self._estimate_instruction_density(window_data)
        byte_distribution = self._analyze_byte_distribution(window_data)
        
        # Combine into overall anomaly score
        anomaly_score = (
            (entropy / 8.0) * 0.4 +           # Normalized entropy
            instruction_density * 0.3 +        # Instruction density
            byte_distribution * 0.3             # Byte distribution anomaly
        )
        
        return min(1.0, anomaly_score)
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
            
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1) if probability > 0 else 0
        
        return entropy
    
    def _estimate_instruction_density(self, data: bytes) -> float:
        """Estimate the density of valid x86 instructions"""
        # Simple heuristic: count bytes that could be instruction opcodes
        valid_opcodes = {
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,  # push reg
            0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,  # pop reg
            0x8B, 0x89,  # mov instructions
            0x03, 0x01,  # add instructions
            0xE8, 0xE9,  # call/jmp
            0x75, 0x74,  # conditional jumps
            0xFF, 0xC3   # various/ret
        }
        
        valid_count = sum(1 for byte in data if byte in valid_opcodes)
        return valid_count / len(data) if data else 0.0
    
    def _analyze_byte_distribution(self, data: bytes) -> float:
        """Analyze byte value distribution for anomalies"""
        if not data:
            return 0.0
            
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate coefficient of variation
        mean_count = len(data) / 256
        variance = sum((count - mean_count) ** 2 for count in byte_counts) / 256
        std_dev = variance ** 0.5
        
        if mean_count > 0:
            cv = std_dev / mean_count
            return min(1.0, cv / 10.0)  # Normalize
        
        return 0.0
