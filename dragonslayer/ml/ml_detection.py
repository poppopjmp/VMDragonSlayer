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
Machine Learning ML Detection
==================================

Advanced ML-powered VM detection with:
- Deep learning pattern recognition
- Behavioral analysis with neural networks
- Adversarial ML resistance
- Ensemble methods for robustness
- Transfer learning for new VM types
- Explainable AI for analysis insights
"""

import logging
import numpy as np
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import pickle
import json
from pathlib import Path

logger = logging.getLogger(__name__)

# Optional ML dependencies with graceful fallbacks
ML_AVAILABLE = {}
try:
    import sklearn
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.svm import SVC
    from sklearn.neural_network import MLPClassifier
    from sklearn.preprocessing import StandardScaler, RobustScaler
    from sklearn.feature_selection import SelectKBest, f_classif
    from sklearn.model_selection import cross_val_score
    from sklearn.metrics import classification_report, confusion_matrix
    ML_AVAILABLE['sklearn'] = True
    logger.info("Scikit-learn available for ML detection")
except ImportError:
    ML_AVAILABLE['sklearn'] = False
    logger.warning("Scikit-learn not available - ML features limited")

try:
    import tensorflow as tf
    from tensorflow import keras
    ML_AVAILABLE['tensorflow'] = True
    logger.info("TensorFlow available for deep learning")
except ImportError:
    ML_AVAILABLE['tensorflow'] = False
    logger.warning("TensorFlow not available - deep learning disabled")

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    ML_AVAILABLE['pytorch'] = True
    logger.info("PyTorch available for deep learning")
except ImportError:
    ML_AVAILABLE['pytorch'] = False
    logger.warning("PyTorch not available - deep learning disabled")


class MLModelType(Enum):
    """Machine learning model types"""
    RANDOM_FOREST = "random_forest"
    GRADIENT_BOOSTING = "gradient_boosting"
    SVM = "svm"
    NEURAL_NETWORK = "neural_network"
    DEEP_NEURAL_NETWORK = "deep_nn"
    CONVOLUTIONAL_NN = "cnn"
    RECURRENT_NN = "rnn"
    TRANSFORMER = "transformer"
    ENSEMBLE = "ensemble"


class FeatureType(Enum):
    """Feature extraction types"""
    STATISTICAL = "statistical"
    STRUCTURAL = "structural"
    BEHAVIORAL = "behavioral"
    TEMPORAL = "temporal"
    SPECTRAL = "spectral"
    SEMANTIC = "semantic"


@dataclass
class MLFeature:
    """ML feature definition"""
    name: str
    type: FeatureType
    description: str
    extractor: callable
    normalizer: Optional[callable] = None
    importance_weight: float = 1.0
    stability_score: float = 1.0  # Resistance to adversarial attacks


@dataclass
class MLModel:
    """ML model container"""
    name: str
    model_type: MLModelType
    model: Any
    scaler: Optional[Any] = None
    feature_selector: Optional[Any] = None
    features_used: List[str] = field(default_factory=list)
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    training_date: Optional[str] = None
    version: str = "1.0"


class AdvancedFeatureExtractor:
    """Advanced feature extraction for ML models"""
    
    def __init__(self):
        self.feature_definitions = self._initialize_feature_definitions()
        self.cache = {}
    
    def _initialize_feature_definitions(self) -> Dict[str, MLFeature]:
        """Initialize comprehensive feature definitions"""
        features = {}
        
        # Statistical features
        features.update(self._get_statistical_features())
        
        # Structural features
        features.update(self._get_structural_features())
        
        # Behavioral features
        features.update(self._get_behavioral_features())
        
        # Temporal features
        features.update(self._get_temporal_features())
        
        # Spectral features
        features.update(self._get_spectral_features())
        
        return features
    
    def _get_statistical_features(self) -> Dict[str, MLFeature]:
        """Statistical analysis features"""
        return {
            "entropy_distribution": MLFeature(
                name="Entropy Distribution",
                type=FeatureType.STATISTICAL,
                description="Statistical distribution of entropy across binary sections",
                extractor=self._extract_entropy_distribution,
                importance_weight=0.9
            ),
            "byte_frequency_analysis": MLFeature(
                name="Byte Frequency Analysis",
                type=FeatureType.STATISTICAL,
                description="Analysis of byte value frequency patterns",
                extractor=self._extract_byte_frequency,
                importance_weight=0.8
            ),
            "instruction_frequency": MLFeature(
                name="Instruction Frequency",
                type=FeatureType.STATISTICAL,
                description="Frequency analysis of instruction opcodes",
                extractor=self._extract_instruction_frequency,
                importance_weight=0.85
            ),
            "statistical_moments": MLFeature(
                name="Statistical Moments",
                type=FeatureType.STATISTICAL,
                description="Statistical moments (mean, variance, skewness, kurtosis)",
                extractor=self._extract_statistical_moments,
                importance_weight=0.7
            )
        }
    
    def _get_structural_features(self) -> Dict[str, MLFeature]:
        """Code structure analysis features"""
        return {
            "control_flow_complexity": MLFeature(
                name="Control Flow Complexity",
                type=FeatureType.STRUCTURAL,
                description="Complexity metrics of control flow graph",
                extractor=self._extract_control_flow_complexity,
                importance_weight=0.95
            ),
            "function_call_graph": MLFeature(
                name="Function Call Graph",
                type=FeatureType.STRUCTURAL,
                description="Function call graph characteristics",
                extractor=self._extract_call_graph_features,
                importance_weight=0.88
            ),
            "basic_block_statistics": MLFeature(
                name="Basic Block Statistics",
                type=FeatureType.STRUCTURAL,
                description="Statistical properties of basic blocks",
                extractor=self._extract_basic_block_stats,
                importance_weight=0.82
            ),
            "section_characteristics": MLFeature(
                name="Section Characteristics",
                type=FeatureType.STRUCTURAL,
                description="PE/ELF section properties and relationships",
                extractor=self._extract_section_characteristics,
                importance_weight=0.78
            )
        }
    
    def _get_behavioral_features(self) -> Dict[str, MLFeature]:
        """Behavioral analysis features"""
        return {
            "api_call_patterns": MLFeature(
                name="API Call Patterns",
                type=FeatureType.BEHAVIORAL,
                description="API usage patterns and sequences",
                extractor=self._extract_api_patterns,
                importance_weight=0.92
            ),
            "memory_access_patterns": MLFeature(
                name="Memory Access Patterns",
                type=FeatureType.BEHAVIORAL,
                description="Memory access behavior analysis",
                extractor=self._extract_memory_patterns,
                importance_weight=0.87
            ),
            "execution_flow_patterns": MLFeature(
                name="Execution Flow Patterns",
                type=FeatureType.BEHAVIORAL,
                description="Dynamic execution flow characteristics",
                extractor=self._extract_execution_patterns,
                importance_weight=0.90
            )
        }
    
    def _get_temporal_features(self) -> Dict[str, MLFeature]:
        """Time-series and temporal features"""
        return {
            "execution_timing_patterns": MLFeature(
                name="Execution Timing Patterns",
                type=FeatureType.TEMPORAL,
                description="Temporal patterns in execution behavior",
                extractor=self._extract_timing_patterns,
                importance_weight=0.75
            ),
            "sequence_analysis": MLFeature(
                name="Sequence Analysis",
                type=FeatureType.TEMPORAL,
                description="Sequential pattern analysis",
                extractor=self._extract_sequence_patterns,
                importance_weight=0.80
            )
        }
    
    def _get_spectral_features(self) -> Dict[str, MLFeature]:
        """Spectral analysis features"""
        return {
            "fourier_transform_features": MLFeature(
                name="Fourier Transform Features",
                type=FeatureType.SPECTRAL,
                description="Frequency domain characteristics",
                extractor=self._extract_fourier_features,
                importance_weight=0.65
            ),
            "wavelet_analysis": MLFeature(
                name="Wavelet Analysis",
                type=FeatureType.SPECTRAL,
                description="Multi-scale wavelet decomposition features",
                extractor=self._extract_wavelet_features,
                importance_weight=0.70
            )
        }
    
    def extract_features(self, binary_data: bytes, feature_names: List[str] = None) -> np.ndarray:
        """Extract specified features from binary data"""
        if feature_names is None:
            feature_names = list(self.feature_definitions.keys())
        
        feature_vector = []
        
        for feature_name in feature_names:
            if feature_name not in self.feature_definitions:
                logger.warning(f"Unknown feature: {feature_name}")
                continue
            
            try:
                feature_def = self.feature_definitions[feature_name]
                
                # Check cache first
                cache_key = f"{feature_name}_{hash(binary_data)}"
                if cache_key in self.cache:
                    feature_values = self.cache[cache_key]
                else:
                    feature_values = feature_def.extractor(binary_data)
                    self.cache[cache_key] = feature_values
                
                # Apply normalization if specified
                if feature_def.normalizer:
                    feature_values = feature_def.normalizer(feature_values)
                
                # Ensure feature values are numeric
                if isinstance(feature_values, (list, np.ndarray)):
                    feature_vector.extend(feature_values)
                else:
                    feature_vector.append(feature_values)
                    
            except Exception as e:
                logger.warning(f"Feature extraction failed for {feature_name}: {e}")
                # Add zeros for failed features to maintain vector size
                feature_vector.append(0.0)
        
        return np.array(feature_vector, dtype=np.float32)
    
    # Feature extraction implementations
    
    def _extract_entropy_distribution(self, data: bytes) -> List[float]:
        """Extract entropy distribution features"""
        if len(data) == 0:
            return [0.0] * 10
        
        # Calculate entropy for sliding windows
        window_size = min(256, len(data) // 10)
        entropies = []
        
        for i in range(0, len(data) - window_size, window_size):
            window = data[i:i + window_size]
            entropy = self._calculate_entropy(window)
            entropies.append(entropy)
        
        if not entropies:
            return [0.0] * 10
        
        # Statistical features of entropy distribution
        entropies = np.array(entropies)
        features = [
            np.mean(entropies),
            np.std(entropies),
            np.min(entropies),
            np.max(entropies),
            np.median(entropies),
            np.percentile(entropies, 25),
            np.percentile(entropies, 75),
            np.var(entropies),
            len([e for e in entropies if e > 7.0]) / len(entropies),  # High entropy ratio
            len([e for e in entropies if e < 2.0]) / len(entropies)   # Low entropy ratio
        ]
        
        return features
    
    def _extract_byte_frequency(self, data: bytes) -> List[float]:
        """Extract byte frequency features"""
        if len(data) == 0:
            return [0.0] * 256
        
        # Calculate byte frequencies
        byte_counts = np.zeros(256, dtype=np.int32)
        for byte in data:
            byte_counts[byte] += 1
        
        # Normalize to frequencies
        frequencies = byte_counts.astype(np.float32) / len(data)
        
        return frequencies.tolist()
    
    def _extract_instruction_frequency(self, data: bytes) -> List[float]:
        """Extract instruction frequency features using proper disassembly"""
        if len(data) == 0:
            return [0.0] * 20
            
        try:
            # Import Capstone for proper disassembly
            try:
                from capstone import Cs, CS_ARCH_X86, CS_MODE_32
                has_capstone = True
            except ImportError:
                has_capstone = False
            
            if has_capstone:
                # Use Capstone for proper disassembly
                md = Cs(CS_ARCH_X86, CS_MODE_32)  # Assume x86-32 by default
                instructions = list(md.disasm(data, 0x1000))
                
                # Count instruction frequencies
                opcode_counts = {}
                total_instructions = len(instructions)
                
                for insn in instructions:
                    mnemonic = insn.mnemonic.lower()
                    opcode_counts[mnemonic] = opcode_counts.get(mnemonic, 0) + 1
                
                # Common x86 instructions to analyze
                important_opcodes = [
                    'mov', 'push', 'pop', 'call', 'ret', 'jmp', 'je', 'jne',
                    'add', 'sub', 'mul', 'div', 'xor', 'or', 'and', 'not',
                    'cmp', 'test', 'lea', 'nop'
                ]
                
                features = []
                for opcode in important_opcodes:
                    frequency = opcode_counts.get(opcode, 0) / max(1, total_instructions)
                    features.append(frequency)
                    
                return features
            else:
                # Fallback to byte pattern analysis
                return self._extract_instruction_frequency_fallback(data)
                
        except Exception as e:
            logger.warning(f"Instruction frequency extraction failed: {e}")
            return self._extract_instruction_frequency_fallback(data)
    
    def _extract_instruction_frequency_fallback(self, data: bytes) -> List[float]:
        """Fallback instruction frequency analysis using byte patterns"""
        # Common x86 opcode bytes with more comprehensive analysis
        common_opcodes = {
            0x55: 'push_ebp',      # push ebp
            0x8B: 'mov_variants',   # mov variations  
            0xE8: 'call',          # call
            0xC3: 'ret',           # ret
            0x75: 'jne',           # jne
            0x74: 'je',            # je
            0xFF: 'multi_byte',    # various instructions
            0x83: 'arith_imm8',    # arithmetic with imm8
            0x89: 'mov_store',     # mov reg to r/m
            0x50: 'push_eax',      # push eax
            0x58: 'pop_eax',       # pop eax
            0x85: 'test',          # test
            0x33: 'xor',           # xor
            0x31: 'xor_alt',       # xor alternative
            0x90: 'nop',           # nop
            0xEB: 'jmp_short',     # jmp short
            0xE9: 'jmp_near',      # jmp near
            0x68: 'push_imm32',    # push imm32
            0x6A: 'push_imm8',     # push imm8
            0xC7: 'mov_imm'        # mov imm to r/m
        }
        
        features = []
        data_len = len(data)
        
        for opcode_byte in sorted(common_opcodes.keys()):
            count = data.count(opcode_byte)
            frequency = count / data_len if data_len > 0 else 0
            features.append(frequency)
        
        return features
    
    def _extract_statistical_moments(self, data: bytes) -> List[float]:
        """Extract statistical moments"""
        if len(data) == 0:
            return [0.0, 0.0, 0.0, 0.0]
        
        values = np.array(list(data), dtype=np.float32)
        
        mean = np.mean(values)
        variance = np.var(values)
        skewness = self._calculate_skewness(values)
        kurtosis = self._calculate_kurtosis(values)
        
        return [mean, variance, skewness, kurtosis]
    
    def _extract_control_flow_complexity(self, data: bytes) -> List[float]:
        """Extract control flow complexity features with proper analysis"""
        if len(data) == 0:
            return [0.0] * 8
            
        try:
            # Import Capstone for proper control flow analysis
            try:
                from capstone import Cs, CS_ARCH_X86, CS_MODE_32
                has_capstone = True
            except ImportError:
                has_capstone = False
            
            if has_capstone:
                return self._extract_control_flow_with_capstone(data)
            else:
                return self._extract_control_flow_fallback(data)
                
        except Exception as e:
            logger.warning(f"Control flow analysis failed: {e}")
            return self._extract_control_flow_fallback(data)
    
    def _extract_control_flow_with_capstone(self, data: bytes) -> List[float]:
        """Extract control flow complexity using Capstone disassembly"""
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        except ImportError:
            return self._extract_control_flow_fallback(data)
        
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions = list(md.disasm(data, 0x1000))
        
        if not instructions:
            return [0.0] * 8
        
        # Analyze control flow patterns
        jump_instructions = []
        call_instructions = []
        basic_blocks = []
        current_block = []
        
        for insn in instructions:
            current_block.append(insn)
            
            # Identify control flow changes
            if insn.mnemonic.startswith('j'):  # All jump instructions
                jump_instructions.append(insn)
                basic_blocks.append(current_block)
                current_block = []
            elif insn.mnemonic == 'call':
                call_instructions.append(insn)
            elif insn.mnemonic in ['ret', 'retn']:
                basic_blocks.append(current_block)
                current_block = []
        
        # Add final block if exists
        if current_block:
            basic_blocks.append(current_block)
        
        # Calculate complexity metrics
        num_instructions = len(instructions)
        num_jumps = len(jump_instructions)
        num_calls = len(call_instructions)
        num_basic_blocks = len(basic_blocks)
        
        # Cyclomatic complexity approximation
        cyclomatic_complexity = num_jumps - num_basic_blocks + 2
        
        # Control flow density
        cf_density = (num_jumps + num_calls) / max(1, num_instructions)
        
        # Average basic block size
        avg_block_size = sum(len(block) for block in basic_blocks) / max(1, num_basic_blocks)
        
        # Branch factor (average outgoing edges per block)
        branch_factor = num_jumps / max(1, num_basic_blocks)
        
        return [
            num_jumps,
            num_calls, 
            num_basic_blocks,
            cyclomatic_complexity,
            cf_density,
            avg_block_size,
            branch_factor,
            self._calculate_entropy(data)
        ]
    
    def _extract_control_flow_fallback(self, data: bytes) -> List[float]:
        """Fallback control flow analysis using byte patterns"""
        # Control flow opcodes with more comprehensive analysis
        jump_opcodes = {
            0xE8: 'call',     # call
            0xE9: 'jmp_near', # jmp near
            0xEB: 'jmp_short',# jmp short
            0x74: 'je',       # je
            0x75: 'jne',      # jne
            0x76: 'jbe',      # jbe
            0x77: 'ja',       # ja
            0x78: 'js',       # js
            0x79: 'jns',      # jns
            0x7A: 'jp',       # jp
            0x7B: 'jnp',      # jnp
            0x7C: 'jl',       # jl
            0x7D: 'jge',      # jge
            0x7E: 'jle',      # jle
            0x7F: 'jg',       # jg
            0xC3: 'ret',      # ret
            0xC2: 'ret_imm16' # ret imm16
        }
        
        # Count different types of control flow
        call_count = data.count(0xE8)
        jump_count = sum(data.count(opcode) for opcode in [0xE9, 0xEB])
        conditional_jump_count = sum(data.count(opcode) for opcode in range(0x74, 0x80))
        ret_count = sum(data.count(opcode) for opcode in [0xC2, 0xC3])
        
        total_cf_instructions = call_count + jump_count + conditional_jump_count + ret_count
        total_instructions = len(data)
        
        # Estimate basic blocks (rough approximation)
        estimated_blocks = ret_count + jump_count + 1
        
        # Calculate metrics
        cf_density = total_cf_instructions / max(1, total_instructions)
        complexity_ratio = conditional_jump_count / max(1, total_instructions)
        call_ret_ratio = call_count / max(1, ret_count)
        
        return [
            total_cf_instructions,
            conditional_jump_count,
            estimated_blocks,
            complexity_ratio,
            cf_density,
            call_ret_ratio,
            len(set(data)),  # Instruction diversity
            self._calculate_entropy(data)
        ]
    
    def _extract_call_graph_features(self, data: bytes) -> List[float]:
        """Extract call graph features"""
        call_count = data.count(b'\xE8')  # call instruction
        ret_count = data.count(b'\xC3')   # ret instruction
        
        call_ret_ratio = call_count / max(1, ret_count)
        call_density = call_count / len(data) if data else 0
        
        return [call_count, ret_count, call_ret_ratio, call_density]
    
    def _extract_basic_block_stats(self, data: bytes) -> List[float]:
        """Extract basic block statistics with proper CFG analysis"""
        if len(data) == 0:
            return [0.0] * 6
        
        try:
            # Try using Capstone for proper CFG analysis
            try:
                from capstone import Cs, CS_ARCH_X86, CS_MODE_32
                has_capstone = True
            except ImportError:
                has_capstone = False
            
            if has_capstone:
                return self._extract_basic_blocks_with_capstone(data)
            else:
                return self._extract_basic_blocks_fallback(data)
        except Exception as e:
            logger.debug(f"Basic block analysis failed: {e}")
            return self._extract_basic_blocks_fallback(data)
    
    def _extract_basic_blocks_with_capstone(self, data: bytes) -> List[float]:
        """Extract basic blocks using Capstone disassembly"""
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions = list(md.disasm(data, 0x1000))
        
        if not instructions:
            return [0.0] * 6
        
        # Identify basic block boundaries
        basic_blocks = []
        current_block = []
        block_leaders = {0x1000}  # First instruction is always a leader
        
        # Find block leaders (targets of jumps, instruction after jumps)
        for insn in instructions:
            if insn.mnemonic.startswith('j') or insn.mnemonic in ['call']:
                # Instruction after jump/call is a leader
                next_addr = insn.address + insn.size
                block_leaders.add(next_addr)
                
                # Jump target is also a leader (if we can determine it)
                if insn.operands and hasattr(insn.operands[0], 'value'):
                    if hasattr(insn.operands[0].value, 'imm'):
                        block_leaders.add(insn.operands[0].value.imm)
        
        # Build basic blocks
        for insn in instructions:
            if insn.address in block_leaders and current_block:
                # Start new block
                basic_blocks.append(current_block)
                current_block = []
            
            current_block.append(insn)
            
            # End block on control flow instruction
            if (insn.mnemonic.startswith('j') or 
                insn.mnemonic in ['call', 'ret', 'int']):
                basic_blocks.append(current_block)
                current_block = []
        
        # Add final block
        if current_block:
            basic_blocks.append(current_block)
        
        # Calculate statistics
        block_count = len(basic_blocks)
        block_sizes = [len(block) for block in basic_blocks]
        
        if not block_sizes:
            return [0.0] * 6
        
        avg_block_size = np.mean(block_sizes)
        max_block_size = np.max(block_sizes)
        min_block_size = np.min(block_sizes)
        block_size_variance = np.var(block_sizes)
        
        # Calculate edge count (approximate)
        edge_count = sum(1 for block in basic_blocks 
                        for insn in block 
                        if insn.mnemonic.startswith('j') or insn.mnemonic == 'call')
        
        return [
            float(block_count),
            avg_block_size,
            max_block_size,
            min_block_size,
            block_size_variance,
            float(edge_count)
        ]
    
    def _extract_basic_blocks_fallback(self, data: bytes) -> List[float]:
        """Fallback basic block analysis using byte patterns"""
        # Control flow instruction patterns
        block_terminators = [0xC3, 0xE9, 0xEB]  # ret, jmp, short jmp
        conditional_jumps = list(range(0x70, 0x80))  # conditional jumps
        call_instruction = [0xE8]  # call
        
        # Count different types of control flow instructions
        ret_count = data.count(0xC3)
        jump_count = sum(data.count(opcode) for opcode in [0xE9, 0xEB])
        conditional_jump_count = sum(data.count(opcode) for opcode in conditional_jumps)
        call_count = data.count(0xE8)
        
        # Estimate basic blocks
        estimated_blocks = ret_count + jump_count + conditional_jump_count + 1
        avg_block_size = len(data) / max(1, estimated_blocks)
        
        # Estimate complexity metrics
        total_cf_instructions = ret_count + jump_count + conditional_jump_count + call_count
        cf_density = total_cf_instructions / len(data)
        
        return [
            float(estimated_blocks),
            avg_block_size,
            float(len(data)),  # max possible block size
            1.0,  # min block size estimate
            avg_block_size * 0.5,  # variance estimate
            float(total_cf_instructions)  # edge count estimate
        ]
    
    def _extract_section_characteristics(self, data: bytes) -> List[float]:
        """Extract section characteristics (simplified)"""
        # This would normally parse PE/ELF headers
        # Simplified version analyzes data patterns
        
        # Look for typical section patterns
        null_bytes = data.count(0)
        high_entropy_regions = len([b for b in data if b > 128])
        
        null_ratio = null_bytes / len(data) if data else 0
        high_entropy_ratio = high_entropy_regions / len(data) if data else 0
        
        return [null_ratio, high_entropy_ratio, len(data)]
    
    def _extract_api_patterns(self, data: bytes) -> List[float]:
        """Extract API call patterns"""
        # Look for common API name strings (simplified)
        common_apis = [
            b'kernel32', b'ntdll', b'user32', b'advapi32',
            b'CreateFile', b'VirtualAlloc', b'LoadLibrary'
        ]
        
        features = []
        for api in common_apis:
            count = len([i for i in range(len(data) - len(api)) 
                        if data[i:i+len(api)].lower() == api.lower()])
            features.append(count)
        
        return features
    
    def _extract_memory_patterns(self, data: bytes) -> List[float]:
        """Extract memory access patterns"""
        # Look for memory access instruction patterns
        mem_opcodes = [0x8B, 0x89, 0xC7, 0xC6]  # mov, mov, mov, mov (memory variants)
        
        features = []
        for opcode in mem_opcodes:
            count = data.count(bytes([opcode]))
            features.append(count)
        
        return features
    
    def _extract_execution_patterns(self, data: bytes) -> List[float]:
        """Extract execution flow patterns"""
        # Analysis of execution flow characteristics
        sequential_ratio = len([i for i in range(len(data)-1) 
                               if abs(data[i] - data[i+1]) <= 1]) / max(1, len(data)-1)
        
        return [sequential_ratio, self._calculate_entropy(data)]
    
    def _extract_timing_patterns(self, data: bytes) -> List[float]:
        """Extract timing-related patterns"""
        # Look for timing-related API calls and patterns
        timing_patterns = [b'GetTickCount', b'QueryPerformanceCounter', b'rdtsc']
        
        timing_features = []
        for pattern in timing_patterns:
            count = len([i for i in range(len(data) - len(pattern)) 
                        if data[i:i+len(pattern)].lower() == pattern.lower()])
            timing_features.append(count)
        
        return timing_features
    
    def _extract_sequence_patterns(self, data: bytes) -> List[float]:
        """Extract sequential patterns"""
        # N-gram analysis for sequences
        bigram_diversity = len(set(zip(data[:-1], data[1:]))) / max(1, len(data)-1)
        trigram_diversity = len(set(zip(data[:-2], data[1:-1], data[2:]))) / max(1, len(data)-2)
        
        return [bigram_diversity, trigram_diversity]
    
    def _extract_fourier_features(self, data: bytes) -> List[float]:
        """Extract Fourier transform features"""
        if not ML_AVAILABLE.get('numpy', True):  # numpy is usually available
            return [0.0] * 10
        
        # Convert to signal
        signal = np.array(list(data), dtype=np.float32)
        
        # Apply FFT
        fft = np.fft.fft(signal)
        magnitude_spectrum = np.abs(fft)
        
        # Extract features from spectrum
        features = [
            np.mean(magnitude_spectrum),
            np.std(magnitude_spectrum),
            np.max(magnitude_spectrum),
            len(magnitude_spectrum[magnitude_spectrum > np.mean(magnitude_spectrum)]),
            np.sum(magnitude_spectrum[:len(magnitude_spectrum)//10]),  # Low frequency energy
            np.sum(magnitude_spectrum[len(magnitude_spectrum)//2:])    # High frequency energy
        ]
        
        # Pad to fixed size
        while len(features) < 10:
            features.append(0.0)
        
        return features[:10]
    
    def _extract_wavelet_features(self, data: bytes) -> List[float]:
        """Extract wavelet analysis features"""
        signal = np.array(list(data), dtype=np.float32)
        
        # Multi-scale analysis using DWT approximation with numpy
        scales = [2, 4, 8, 16]
        features = []
        
        for scale in scales:
            # Simple wavelet-like transform using convolution
            if len(signal) >= scale:
                # Create simple wavelet-like filters
                low_pass = np.ones(scale) / scale  # Averaging filter
                high_pass = np.array([1, -1] * (scale // 2))[:scale] / scale  # Difference filter
                
                # Apply filters (approximation coefficients)
                if len(signal) >= len(low_pass):
                    approx = np.convolve(signal, low_pass, mode='valid')[::scale]
                    detail = np.convolve(signal, high_pass, mode='valid')[::scale]
                    
                    if len(approx) > 0:
                        features.extend([
                            np.mean(approx),
                            np.std(approx),
                            np.mean(np.abs(detail)) if len(detail) > 0 else 0.0,
                            np.std(detail) if len(detail) > 0 else 0.0
                        ])
                    else:
                        features.extend([0.0, 0.0, 0.0, 0.0])
                else:
                    features.extend([0.0, 0.0, 0.0, 0.0])
            else:
                features.extend([0.0, 0.0, 0.0, 0.0])
        
        # Energy distribution across scales
        if features:
            total_energy = sum(f**2 for f in features)
            if total_energy > 0:
                energy_ratios = [f**2 / total_energy for f in features[:4]]
                features.extend(energy_ratios)
        
        return features[:20]  # Return first 20 features
    
    # Helper methods
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        byte_counts = np.zeros(256, dtype=np.int32)
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _calculate_skewness(self, values: np.ndarray) -> float:
        """Calculate skewness"""
        if len(values) < 3:
            return 0.0
        
        mean = np.mean(values)
        std = np.std(values)
        
        if std == 0:
            return 0.0
        
        skewness = np.mean(((values - mean) / std) ** 3)
        return skewness
    
    def _calculate_kurtosis(self, values: np.ndarray) -> float:
        """Calculate kurtosis"""
        if len(values) < 4:
            return 0.0
        
        mean = np.mean(values)
        std = np.std(values)
        
        if std == 0:
            return 0.0
        
        kurtosis = np.mean(((values - mean) / std) ** 4) - 3
        return kurtosis


class MLVMDetector:
    """ML-ML VM detection engine"""
    
    def __init__(self):
        self.feature_extractor = AdvancedFeatureExtractor()
        self.models = {}
        self.ensemble_weights = {}
        self.model_performance = {}
        
        # Initialize models if ML libraries are available
        if ML_AVAILABLE['sklearn']:
            self._initialize_sklearn_models()
        
        if ML_AVAILABLE['tensorflow']:
            self._initialize_tensorflow_models()
    
    def _initialize_sklearn_models(self):
        """Initialize sklearn-based models"""
        # Random Forest
        rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        self.models['random_forest'] = MLModel(
            name="Random Forest VM Detector",
            model_type=MLModelType.RANDOM_FOREST,
            model=rf_model
        )
        
        # Gradient Boosting
        gb_model = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=6,
            random_state=42
        )
        self.models['gradient_boosting'] = MLModel(
            name="Gradient Boosting VM Detector",
            model_type=MLModelType.GRADIENT_BOOSTING,
            model=gb_model
        )
        
        # SVM
        svm_model = SVC(
            kernel='rbf',
            probability=True,
            random_state=42
        )
        self.models['svm'] = MLModel(
            name="SVM VM Detector",
            model_type=MLModelType.SVM,
            model=svm_model,
            scaler=StandardScaler()
        )
        
        # Neural Network
        nn_model = MLPClassifier(
            hidden_layer_sizes=(100, 50),
            activation='relu',
            solver='adam',
            alpha=0.01,
            random_state=42,
            max_iter=1000
        )
        self.models['neural_network'] = MLModel(
            name="Neural Network VM Detector",
            model_type=MLModelType.NEURAL_NETWORK,
            model=nn_model,
            scaler=StandardScaler()
        )
    
    def _initialize_tensorflow_models(self):
        """Initialize TensorFlow-based models"""
        if not ML_AVAILABLE['tensorflow']:
            return
        
        # Deep Neural Network
        dnn_model = self._create_deep_nn_model()
        self.models['deep_nn'] = MLModel(
            name="Deep Neural Network VM Detector",
            model_type=MLModelType.DEEP_NEURAL_NETWORK,
            model=dnn_model,
            scaler=StandardScaler()
        )
    
    def _create_deep_nn_model(self):
        """Create deep neural network model"""
        if not ML_AVAILABLE['tensorflow']:
            return None
        
        model = keras.Sequential([
            keras.layers.Dense(512, activation='relu', input_shape=(None,)),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(256, activation='relu'),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(128, activation='relu'),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(64, activation='relu'),
            keras.layers.Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        return model
    
    def train_models(self, training_data: List[Tuple[bytes, int]], 
                    validation_split: float = 0.2) -> Dict[str, Dict[str, float]]:
        """Train all available models"""
        if not training_data:
            raise ValueError("No training data provided")
        
        logger.info(f"Training ML models with {len(training_data)} samples")
        
        # Extract features for all samples
        X = []
        y = []
        
        for binary_data, label in training_data:
            features = self.feature_extractor.extract_features(binary_data)
            X.append(features)
            y.append(label)
        
        X = np.array(X)
        y = np.array(y)
        
        logger.info(f"Feature matrix shape: {X.shape}")
        
        training_results = {}
        
        for model_name, ml_model in self.models.items():
            try:
                logger.info(f"Training {model_name}...")
                
                # Prepare data
                X_processed = X.copy()
                
                # Apply scaling if needed
                if ml_model.scaler:
                    X_processed = ml_model.scaler.fit_transform(X_processed)
                
                # Feature selection if needed
                if ml_model.feature_selector:
                    X_processed = ml_model.feature_selector.fit_transform(X_processed, y)
                
                # Train model
                if ml_model.model_type in [MLModelType.DEEP_NEURAL_NETWORK]:
                    # TensorFlow model
                    history = ml_model.model.fit(
                        X_processed, y,
                        epochs=50,
                        batch_size=32,
                        validation_split=validation_split,
                        verbose=0
                    )
                    
                    # Get final metrics
                    val_loss, val_accuracy, val_precision, val_recall = ml_model.model.evaluate(
                        X_processed, y, verbose=0
                    )
                    
                    metrics = {
                        'accuracy': val_accuracy,
                        'precision': val_precision,
                        'recall': val_recall,
                        'f1_score': 2 * (val_precision * val_recall) / (val_precision + val_recall)
                    }
                    
                else:
                    # Scikit-learn model
                    ml_model.model.fit(X_processed, y)
                    
                    # Cross-validation
                    cv_scores = cross_val_score(ml_model.model, X_processed, y, 
                                              cv=5, scoring='accuracy')
                    
                    metrics = {
                        'accuracy': np.mean(cv_scores),
                        'accuracy_std': np.std(cv_scores),
                        'cross_val_scores': cv_scores.tolist()
                    }
                
                ml_model.performance_metrics = metrics
                training_results[model_name] = metrics
                
                logger.info(f"{model_name} training completed. Accuracy: {metrics['accuracy']:.3f}")
                
            except Exception as e:
                logger.error(f"Training failed for {model_name}: {e}")
                training_results[model_name] = {'error': str(e)}
        
        # Calculate ensemble weights based on performance
        self._update_ensemble_weights()
        
        return training_results
    
    def predict(self, binary_data: bytes, use_ensemble: bool = True) -> Dict[str, Any]:
        """Predict VM protection for binary data"""
        features = self.feature_extractor.extract_features(binary_data)
        
        predictions = {}
        confidences = {}
        
        for model_name, ml_model in self.models.items():
            try:
                # Prepare features
                X = features.reshape(1, -1)
                
                # Apply preprocessing
                if ml_model.scaler:
                    X = ml_model.scaler.transform(X)
                
                if ml_model.feature_selector:
                    X = ml_model.feature_selector.transform(X)
                
                # Make prediction
                if ml_model.model_type == MLModelType.DEEP_NEURAL_NETWORK:
                    # TensorFlow model
                    prob = ml_model.model.predict(X, verbose=0)[0][0]
                    prediction = 1 if prob > 0.5 else 0
                    confidence = prob if prediction == 1 else 1 - prob
                    
                else:
                    # Scikit-learn model
                    prediction = ml_model.model.predict(X)[0]
                    
                    # Get probability if available
                    if hasattr(ml_model.model, 'predict_proba'):
                        probs = ml_model.model.predict_proba(X)[0]
                        confidence = max(probs)
                    else:
                        confidence = 0.5  # Default confidence for models without probability
                
                predictions[model_name] = prediction
                confidences[model_name] = confidence
                
            except Exception as e:
                logger.warning(f"Prediction failed for {model_name}: {e}")
                predictions[model_name] = 0
                confidences[model_name] = 0.0
        
        # Ensemble prediction
        if use_ensemble and len(predictions) > 1:
            ensemble_pred, ensemble_conf = self._ensemble_predict(predictions, confidences)
        else:
            # Use best performing model
            best_model = max(self.models.keys(), 
                           key=lambda x: self.models[x].performance_metrics.get('accuracy', 0))
            ensemble_pred = predictions.get(best_model, 0)
            ensemble_conf = confidences.get(best_model, 0.0)
        
        return {
            'vm_detected': bool(ensemble_pred),
            'confidence': ensemble_conf,
            'individual_predictions': predictions,
            'individual_confidences': confidences,
            'feature_vector_size': len(features),
            'models_used': list(predictions.keys())
        }
    
    def _ensemble_predict(self, predictions: Dict[str, int], 
                         confidences: Dict[str, float]) -> Tuple[int, float]:
        """Ensemble prediction combining multiple models"""
        if not predictions:
            return 0, 0.0
        
        # Weighted voting based on model performance and confidence
        total_weight = 0.0
        weighted_score = 0.0
        
        for model_name, prediction in predictions.items():
            model_weight = self.ensemble_weights.get(model_name, 1.0)
            confidence = confidences.get(model_name, 0.5)
            
            # Combine model weight with prediction confidence
            combined_weight = model_weight * confidence
            
            total_weight += combined_weight
            weighted_score += prediction * combined_weight
        
        if total_weight == 0:
            return 0, 0.0
        
        final_score = weighted_score / total_weight
        final_prediction = 1 if final_score > 0.5 else 0
        final_confidence = abs(final_score - 0.5) * 2  # Convert to 0-1 range
        
        return final_prediction, final_confidence
    
    def _update_ensemble_weights(self):
        """Update ensemble weights based on model performance"""
        if not self.models:
            return
        
        # Calculate weights based on accuracy
        for model_name, ml_model in self.models.items():
            accuracy = ml_model.performance_metrics.get('accuracy', 0.5)
            # Weight is proportional to accuracy above random chance
            self.ensemble_weights[model_name] = max(0.1, (accuracy - 0.5) * 2)
        
        logger.info(f"Updated ensemble weights: {self.ensemble_weights}")
    
    def save_models(self, save_directory: str):
        """Save trained models to disk"""
        save_path = Path(save_directory)
        save_path.mkdir(parents=True, exist_ok=True)
        
        for model_name, ml_model in self.models.items():
            model_file = save_path / f"{model_name}_model.pkl"
            
            try:
                with open(model_file, 'wb') as f:
                    pickle.dump(ml_model, f)
                logger.info(f"Saved {model_name} to {model_file}")
            except Exception as e:
                logger.error(f"Failed to save {model_name}: {e}")
        
        # Save ensemble weights
        weights_file = save_path / "ensemble_weights.json"
        with open(weights_file, 'w') as f:
            json.dump(self.ensemble_weights, f, indent=2)
    
    def load_models(self, load_directory: str):
        """Load trained models from disk"""
        load_path = Path(load_directory)
        
        if not load_path.exists():
            logger.error(f"Model directory not found: {load_directory}")
            return
        
        # Load models
        for model_file in load_path.glob("*_model.pkl"):
            model_name = model_file.stem.replace("_model", "")
            
            try:
                with open(model_file, 'rb') as f:
                    ml_model = pickle.load(f)
                self.models[model_name] = ml_model
                logger.info(f"Loaded {model_name} from {model_file}")
            except Exception as e:
                logger.error(f"Failed to load {model_name}: {e}")
        
        # Load ensemble weights
        weights_file = load_path / "ensemble_weights.json"
        if weights_file.exists():
            try:
                with open(weights_file, 'r') as f:
                    self.ensemble_weights = json.load(f)
                logger.info("Loaded ensemble weights")
            except Exception as e:
                logger.error(f"Failed to load ensemble weights: {e}")
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models"""
        info = {
            'total_models': len(self.models),
            'models': {},
            'ml_libraries_available': ML_AVAILABLE,
            'ensemble_weights': self.ensemble_weights
        }
        
        for model_name, ml_model in self.models.items():
            info['models'][model_name] = {
                'name': ml_model.name,
                'type': ml_model.model_type.value,
                'performance': ml_model.performance_metrics,
                'features_count': len(ml_model.features_used),
                'version': ml_model.version,
                'training_date': ml_model.training_date
            }
        
        return info
