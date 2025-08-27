# VMDragonSlayer - Enhanced VM detection and analysis library
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
Extended Integration
===========================

Integration layer for Extended features:
- Enhanced pattern analysis integration
- Multi-architecture detection coordination  
- ML-enhanced detection pipeline
- Enhanced symbolic execution integration
- Real-time analysis orchestration
- Anti-evasion technique coordination
- Unified API for all Extended features
"""

import logging
import time
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import asyncio
from pathlib import Path

logger = logging.getLogger(__name__)

# Import Extended components with graceful fallbacks
try:
    from ..analysis.pattern_analysis.extended_recognizer import (
        ExtendedPatternMatcher, MetamorphicPatternEngine, ContextualAnalyzer
    )
    Extended_PATTERNS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Extended patterns not available: {e}")
    Extended_PATTERNS_AVAILABLE = False

try:
    from ..analysis.multi_arch.cross_platform_detector import (
        CrossArchitectureVMDetector, ArchitectureDetector
    )
    MULTI_ARCH_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Multi-architecture detection not available: {e}")
    MULTI_ARCH_AVAILABLE = False

try:
    from ..ml.ml_detection import MLVMDetector, MLFeatureExtractor
    ML_DETECTION_AVAILABLE = True
except ImportError as e:
    logger.warning(f"ML detection not available: {e}")
    ML_DETECTION_AVAILABLE = False

try:
    from ..analysis.symbolic_execution.symbolic_engine import (
        SymbolicExecutor, ExecutionStrategy
    )
    SYMBOLIC_EXECUTION_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Symbolic execution not available: {e}")
    SYMBOLIC_EXECUTION_AVAILABLE = False

try:
    from ..realtime.analysis_engine import (
        RealtimeAnalysisEngine, AnalysisTask, AnalysisType, Priority
    )
    REALTIME_ANALYSIS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Real-time analysis not available: {e}")
    REALTIME_ANALYSIS_AVAILABLE = False

try:
    from ..analysis.anti_evasion.security_extensions import EnhancedAntiEvasion
    ANTI_EVASION_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Anti-evasion countermeasures not available: {e}")
    ANTI_EVASION_AVAILABLE = False


class AnalysisMode(Enum):
    """Enhanced analysis modes"""
    BASIC = "basic"
    COMPREHENSIVE = "comprehensive"
    ML_ENHANCED = "ml_enhanced"
    SYMBOLIC = "symbolic"
    REALTIME = "realtime"
    MULTI_ARCH = "multi_arch"
    STEALTH = "stealth"
    MAXIMUM = "maximum"


class FeatureSet(Enum):
    """Available feature sets"""
    PATTERN_ANALYSIS = "pattern_analysis"
    MULTI_ARCHITECTURE = "multi_architecture"
    MACHINE_LEARNING = "machine_learning"
    SYMBOLIC_EXECUTION = "symbolic_execution"
    REALTIME_MONITORING = "realtime_monitoring"
    ANTI_EVASION = "anti_evasion"


@dataclass
class EnhancedAnalysisConfig:
    """Configuration for Enhanced analysis"""
    mode: AnalysisMode = AnalysisMode.COMPREHENSIVE
    enabled_features: List[FeatureSet] = field(default_factory=lambda: list(FeatureSet))
    
    # Pattern analysis settings
    enable_metamorphic_detection: bool = True
    contextual_analysis_depth: int = 3
    pattern_sensitivity: float = 0.8
    
    # Multi-architecture settings
    target_architectures: List[str] = field(default_factory=lambda: ['x86', 'x64', 'arm64'])
    cross_arch_optimization: bool = True
    
    # ML settings
    ml_model_ensemble: bool = True
    ml_confidence_threshold: float = 0.7
    feature_extraction_level: str = "comprehensive"
    
    # Symbolic execution settings
    symbolic_max_paths: int = 50
    symbolic_max_depth: int = 1000
    symbolic_timeout: int = 300
    execution_strategy: str = "hybrid"
    
    # Real-time settings
    realtime_enabled: bool = False
    monitor_paths: List[str] = field(default_factory=list)
    max_workers: int = 4
    
    # Anti-evasion settings
    stealth_mode: bool = False
    behavioral_mimicry: bool = True
    timing_randomization: bool = True
    
    # Performance settings
    max_analysis_time: int = 600  # seconds
    memory_limit_mb: int = 2048
    cpu_priority: str = "normal"


@dataclass
class EnhancedAnalysisResult:
    """Comprehensive analysis result"""
    # Basic analysis info
    analysis_id: str
    target_binary: str
    analysis_mode: AnalysisMode
    start_time: float
    end_time: float
    
    # Feature-specific results
    pattern_analysis: Optional[Dict[str, Any]] = None
    multi_arch_analysis: Optional[Dict[str, Any]] = None
    ml_analysis: Optional[Dict[str, Any]] = None
    symbolic_analysis: Optional[Dict[str, Any]] = None
    realtime_analysis: Optional[Dict[str, Any]] = None
    anti_evasion_analysis: Optional[Dict[str, Any]] = None
    
    # Overall assessment
    vm_detected: bool = False
    confidence_score: float = 0.0
    detection_methods: List[str] = field(default_factory=list)
    vm_types_detected: List[str] = field(default_factory=list)
    evasion_techniques: List[str] = field(default_factory=list)
    
    # Performance metrics
    total_analysis_time: float = 0.0
    memory_peak_mb: float = 0.0
    features_used: List[str] = field(default_factory=list)
    
    # Warnings and errors
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class UnifiedIntegratedAnalyzer:
    """Integrated analyzer for all Phase 2 Enhanced features"""
    
    def __init__(self, config: Optional[EnhancedAnalysisConfig] = None):
        self.config = config or EnhancedAnalysisConfig()
        self.components = {}
        self.realtime_engine = None
        
        # Initialize available components
        self._initialize_components()
        
        # Validate configuration
        self._validate_configuration()
        
        logger.info(f"Phase 2 Integrated Analyzer initialized with {len(self.components)} components")
    
    def _initialize_components(self):
        """Initialize available components"""
        
        # Pattern Analysis
        if EXTENDED_PATTERNS_AVAILABLE and FeatureSet.PATTERN_ANALYSIS in self.config.enabled_features:
            try:
                self.components['pattern_matcher'] = ExtendedPatternMatcher()
                self.components['metamorphic_engine'] = MetamorphicPatternEngine()
                self.components['contextual_analyzer'] = ContextualAnalyzer()
                logger.info("Pattern analysis components initialized")
            except Exception as e:
                logger.error(f"Failed to initialize pattern analysis: {e}")
        
        # Multi-Architecture Detection
        if MULTI_ARCH_AVAILABLE and FeatureSet.MULTI_ARCHITECTURE in self.config.enabled_features:
            try:
                self.components['arch_detector'] = ArchitectureDetector()
                self.components['cross_arch_detector'] = CrossArchitectureVMDetector()
                logger.info("Multi-architecture detection components initialized")
            except Exception as e:
                logger.error(f"Failed to initialize multi-architecture detection: {e}")
        
        # Machine Learning Detection
        if ML_DETECTION_AVAILABLE and FeatureSet.MACHINE_LEARNING in self.config.enabled_features:
            try:
                self.components['ml_detector'] = MLVMDetector()
                self.components['feature_extractor'] = MLFeatureExtractor()
                logger.info("ML detection components initialized")
            except Exception as e:
                logger.error(f"Failed to initialize ML detection: {e}")
        
        # Symbolic Execution
        if SYMBOLIC_EXECUTION_AVAILABLE and FeatureSet.SYMBOLIC_EXECUTION in self.config.enabled_features:
            try:
                strategy = ExecutionStrategy[self.config.execution_strategy.upper()]
                self.components['symbolic_executor'] = SymbolicExecutor(strategy)
                logger.info("Symbolic execution components initialized")
            except Exception as e:
                logger.error(f"Failed to initialize symbolic execution: {e}")
        
        # Anti-Evasion Countermeasures
        if ANTI_EVASION_AVAILABLE and FeatureSet.ANTI_EVASION in self.config.enabled_features:
            try:
                self.components['anti_evasion'] = EnhancedAntiEvasion(
                    stealth_mode=self.config.stealth_mode,
                    behavioral_mimicry=self.config.behavioral_mimicry
                )
                logger.info("Anti-evasion components initialized")
            except Exception as e:
                logger.error(f"Failed to initialize anti-evasion: {e}")
        
        # Real-time Analysis
        if REALTIME_ANALYSIS_AVAILABLE and FeatureSet.REALTIME_MONITORING in self.config.enabled_features:
            try:
                if self.config.realtime_enabled:
                    self.realtime_engine = RealtimeAnalysisEngine(
                        max_workers=self.config.max_workers
                    )
                    self.components['realtime_engine'] = self.realtime_engine
                    logger.info("Real-time analysis components initialized")
            except Exception as e:
                logger.error(f"Failed to initialize real-time analysis: {e}")
    
    def _validate_configuration(self):
        """Validate configuration against available components"""
        warnings = []
        
        for feature in self.config.enabled_features:
            if feature == FeatureSet.PATTERN_ANALYSIS and not EXTENDED_PATTERNS_AVAILABLE:
                warnings.append(f"Pattern analysis requested but not available")
            elif feature == FeatureSet.MULTI_ARCHITECTURE and not MULTI_ARCH_AVAILABLE:
                warnings.append(f"Multi-architecture detection requested but not available")
            elif feature == FeatureSet.MACHINE_LEARNING and not ML_DETECTION_AVAILABLE:
                warnings.append(f"ML detection requested but not available")
            elif feature == FeatureSet.SYMBOLIC_EXECUTION and not SYMBOLIC_EXECUTION_AVAILABLE:
                warnings.append(f"Symbolic execution requested but not available")
            elif feature == FeatureSet.REALTIME_MONITORING and not REALTIME_ANALYSIS_AVAILABLE:
                warnings.append(f"Real-time monitoring requested but not available")
            elif feature == FeatureSet.ANTI_EVASION and not ANTI_EVASION_AVAILABLE:
                warnings.append(f"Anti-evasion countermeasures requested but not available")
        
        for warning in warnings:
            logger.warning(warning)
    
    def analyze(self, binary_path: str) -> EnhancedAnalysisResult:
        """Perform comprehensive Enhanced analysis"""
        analysis_id = f"analysis_{int(time.time() * 1000000)}"
        start_time = time.time()
        
        logger.info(f"Starting Phase 2 analysis {analysis_id} for {binary_path}")
        
        # Initialize result
        result = EnhancedAnalysisResult(
            analysis_id=analysis_id,
            target_binary=binary_path,
            analysis_mode=self.config.mode,
            start_time=start_time,
            end_time=0.0
        )
        
        try:
            # Load binary data
            binary_data = self._load_binary(binary_path)
            
            # Apply anti-evasion countermeasures if enabled
            if 'anti_evasion' in self.components:
                self._apply_anti_evasion_countermeasures(result)
            
            # Run enabled analyses in order of dependency
            if 'arch_detector' in self.components:
                result.multi_arch_analysis = self._run_multi_arch_analysis(binary_data, result)
            
            if 'pattern_matcher' in self.components:
                result.pattern_analysis = self._run_pattern_analysis(binary_data, result)
            
            if 'ml_detector' in self.components:
                result.ml_analysis = self._run_ml_analysis(binary_data, result)
            
            if 'symbolic_executor' in self.components:
                result.symbolic_analysis = self._run_symbolic_analysis(binary_data, result)
            
            # Combine results for overall assessment
            self._compute_overall_assessment(result)
            
        except Exception as e:
            logger.error(f"Analysis {analysis_id} failed: {e}")
            result.errors.append(str(e))
        
        finally:
            result.end_time = time.time()
            result.total_analysis_time = result.end_time - result.start_time
            
        logger.info(f"Analysis {analysis_id} completed in {result.total_analysis_time:.2f}s")
        return result
    
    def start_realtime_monitoring(self) -> bool:
        """Start real-time monitoring if enabled"""
        if not self.realtime_engine:
            logger.warning("Real-time monitoring not enabled")
            return False
        
        try:
            self.realtime_engine.start(monitor_paths=self.config.monitor_paths)
            logger.info("Real-time monitoring started")
            return True
        except Exception as e:
            logger.error(f"Failed to start real-time monitoring: {e}")
            return False
    
    def stop_realtime_monitoring(self):
        """Stop real-time monitoring"""
        if self.realtime_engine:
            self.realtime_engine.stop()
            logger.info("Real-time monitoring stopped")
    
    def _load_binary(self, binary_path: str) -> bytes:
        """Load binary data with error handling"""
        try:
            path = Path(binary_path)
            if not path.exists():
                raise FileNotFoundError(f"Binary not found: {binary_path}")
            
            with open(path, 'rb') as f:
                return f.read()
                
        except Exception as e:
            logger.error(f"Failed to load binary {binary_path}: {e}")
            raise
    
    def _apply_anti_evasion_countermeasures(self, result: EnhancedAnalysisResult):
        """Apply anti-evasion countermeasures"""
        try:
            anti_evasion = self.components['anti_evasion']
            
            # Apply countermeasures
            countermeasures_applied = anti_evasion.apply_comprehensive_countermeasures()
            
            result.anti_evasion_analysis = {
                'countermeasures_applied': countermeasures_applied,
                'stealth_mode': self.config.stealth_mode,
                'behavioral_mimicry_active': anti_evasion.behavioral_mimicry.is_active if hasattr(anti_evasion, 'behavioral_mimicry') else False
            }
            
            logger.debug(f"Applied {len(countermeasures_applied)} anti-evasion countermeasures")
            
        except Exception as e:
            logger.warning(f"Anti-evasion countermeasures failed: {e}")
            result.warnings.append(f"Anti-evasion error: {str(e)}")
    
    def _run_pattern_analysis(self, binary_data: bytes, result: EnhancedAnalysisResult) -> Dict[str, Any]:
        """Run Enhanced pattern analysis"""
        try:
            pattern_matcher = self.components['pattern_matcher']
            metamorphic_engine = self.components['metamorphic_engine']
            contextual_analyzer = self.components['contextual_analyzer']
            
            # Enhanced pattern matching
            pattern_results = pattern_matcher.analyze_comprehensive(binary_data)
            
            # Metamorphic analysis if enabled
            metamorphic_results = None
            if self.config.enable_metamorphic_detection:
                metamorphic_results = metamorphic_engine.analyze_metamorphic_variants(binary_data)
            
            # Contextual analysis
            contextual_results = contextual_analyzer.analyze_with_context(
                binary_data, depth=self.config.contextual_analysis_depth
            )
            
            # Combine results
            analysis_result = {
                'pattern_matches': pattern_results.get('matches', []),
                'confidence': pattern_results.get('overall_confidence', 0.0),
                'vm_types': pattern_results.get('detected_types', []),
                'metamorphic_analysis': metamorphic_results,
                'contextual_analysis': contextual_results
            }
            
            # Update overall result
            if analysis_result['confidence'] >= self.config.pattern_sensitivity:
                result.vm_detected = True
                result.detection_methods.append('Securitypatterns')
                result.vm_types_detected.extend(analysis_result['vm_types'])
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Pattern analysis failed: {e}")
            result.errors.append(f"Pattern analysis error: {str(e)}")
            return {'error': str(e)}
    
    def _run_multi_arch_analysis(self, binary_data: bytes, result: EnhancedAnalysisResult) -> Dict[str, Any]:
        """Run multi-architecture analysis"""
        try:
            arch_detector = self.components['arch_detector']
            cross_arch_detector = self.components['cross_arch_detector']
            
            # Detect architecture
            detected_arch = arch_detector.detect_architecture(binary_data)
            
            # Cross-architecture VM detection
            cross_arch_results = cross_arch_detector.analyze_cross_platform(
                binary_data, target_architectures=self.config.target_architectures
            )
            
            analysis_result = {
                'detected_architecture': detected_arch,
                'cross_platform_results': cross_arch_results,
                'vm_patterns_found': cross_arch_results.get('vm_patterns', []),
                'architecture_confidence': cross_arch_results.get('confidence', 0.0)
            }
            
            # Update overall result
            if cross_arch_results.get('vm_detected', False):
                result.vm_detected = True
                result.detection_methods.append('multi_architecture')
                result.vm_types_detected.extend(cross_arch_results.get('vm_types', []))
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Multi-architecture analysis failed: {e}")
            result.errors.append(f"Multi-architecture error: {str(e)}")
            return {'error': str(e)}
    
    def _run_ml_analysis(self, binary_data: bytes, result: EnhancedAnalysisResult) -> Dict[str, Any]:
        """Run machine learning analysis"""
        try:
            ml_detector = self.components['ml_detector']
            
            # ML-based VM detection
            ml_results = ml_detector.predict(binary_data, use_ensemble=self.config.ml_model_ensemble)
            
            analysis_result = {
                'ml_prediction': ml_results.get('vm_detected', False),
                'confidence': ml_results.get('confidence', 0.0),
                'models_used': ml_results.get('models_used', []),
                'individual_predictions': ml_results.get('individual_predictions', {}),
                'feature_vector_size': ml_results.get('feature_vector_size', 0)
            }
            
            # Update overall result
            if (ml_results.get('vm_detected', False) and 
                ml_results.get('confidence', 0.0) >= self.config.ml_confidence_threshold):
                result.vm_detected = True
                result.detection_methods.append('machine_learning')
                result.confidence_score = max(result.confidence_score, ml_results.get('confidence', 0.0))
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"ML analysis failed: {e}")
            result.errors.append(f"ML analysis error: {str(e)}")
            return {'error': str(e)}
    
    def _run_symbolic_analysis(self, binary_data: bytes, result: EnhancedAnalysisResult) -> Dict[str, Any]:
        """Run symbolic execution analysis"""
        try:
            symbolic_executor = self.components['symbolic_executor']
            
            # Symbolic execution
            symbolic_results = symbolic_executor.execute(
                binary_data,
                max_paths=self.config.symbolic_max_paths
            )
            
            analysis_result = {
                'paths_explored': symbolic_results.get('paths_completed', 0),
                'vm_detections': symbolic_results.get('vm_detections', []),
                'execution_time': symbolic_results.get('execution_time', 0.0),
                'coverage': symbolic_results.get('coverage', {}),
                'interesting_paths': symbolic_results.get('interesting_paths', [])
            }
            
            # Update overall result
            vm_detections = symbolic_results.get('vm_detections', [])
            if vm_detections:
                result.vm_detected = True
                result.detection_methods.append('symbolic_execution')
                
                # Extract VM types from symbolic analysis
                for detection in vm_detections:
                    if 'type' in detection:
                        result.vm_types_detected.append(detection['type'])
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Symbolic analysis failed: {e}")
            result.errors.append(f"Symbolic analysis error: {str(e)}")
            return {'error': str(e)}
    
    def _compute_overall_assessment(self, result: EnhancedAnalysisResult):
        """Compute overall analysis assessment"""
        
        # Collect confidence scores from different methods
        confidence_scores = []
        
        if result.pattern_analysis and 'confidence' in result.pattern_analysis:
            confidence_scores.append(result.pattern_analysis['confidence'])
        
        if result.multi_arch_analysis and 'architecture_confidence' in result.multi_arch_analysis:
            confidence_scores.append(result.multi_arch_analysis['architecture_confidence'])
        
        if result.ml_analysis and 'confidence' in result.ml_analysis:
            confidence_scores.append(result.ml_analysis['confidence'])
        
        # Symbolic execution contributes to confidence based on VM detections
        if result.symbolic_analysis and result.symbolic_analysis.get('vm_detections'):
            symbolic_confidence = min(0.9, len(result.symbolic_analysis['vm_detections']) * 0.3)
            confidence_scores.append(symbolic_confidence)
        
        # Calculate weighted average confidence
        if confidence_scores:
            result.confidence_score = sum(confidence_scores) / len(confidence_scores)
        
        # Remove duplicates from detection lists
        result.detection_methods = list(set(result.detection_methods))
        result.vm_types_detected = list(set(result.vm_types_detected))
        
        # Extract evasion techniques if anti-evasion was used
        if result.anti_evasion_analysis:
            countermeasures = result.anti_evasion_analysis.get('countermeasures_applied', [])
            result.evasion_techniques = [cm['type'] for cm in countermeasures if 'type' in cm]
        
        # Set features used
        result.features_used = list(self.components.keys())
        
        logger.info(f"Overall assessment - VM Detected: {result.vm_detected}, "
                   f"Confidence: {result.confidence_score:.2f}, "
                   f"Methods: {result.detection_methods}")
    
    def get_capabilities(self) -> Dict[str, Any]:
        """Get analyzer capabilities"""
        return {
            'available_features': list(self.components.keys()),
            'configuration': {
                'mode': self.config.mode.value,
                'enabled_features': [f.value for f in self.config.enabled_features],
                'realtime_enabled': self.config.realtime_enabled,
                'stealth_mode': self.config.stealth_mode
            },
            'component_status': {
                'pattern_analysis': EXTENDED_PATTERNS_AVAILABLE,
                'multi_architecture': MULTI_ARCH_AVAILABLE,
                'machine_learning': ML_DETECTION_AVAILABLE,
                'symbolic_execution': SYMBOLIC_EXECUTION_AVAILABLE,
                'realtime_analysis': REALTIME_ANALYSIS_AVAILABLE,
                'anti_evasion': ANTI_EVASION_AVAILABLE
            }
        }


def create_Unified_analyzer(
    mode: AnalysisMode = AnalysisMode.COMPREHENSIVE,
    features: Optional[List[FeatureSet]] = None,
    **kwargs
) -> UnifiedIntegratedAnalyzer:
    """Convenience function to create Phase 2 analyzer"""
    
    if features is None:
        # Enable all available features by default
        features = []
        if EXTENDED_PATTERNS_AVAILABLE:
            features.append(FeatureSet.PATTERN_ANALYSIS)
        if MULTI_ARCH_AVAILABLE:
            features.append(FeatureSet.MULTI_ARCHITECTURE)
        if ML_DETECTION_AVAILABLE:
            features.append(FeatureSet.MACHINE_LEARNING)
        if SYMBOLIC_EXECUTION_AVAILABLE:
            features.append(FeatureSet.SYMBOLIC_EXECUTION)
        if REALTIME_ANALYSIS_AVAILABLE:
            features.append(FeatureSet.REALTIME_MONITORING)
        if ANTI_EVASION_AVAILABLE:
            features.append(FeatureSet.ANTI_EVASION)
    
    config = EnhancedAnalysisConfig(
        mode=mode,
        enabled_features=features,
        **kwargs
    )
    
    return UnifiedIntegratedAnalyzer(config)
