#!/usr/bin/env python3

"""
VMDragonSlayer Extended Features Demo
============================================

Comprehensive demonstration of Extended features:
- Extended pattern analysis with metamorphic detection
- Multi-architecture cross-platform VM detection  
- Machine learning enhanced detection
- Extended symbolic execution with constraint solving
- Real-time analysis capabilities
- Sophisticated anti-evasion countermeasures

This example showcases the integrated Phase 2 capabilities
and demonstrates enterprise-grade VM detection features.
"""

import sys
import time
import logging
from pathlib import Path

# Add the dragonslayer package to the path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from dragonslayer.extended_integration import (
        create_extended_analyzer, AnalysisMode, FeatureSet,
        ExtendedAnalysisConfig
    )
    from dragonslayer.core.orchestrator import DragonSlayerOrchestrator
    from dragonslayer.utils.logger import setup_logger
except ImportError as e:
    print(f"Error importing DragonSlayer modules: {e}")
    print("Please ensure the package is properly installed.")
    sys.exit(1)

def main():
    """Main Phase 2 demonstration function"""
    
    # Setup logging
    setup_logger(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    print("=" * 80)
    print("VMDragonSlayer Extended Features Demonstration")
    print("=" * 80)
    print()
    
    # Create sample binary data for testing
    sample_binary = create_sample_binary()
    
    # Demo 1: Comprehensive Analysis Mode
    print("🔍 Demo 1: Comprehensive Analysis with All Features")
    print("-" * 60)
    
    try:
        # Create Phase 2 analyzer with all features
        analyzer = create_extended_analyzer(
            mode=AnalysisMode.COMPREHENSIVE,
            # Enable all available features
            features=[
                FeatureSet.PATTERN_ANALYSIS,
                FeatureSet.MULTI_ARCHITECTURE, 
                FeatureSet.MACHINE_LEARNING,
                FeatureSet.SYMBOLIC_EXECUTION,
                FeatureSet.ANTI_EVASION
            ],
            # Configure Extended options
            enable_metamorphic_detection=True,
            target_architectures=['x86', 'x64', 'arm64'],
            ml_model_ensemble=True,
            symbolic_max_paths=25,
            stealth_mode=True,
            behavioral_mimicry=True
        )
        
        # Display analyzer capabilities
        capabilities = analyzer.get_capabilities()
        print(f"✓ Analyzer initialized with {len(capabilities['available_features'])} features:")
        for feature in capabilities['available_features']:
            print(f"  • {feature}")
        print()
        
        # Write sample binary to temp file
        temp_binary_path = Path("temp_sample.bin")
        with open(temp_binary_path, 'wb') as f:
            f.write(sample_binary)
        
        # Perform comprehensive analysis
        print("🔬 Running comprehensive analysis...")
        start_time = time.time()
        
        result = analyzer.analyze(str(temp_binary_path))
        
        analysis_time = time.time() - start_time
        print(f"✓ Analysis completed in {analysis_time:.2f} seconds")
        print()
        
        # Display results
        display_analysis_results(result)
        
        # Clean up temp file
        temp_binary_path.unlink()
        
    except Exception as e:
        logger.error(f"Comprehensive analysis demo failed: {e}")
        print(f"❌ Error: {e}")
    
    print()
    
    # Demo 2: ML-Enhanced Analysis
    print("🧠 Demo 2: Machine Learning Enhanced Detection")
    print("-" * 60)
    
    try:
        # Create ML-focused analyzer
        ml_analyzer = create_extended_analyzer(
            mode=AnalysisMode.ML_ENHANCED,
            features=[FeatureSet.MACHINE_LEARNING, FeatureSet.PATTERN_ANALYSIS],
            ml_model_ensemble=True,
            ml_confidence_threshold=0.6,
            feature_extraction_level="comprehensive"
        )
        
        print("🔬 Running ML-enhanced analysis...")
        
        temp_binary_path = Path("temp_ml_sample.bin")
        with open(temp_binary_path, 'wb') as f:
            f.write(create_vm_binary_sample())
        
        ml_result = ml_analyzer.analyze(str(temp_binary_path))
        
        print(f"✓ ML Analysis Results:")
        if ml_result.ml_analysis:
            ml_data = ml_result.ml_analysis
            print(f"  • VM Detected: {ml_data.get('ml_prediction', False)}")
            print(f"  • Confidence: {ml_data.get('confidence', 0.0):.2f}")
            print(f"  • Models Used: {', '.join(ml_data.get('models_used', []))}")
            print(f"  • Feature Vector Size: {ml_data.get('feature_vector_size', 0)}")
        print()
        
        temp_binary_path.unlink()
        
    except Exception as e:
        logger.error(f"ML-enhanced analysis demo failed: {e}")
        print(f"❌ Error: {e}")
    
    print()
    
    # Demo 3: Multi-Architecture Analysis
    print("🏗️ Demo 3: Multi-Architecture Cross-Platform Detection")
    print("-" * 60)
    
    try:
        # Create multi-arch analyzer
        multiarch_analyzer = create_extended_analyzer(
            mode=AnalysisMode.MULTI_ARCH,
            features=[FeatureSet.MULTI_ARCHITECTURE, FeatureSet.PATTERN_ANALYSIS],
            target_architectures=['x86', 'x64', 'arm32', 'arm64', 'mips'],
            cross_arch_optimization=True
        )
        
        print("🔬 Running multi-architecture analysis...")
        
        # Test different architecture samples
        architectures = ['x86', 'x64', 'arm64']
        for arch in architectures:
            print(f"  Testing {arch} binary...")
            
            temp_binary_path = Path(f"temp_{arch}_sample.bin")
            with open(temp_binary_path, 'wb') as f:
                f.write(create_arch_binary_sample(arch))
            
            arch_result = multiarch_analyzer.analyze(str(temp_binary_path))
            
            if arch_result.multi_arch_analysis:
                arch_data = arch_result.multi_arch_analysis
                detected_arch = arch_data.get('detected_architecture', 'unknown')
                confidence = arch_data.get('architecture_confidence', 0.0)
                print(f"    • Detected Architecture: {detected_arch}")
                print(f"    • Confidence: {confidence:.2f}")
            
            temp_binary_path.unlink()
        
        print()
        
    except Exception as e:
        logger.error(f"Multi-architecture analysis demo failed: {e}")
        print(f"❌ Error: {e}")
    
    print()
    
    # Demo 4: Symbolic Execution Analysis
    print("🎯 Demo 4: Extended Symbolic Execution")
    print("-" * 60)
    
    try:
        # Create symbolic execution analyzer
        symbolic_analyzer = create_extended_analyzer(
            mode=AnalysisMode.SYMBOLIC,
            features=[FeatureSet.SYMBOLIC_EXECUTION, FeatureSet.PATTERN_ANALYSIS],
            symbolic_max_paths=10,
            symbolic_max_depth=100,
            execution_strategy="vm_focused"
        )
        
        print("🔬 Running symbolic execution analysis...")
        
        temp_binary_path = Path("temp_symbolic_sample.bin")
        with open(temp_binary_path, 'wb') as f:
            f.write(create_complex_binary_sample())
        
        symbolic_result = symbolic_analyzer.analyze(str(temp_binary_path))
        
        if symbolic_result.symbolic_analysis:
            symbolic_data = symbolic_result.symbolic_analysis
            print(f"  • Paths Explored: {symbolic_data.get('paths_explored', 0)}")
            print(f"  • VM Detections: {len(symbolic_data.get('vm_detections', []))}")
            print(f"  • Execution Time: {symbolic_data.get('execution_time', 0.0):.2f}s")
            print(f"  • Interesting Paths: {len(symbolic_data.get('interesting_paths', []))}")
            
            # Show VM detections
            vm_detections = symbolic_data.get('vm_detections', [])
            if vm_detections:
                print("  • VM Detection Details:")
                for detection in vm_detections[:3]:  # Show first 3
                    print(f"    - Type: {detection.get('type', 'unknown')}")
                    print(f"      Description: {detection.get('description', 'N/A')}")
        
        print()
        temp_binary_path.unlink()
        
    except Exception as e:
        logger.error(f"Symbolic execution demo failed: {e}")
        print(f"❌ Error: {e}")
    
    print()
    
    # Demo 5: Stealth Mode with Anti-Evasion
    print("🥷 Demo 5: Stealth Mode with Anti-Evasion Countermeasures")
    print("-" * 60)
    
    try:
        # Create stealth analyzer
        stealth_analyzer = create_extended_analyzer(
            mode=AnalysisMode.STEALTH,
            features=[FeatureSet.ANTI_EVASION, FeatureSet.PATTERN_ANALYSIS],
            stealth_mode=True,
            behavioral_mimicry=True,
            timing_randomization=True
        )
        
        print("🔬 Running stealth analysis with anti-evasion...")
        
        temp_binary_path = Path("temp_stealth_sample.bin")
        with open(temp_binary_path, 'wb') as f:
            f.write(create_evasive_binary_sample())
        
        stealth_result = stealth_analyzer.analyze(str(temp_binary_path))
        
        if stealth_result.anti_evasion_analysis:
            anti_evasion_data = stealth_result.anti_evasion_analysis
            countermeasures = anti_evasion_data.get('countermeasures_applied', [])
            print(f"  • Countermeasures Applied: {len(countermeasures)}")
            print(f"  • Stealth Mode Active: {anti_evasion_data.get('stealth_mode', False)}")
            print(f"  • Behavioral Mimicry: {anti_evasion_data.get('behavioral_mimicry_active', False)}")
            
            # Show applied countermeasures
            if countermeasures:
                print("  • Applied Countermeasures:")
                for cm in countermeasures[:5]:  # Show first 5
                    cm_type = cm.get('type', 'unknown') if isinstance(cm, dict) else str(cm)
                    print(f"    - {cm_type}")
        
        print(f"  • Overall VM Detection: {'Yes' if stealth_result.vm_detected else 'No'}")
        print(f"  • Confidence Score: {stealth_result.confidence_score:.2f}")
        print()
        
        temp_binary_path.unlink()
        
    except Exception as e:
        logger.error(f"Stealth analysis demo failed: {e}")
        print(f"❌ Error: {e}")
    
    print()
    
    # Demo 6: Real-time Analysis (if available)
    print("⚡ Demo 6: Real-time Analysis Capabilities")
    print("-" * 60)
    
    try:
        # Create real-time analyzer
        realtime_analyzer = create_extended_analyzer(
            mode=AnalysisMode.REALTIME,
            features=[FeatureSet.REALTIME_MONITORING, FeatureSet.PATTERN_ANALYSIS],
            realtime_enabled=True,
            max_workers=2,
            monitor_paths=[str(Path.cwd())]  # Monitor current directory
        )
        
        print("🔬 Testing real-time analysis capabilities...")
        
        # Check if real-time monitoring can be started
        if hasattr(realtime_analyzer, 'start_realtime_monitoring'):
            print("  • Real-time monitoring available")
            print("  • In a production environment, this would monitor:")
            print("    - File system changes")
            print("    - Process creation/modification")
            print("    - Memory analysis")
            print("    - Network activity")
            print("  • Results would be provided via callbacks and dashboard")
        else:
            print("  • Real-time monitoring not available (missing dependencies)")
        
        print()
        
    except Exception as e:
        logger.error(f"Real-time analysis demo failed: {e}")
        print(f"❌ Error: {e}")
    
    print()
    print("=" * 80)
    print("Extended Features Demonstration Complete!")
    print("=" * 80)
    print()
    print("📊 Summary of Extended Capabilities Demonstrated:")
    print("  ✓ Extended pattern analysis with metamorphic detection")
    print("  ✓ Multi-architecture cross-platform VM detection")
    print("  ✓ Machine learning enhanced detection with ensemble methods")
    print("  ✓ Extended symbolic execution with constraint solving")
    print("  ✓ Sophisticated anti-evasion countermeasures")
    print("  ✓ Real-time analysis architecture (when dependencies available)")
    print()
    print("🚀 VMDragonSlayer Phase 2 provides enterprise-grade")
    print("   VM detection capabilities with cutting-edge techniques!")


def display_analysis_results(result):
    """Display comprehensive analysis results"""
    print(f"📋 Analysis Results for: {result.target_binary}")
    print(f"   Analysis ID: {result.analysis_id}")
    print(f"   Mode: {result.analysis_mode.value}")
    print(f"   Duration: {result.total_analysis_time:.2f} seconds")
    print()
    
    print(f"🎯 Overall Assessment:")
    print(f"   • VM Detected: {'Yes' if result.vm_detected else 'No'}")
    print(f"   • Confidence Score: {result.confidence_score:.2f}")
    print(f"   • Detection Methods: {', '.join(result.detection_methods) or 'None'}")
    print(f"   • VM Types Detected: {', '.join(result.vm_types_detected) or 'None'}")
    print(f"   • Features Used: {', '.join(result.features_used)}")
    print()
    
    # Pattern Analysis Results
    if result.pattern_analysis:
        pattern_data = result.pattern_analysis
        print(f"🔍 Pattern Analysis:")
        print(f"   • Matches Found: {len(pattern_data.get('pattern_matches', []))}")
        print(f"   • Confidence: {pattern_data.get('confidence', 0.0):.2f}")
        if pattern_data.get('metamorphic_analysis'):
            print(f"   • Metamorphic Analysis: Available")
        if pattern_data.get('contextual_analysis'):
            print(f"   • Contextual Analysis: Available")
        print()
    
    # Multi-Architecture Results
    if result.multi_arch_analysis:
        arch_data = result.multi_arch_analysis
        print(f"🏗️ Multi-Architecture Analysis:")
        print(f"   • Detected Architecture: {arch_data.get('detected_architecture', 'Unknown')}")
        print(f"   • Architecture Confidence: {arch_data.get('architecture_confidence', 0.0):.2f}")
        print(f"   • Cross-Platform Patterns: {len(arch_data.get('vm_patterns_found', []))}")
        print()
    
    # ML Analysis Results
    if result.ml_analysis:
        ml_data = result.ml_analysis
        print(f"🧠 Machine Learning Analysis:")
        print(f"   • ML Prediction: {ml_data.get('ml_prediction', False)}")
        print(f"   • ML Confidence: {ml_data.get('confidence', 0.0):.2f}")
        print(f"   • Models Used: {len(ml_data.get('models_used', []))}")
        print()
    
    # Symbolic Execution Results
    if result.symbolic_analysis:
        symbolic_data = result.symbolic_analysis
        print(f"🎯 Symbolic Execution Analysis:")
        print(f"   • Paths Explored: {symbolic_data.get('paths_explored', 0)}")
        print(f"   • VM Detections: {len(symbolic_data.get('vm_detections', []))}")
        print(f"   • Execution Time: {symbolic_data.get('execution_time', 0.0):.2f}s")
        print()
    
    # Anti-Evasion Results
    if result.anti_evasion_analysis:
        anti_evasion_data = result.anti_evasion_analysis
        print(f"🥷 Anti-Evasion Analysis:")
        countermeasures = anti_evasion_data.get('countermeasures_applied', [])
        print(f"   • Countermeasures Applied: {len(countermeasures)}")
        print(f"   • Stealth Mode: {anti_evasion_data.get('stealth_mode', False)}")
        print()
    
    # Warnings and Errors
    if result.warnings:
        print(f"⚠️ Warnings:")
        for warning in result.warnings:
            print(f"   • {warning}")
        print()
    
    if result.errors:
        print(f"❌ Errors:")
        for error in result.errors:
            print(f"   • {error}")
        print()


def create_sample_binary() -> bytes:
    """Create a sample binary for testing"""
    return b'\x4D\x5A' + b'SAMPLE_BINARY_DATA_FOR_TESTING' + b'\x00' * 100


def create_vm_binary_sample() -> bytes:
    """Create a sample binary with VM indicators"""
    return (b'\x4D\x5A' + 
            b'vmware' + b'\x00' * 10 +
            b'virtualbox' + b'\x00' * 10 +
            b'GetTickCount' + b'\x00' * 10 +
            b'SAMPLE_VM_BINARY' + b'\x00' * 100)


def create_arch_binary_sample(arch: str) -> bytes:
    """Create architecture-specific binary sample"""
    arch_signatures = {
        'x86': b'\x4D\x5A' + b'\x55\x8B\xEC',  # PE + push ebp, mov ebp, esp
        'x64': b'\x4D\x5A' + b'\x48\x89\xE5',  # PE + mov rbp, rsp (x64)
        'arm64': b'\x7F\x45\x4C\x46' + b'\x01\x02\x03\x04',  # ELF + ARM64 signature
    }
    
    signature = arch_signatures.get(arch, b'\x4D\x5A\x00\x00')
    return signature + f'ARCH_{arch.upper()}_BINARY'.encode() + b'\x00' * 100


def create_complex_binary_sample() -> bytes:
    """Create complex binary for symbolic execution"""
    return (b'\x4D\x5A' +
            b'\xE8\x00\x00\x00\x00' +  # call instruction
            b'\x74\x05' +              # je short
            b'\x75\x03' +              # jne short 
            b'\x0F\x31' +              # rdtsc
            b'\x0F\xA2' +              # cpuid
            b'COMPLEX_BINARY_FOR_SYMBOLIC' + b'\x00' * 100)


def create_evasive_binary_sample() -> bytes:
    """Create binary with evasion techniques"""
    return (b'\x4D\x5A' +
            b'IsDebuggerPresent' + b'\x00' * 5 +
            b'CheckRemoteDebuggerPresent' + b'\x00' * 5 +
            b'\x0F\x31' +  # rdtsc for timing
            b'EVASIVE_BINARY_SAMPLE' + b'\x00' * 100)


if __name__ == "__main__":
    main()
