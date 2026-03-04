#!/usr/bin/env python3
"""
VMDragonSlayer VMProtect Detection Example
==========================================

This example focuses specifically on VMProtect detection and troubleshooting.
It includes debugging options to help identify why detection might fail.
"""

import sys
from pathlib import Path

try:
    from dragonslayer.core.orchestrator import Orchestrator, AnalysisType
    from dragonslayer.core.config import ConfigManager
except ImportError as e:
    print(f"Error importing VMDragonSlayer: {e}")
    print("Please ensure VMDragonSlayer is properly installed:")
    print("  pip install vmdragonslayer")
    sys.exit(1)


def configure_vmprotect_analysis(orchestrator):
    """Configure orchestrator for optimal VMProtect detection."""
    
    try:
        # Get current configuration
        config = orchestrator.config if hasattr(orchestrator, 'config') else None
        
        if config:
            # Enable verbose logging for debugging
            if hasattr(config, 'analysis'):
                config.analysis.verbose = True
                config.analysis.debug_vm_detection = True
            
            # VMProtect-specific settings
            if hasattr(config, 'vm_discovery'):
                config.vm_discovery.vmprotect_signatures = True
                config.vm_discovery.nested_vm_detection = True
                config.vm_discovery.handler_analysis_depth = 3
        
        print("✓ Configuration optimized for VMProtect detection")
        
    except Exception as e:
        print(f"⚠ Configuration adjustment failed: {e}")
        print("Continuing with default settings...")


def analyze_vmprotect_sample(binary_path):
    """Analyze a VMProtect-protected binary with detailed output."""
    
    print(f"Analyzing VMProtect sample: {binary_path}")
    print("-" * 60)
    
    # Initialize orchestrator
    orchestrator = Orchestrator()
    
    # Configure for VMProtect
    configure_vmprotect_analysis(orchestrator)
    
    try:
        # Perform comprehensive analysis
        result = orchestrator.analyze_binary(
            binary_path,
            analysis_type=AnalysisType.VM_DISCOVERY
        )
        
        if not result.get("success", False):
            print("✗ Analysis failed")
            error = result.get("error", "Unknown error")
            print(f"Error: {error}")
            return False
        
        # Extract detailed results
        vmd = result.get("vm_discovery", {})
        
        print("\nVMPROTECT DETECTION RESULTS")
        print("="*40)
        
        vm_detected = vmd.get('vm_detected', False)
        print(f"VM Protection Detected: {'YES' if vm_detected else 'NO'}")
        
        if vm_detected:
            vm_type = vmd.get('vm_type', 'Unknown')
            print(f"VM Type: {vm_type}")
            
            version = vmd.get('version', 'Unknown')
            print(f"Detected Version: {version}")
            
            handlers = vmd.get('handlers_found', [])
            print(f"VM Handlers: {len(handlers)}")
            
            if handlers:
                print("\nHandler Analysis:")
                for i, handler in enumerate(handlers):
                    addr = handler.get('address', 0)
                    h_type = handler.get('type', 'Unknown')
                    confidence = handler.get('confidence', 0.0)
                    print(f"  Handler {i+1}: 0x{addr:x} ({h_type}) - {confidence:.1%}")
            
            # Dispatcher information
            dispatcher = vmd.get('dispatcher', {})
            if dispatcher:
                disp_addr = dispatcher.get('address', 0)
                print(f"\nVM Dispatcher: 0x{disp_addr:x}")
        
        else:
            print("\n⚠ VMProtect not detected. Possible reasons:")
            print("  1. Binary is not VMProtect-protected")
            print("  2. Unsupported VMProtect version")
            print("  3. Custom VMProtect configuration")
            print("  4. Analysis patterns need updating")
            
            # Show what was found instead
            patterns = result.get("patterns", {})
            if patterns:
                print(f"\nAlternative patterns detected: {len(patterns)}")
                for pattern_name, pattern_data in patterns.items():
                    confidence = pattern_data.get('confidence', 0.0)
                    print(f"  - {pattern_name}: {confidence:.1%}")
        
        # Pattern analysis results
        pattern_analysis = result.get("pattern_analysis", {})
        if pattern_analysis:
            print(f"\nPattern Analysis Confidence: {pattern_analysis.get('confidence', 0.0):.1%}")
        
        # Performance metrics
        timing = result.get("timing", {})
        if timing:
            total_time = timing.get('total_seconds', 0)
            print(f"\nAnalysis completed in {total_time:.2f} seconds")
        
        return vm_detected
        
    except Exception as e:
        print(f"✗ Analysis failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main function for VMProtect detection example."""
    
    # Example VMProtect samples - update these paths
    sample_paths = [
        "path/to/vmprotect2_sample.exe",
        "path/to/vmprotect3_sample.exe",
        "path/to/custom_vm_sample.exe"
    ]
    
    detected_count = 0
    
    for sample_path in sample_paths:
        if not Path(sample_path).exists():
            print(f"⚠ Sample not found: {sample_path}")
            print("Please update sample paths in the script")
            continue
        
        try:
            if analyze_vmprotect_sample(sample_path):
                detected_count += 1
            
            print("\n" + "="*60 + "\n")
            
        except KeyboardInterrupt:
            print("\n⚠ Analysis interrupted by user")
            break
        except Exception as e:
            print(f"✗ Unexpected error: {e}")
            continue
    
    print(f"Detection Summary: {detected_count}/{len([p for p in sample_paths if Path(p).exists()])} samples detected")
    
    return detected_count > 0


if __name__ == "__main__":
    print("VMDragonSlayer VMProtect Detection Example")
    print("=" * 50)
    
    success = main()
    
    if success:
        print("✓ VMProtect detection completed successfully")
    else:
        print("⚠ No VMProtect samples detected - check sample paths and binary types")
        print("\nTroubleshooting tips:")
        print("1. Ensure samples are actually VMProtect-protected")
        print("2. Try different VMProtect versions")
        print("3. Check if patterns database is up to date")
        print("4. Enable debug logging for detailed analysis")
