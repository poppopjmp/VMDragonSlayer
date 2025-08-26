#!/usr/bin/env python3
"""
VMDragonSlayer Basic Usage Example
=================================

This example demonstrates basic framework usage with proper error handling.
It shows the correct API calls and how to handle different analysis results.
"""

import sys
from pathlib import Path

try:
    from dragonslayer.core.orchestrator import Orchestrator, AnalysisType
except ImportError as e:
    print(f"Error importing VMDragonSlayer: {e}")
    print("Please ensure VMDragonSlayer is properly installed:")
    print("  pip install vmdragonslayer")
    sys.exit(1)


def main():
    """Basic VMDragonSlayer usage example."""
    
    # Initialize orchestrator (automatically loads default configuration)
    try:
        orchestrator = Orchestrator()
        print("✓ VMDragonSlayer orchestrator initialized successfully")
    except Exception as e:
        print(f"✗ Failed to initialize orchestrator: {e}")
        return False
    
    # Example binary path - replace with your target
    binary_path = "path/to/your/protected_binary.exe"
    
    # Check if binary exists
    if not Path(binary_path).exists():
        print(f"✗ Binary not found: {binary_path}")
        print("Please update the binary_path variable with a valid file path")
        return False
    
    print(f"Analyzing binary: {binary_path}")
    
    try:
        # Perform VM discovery analysis
        result = orchestrator.analyze_binary(
            binary_path, 
            analysis_type=AnalysisType.VM_DISCOVERY
        )
        
        print("✓ Analysis completed")
        
        # Check if analysis was successful
        if not result.get("success", False):
            print("✗ Analysis failed")
            error = result.get("error", "Unknown error")
            print(f"Error: {error}")
            return False
        
        # Extract VM discovery results
        vmd = result.get("vm_discovery", {})
        
        # Display results
        print("\n" + "="*50)
        print("ANALYSIS RESULTS")
        print("="*50)
        
        print(f"VM Protection Detected: {vmd.get('vm_detected', False)}")
        
        handlers = vmd.get('handlers_found', [])
        print(f"Handler Count: {len(handlers)}")
        
        if handlers:
            print("\nVM Handlers Found:")
            for i, handler in enumerate(handlers[:5]):  # Show first 5
                addr = handler.get('address', 'Unknown')
                handler_type = handler.get('type', 'Unknown')
                print(f"  {i+1}. Address: 0x{addr:x} Type: {handler_type}")
            
            if len(handlers) > 5:
                print(f"  ... and {len(handlers) - 5} more handlers")
        
        # Additional analysis results
        patterns = result.get("patterns", {})
        if patterns:
            print(f"\nPattern Analysis: {len(patterns)} patterns identified")
        
        confidence = vmd.get('confidence', 0.0)
        print(f"Detection Confidence: {confidence:.2%}")
        
        return True
        
    except Exception as e:
        print(f"✗ Analysis failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("VMDragonSlayer Basic Usage Example")
    print("-" * 40)
    
    success = main()
    
    if success:
        print("\n✓ Example completed successfully")
    else:
        print("\n✗ Example failed - check error messages above")
        sys.exit(1)
