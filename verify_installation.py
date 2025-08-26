#!/usr/bin/env python3
"""
VMDragonSlayer Installation Verification Script
===============================================

This script verifies that VMDragonSlayer is properly installed and configured.
It runs through all the critical components to ensure they work correctly.
"""

import sys
import os
from pathlib import Path

def test_basic_imports():
    """Test basic VMDragonSlayer imports."""
    print("Testing basic imports...")
    
    try:
        from dragonslayer.core.orchestrator import Orchestrator, AnalysisType
        print("✓ Core orchestrator imports successful")
        return True
    except ImportError as e:
        print(f"✗ Import failed: {e}")
        return False

def test_dependencies():
    """Test critical dependencies."""
    print("\nTesting critical dependencies...")
    
    # Test z3-solver
    try:
        import z3
        solver = z3.Solver()
        print("✓ z3-solver available and functional")
    except Exception as e:
        print(f"✗ z3-solver issue: {e}")
        return False
    
    # Test other core dependencies
    dependencies = [
        ('numpy', 'numpy'),
        ('pandas', 'pandas'),
        ('pydantic', 'pydantic'),
        ('yaml', 'pyyaml'),
        ('psutil', 'psutil'),
        ('cryptography', 'cryptography'),
        ('requests', 'requests'),
    ]
    
    for module, package in dependencies:
        try:
            __import__(module)
            print(f"✓ {package} available")
        except ImportError:
            print(f"⚠ {package} not available (may be optional)")
    
    return True

def test_orchestrator_creation():
    """Test orchestrator creation and basic functionality."""
    print("\nTesting orchestrator creation...")
    
    try:
        from dragonslayer.core.orchestrator import Orchestrator, AnalysisType
        
        orchestrator = Orchestrator()
        print("✓ Orchestrator created successfully")
        
        # Test analysis types
        analysis_types = [t.value for t in AnalysisType]
        print(f"✓ Available analysis types: {', '.join(analysis_types)}")
        
        return True
    except Exception as e:
        print(f"✗ Orchestrator creation failed: {e}")
        return False

def test_gpu_detection():
    """Test GPU detection and graceful fallback."""
    print("\nTesting GPU detection...")
    
    try:
        # Test PyTorch GPU detection
        import torch
        print(f"✓ PyTorch available: {torch.__version__}")
        if torch.cuda.is_available():
            print(f"✓ CUDA available: {torch.cuda.device_count()} devices")
            print(f"✓ Current device: {torch.cuda.get_device_name()}")
        else:
            print("ℹ CUDA not available - CPU mode will be used")
    except ImportError:
        print("ℹ PyTorch not installed - ML features unavailable")
    
    try:
        # Test GPU module graceful handling
        from dragonslayer.gpu import GPUEngine
        print("✓ GPU module imports successfully (graceful fallback)")
    except Exception as e:
        print(f"⚠ GPU module issue: {e}")
    
    return True

def test_configuration():
    """Test configuration system."""
    print("\nTesting configuration system...")
    
    try:
        from dragonslayer.core.config import ConfigManager
        
        config_manager = ConfigManager()
        print("✓ ConfigManager available")
        
        # Test default config
        config = config_manager.get_default_config()
        print("✓ Default configuration loaded")
        
        return True
    except Exception as e:
        print(f"ℹ Configuration system: {e}")
        return True  # Not critical for basic functionality

def test_example_import():
    """Test that examples can be imported."""
    print("\nTesting example scripts...")
    
    example_dir = Path("examples")
    if not example_dir.exists():
        print("⚠ Examples directory not found")
        return True
    
    examples = list(example_dir.glob("*.py"))
    print(f"✓ Found {len(examples)} example scripts")
    
    for example in examples[:3]:  # Test first 3 examples
        try:
            # Test syntax by compiling
            with open(example, 'r') as f:
                compile(f.read(), str(example), 'exec')
            print(f"✓ {example.name} syntax OK")
        except Exception as e:
            print(f"⚠ {example.name} issue: {e}")
    
    return True

def main():
    """Run all verification tests."""
    print("VMDragonSlayer Installation Verification")
    print("=" * 50)
    
    tests = [
        test_basic_imports,
        test_dependencies,
        test_orchestrator_creation,
        test_gpu_detection,
        test_configuration,
        test_example_import,
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} failed with exception: {e}")
    
    print("\n" + "=" * 50)
    print(f"VERIFICATION RESULTS: {passed}/{total} tests passed")
    
    if passed == total:
        print("✓ VMDragonSlayer is properly installed and configured!")
        print("\nYou can now:")
        print("  • Run the examples in examples/ directory")
        print("  • Use the Direct API for analysis")
        print("  • Read INSTALLATION.md for advanced setup")
        return True
    else:
        print("⚠ Some issues detected. Check the output above.")
        print("\nFor help:")
        print("  • Check INSTALLATION.md for troubleshooting")
        print("  • Ensure all dependencies are installed")
        print("  • Try: pip install -r requirements.txt")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
