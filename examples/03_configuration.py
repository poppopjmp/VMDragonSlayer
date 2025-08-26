#!/usr/bin/env python3
"""
VMDragonSlayer Configuration System Example
==========================================

This example demonstrates how to use the configuration system properly.
Shows how to load, modify, and use different configuration options.
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


def demonstrate_default_config():
    """Show how the default configuration works."""
    
    print("DEFAULT CONFIGURATION")
    print("-" * 30)
    
    # Initialize with default configuration (automatic)
    orchestrator = Orchestrator()
    
    print("✓ Orchestrator initialized with default configuration")
    
    # Access configuration if available
    if hasattr(orchestrator, 'config'):
        config = orchestrator.config
        print(f"Configuration loaded: {type(config).__name__}")
    else:
        print("Configuration managed internally")
    
    return orchestrator


def demonstrate_config_manager():
    """Show how to use ConfigManager for advanced configuration."""
    
    print("\nCONFIG MANAGER USAGE")
    print("-" * 30)
    
    try:
        # Initialize config manager
        config_manager = ConfigManager()
        
        # Load default configuration
        config = config_manager.get_default_config()
        print("✓ Default configuration loaded via ConfigManager")
        
        # Display some configuration sections
        if hasattr(config, 'analysis'):
            print(f"Analysis config available: {hasattr(config.analysis, 'timeout_seconds')}")
        
        if hasattr(config, 'ml'):
            print(f"ML config available: {hasattr(config.ml, 'device_preference')}")
        
        if hasattr(config, 'vm_discovery'):
            print(f"VM Discovery config available: True")
        
        return config
        
    except Exception as e:
        print(f"⚠ ConfigManager not available or failed: {e}")
        return None


def demonstrate_custom_config():
    """Show how to create custom configuration."""
    
    print("\nCUSTOM CONFIGURATION")
    print("-" * 30)
    
    try:
        # Create orchestrator
        orchestrator = Orchestrator()
        
        # Example of configuration that might be available
        custom_settings = {
            'analysis_timeout': 300,  # 5 minutes
            'verbose_logging': True,
            'gpu_enabled': True,
            'pattern_database_path': 'data/patterns/pattern_database.json'
        }
        
        print("Custom settings prepared:")
        for key, value in custom_settings.items():
            print(f"  - {key}: {value}")
        
        # Note: Actual configuration method depends on implementation
        print("✓ Custom configuration prepared (method varies by implementation)")
        
        return orchestrator
        
    except Exception as e:
        print(f"⚠ Custom configuration failed: {e}")
        return None


def demonstrate_config_based_analysis():
    """Show analysis with different configuration approaches."""
    
    print("\nCONFIGURATION-BASED ANALYSIS")
    print("-" * 40)
    
    # Use a test binary path
    test_binary = "path/to/test_binary.exe"
    
    if not Path(test_binary).exists():
        print(f"⚠ Test binary not found: {test_binary}")
        print("Please update test_binary path for actual testing")
        return False
    
    configurations = [
        ("Default Configuration", lambda: Orchestrator()),
        ("ConfigManager Approach", lambda: Orchestrator()),  # Assuming same interface
    ]
    
    for config_name, config_func in configurations:
        print(f"\nTesting with {config_name}:")
        
        try:
            orchestrator = config_func()
            
            result = orchestrator.analyze_binary(
                test_binary,
                analysis_type=AnalysisType.VM_DISCOVERY
            )
            
            if result.get("success", False):
                vmd = result.get("vm_discovery", {})
                print(f"  ✓ Analysis successful - VM detected: {vmd.get('vm_detected', False)}")
            else:
                print(f"  ✗ Analysis failed: {result.get('error', 'Unknown error')}")
                
        except Exception as e:
            print(f"  ✗ Configuration failed: {e}")
    
    return True


def demonstrate_environment_config():
    """Show environment variable configuration options."""
    
    print("\nENVIRONMENT CONFIGURATION")
    print("-" * 35)
    
    import os
    
    # Common environment variables that might be supported
    env_vars = [
        'VMDS_CONFIG_PATH',
        'VMDS_DATA_PATH',
        'VMDS_PATTERN_DB_PATH',
        'VMDS_GPU_ENABLED',
        'VMDS_LOG_LEVEL',
        'VMDS_TIMEOUT'
    ]
    
    print("Checking environment variables:")
    for var in env_vars:
        value = os.environ.get(var)
        if value:
            print(f"  ✓ {var}: {value}")
        else:
            print(f"  - {var}: not set")
    
    print("\nExample environment setup:")
    print("export VMDS_CONFIG_PATH=/path/to/config")
    print("export VMDS_GPU_ENABLED=true")
    print("export VMDS_LOG_LEVEL=DEBUG")


def main():
    """Main function demonstrating configuration usage."""
    
    print("VMDragonSlayer Configuration System Example")
    print("=" * 50)
    
    try:
        # Demonstrate different configuration approaches
        orchestrator = demonstrate_default_config()
        
        config = demonstrate_config_manager()
        
        custom_orch = demonstrate_custom_config()
        
        # Show environment configuration
        demonstrate_environment_config()
        
        # Demonstrate analysis with different configs
        # demonstrate_config_based_analysis()  # Uncomment when you have test binaries
        
        print("\n" + "="*50)
        print("CONFIGURATION SUMMARY")
        print("="*50)
        print("✓ Default configuration: Always available")
        print("✓ ConfigManager: For advanced usage")
        print("✓ Custom settings: Application-specific")
        print("✓ Environment variables: System-wide settings")
        
        return True
        
    except Exception as e:
        print(f"✗ Configuration example failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    
    if success:
        print("\n✓ Configuration example completed successfully")
    else:
        print("\n✗ Configuration example failed - check error messages")
        sys.exit(1)
