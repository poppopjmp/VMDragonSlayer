#!/usr/bin/env python3
"""
VMDragonSlayer Batch Analysis Example
=====================================

This example demonstrates how to analyze multiple binary files in batch mode.
It shows progress tracking, results aggregation, and error handling.
"""

import sys
from pathlib import Path
import json
from typing import List, Dict, Any

try:
    from dragonslayer.core.orchestrator import Orchestrator, AnalysisType
except ImportError as e:
    print(f"Error importing VMDragonSlayer: {e}")
    print("Please ensure VMDragonSlayer is properly installed:")
    print("  pip install vmdragonslayer")
    sys.exit(1)


def analyze_binary_batch(binary_paths: List[str], analysis_type: AnalysisType = AnalysisType.VM_DISCOVERY) -> Dict[str, Any]:
    """
    Analyze multiple binaries and return aggregated results.
    
    Args:
        binary_paths: List of paths to binary files
        analysis_type: Type of analysis to perform
    
    Returns:
        Dictionary with aggregated results and individual analysis data
    """
    
    orchestrator = Orchestrator()
    results = {
        'summary': {
            'total_files': len(binary_paths),
            'successful': 0,
            'failed': 0,
            'vm_detected_count': 0,
            'total_handlers': 0,
        },
        'individual_results': {},
        'errors': []
    }
    
    print(f"Starting batch analysis of {len(binary_paths)} files...")
    print(f"Analysis type: {analysis_type.value}")
    print("-" * 60)
    
    for i, binary_path in enumerate(binary_paths, 1):
        print(f"[{i}/{len(binary_paths)}] Analyzing: {Path(binary_path).name}")
        
        # Check if file exists
        if not Path(binary_path).exists():
            error_msg = f"File not found: {binary_path}"
            print(f"  ✗ {error_msg}")
            results['errors'].append({
                'file': binary_path,
                'error': error_msg
            })
            results['summary']['failed'] += 1
            continue
        
        try:
            # Perform analysis
            result = orchestrator.analyze_binary(binary_path, analysis_type=analysis_type)
            
            if result.get('success', False):
                results['summary']['successful'] += 1
                
                # Extract VM discovery results
                vmd = result.get('vm_discovery', {})
                vm_detected = vmd.get('vm_detected', False)
                handlers = vmd.get('handlers_found', [])
                
                if vm_detected:
                    results['summary']['vm_detected_count'] += 1
                    results['summary']['total_handlers'] += len(handlers)
                
                # Store individual result
                results['individual_results'][binary_path] = {
                    'success': True,
                    'vm_detected': vm_detected,
                    'handler_count': len(handlers),
                    'vm_type': vmd.get('vm_type', 'Unknown'),
                    'confidence': vmd.get('confidence', 0.0),
                    'analysis_time': result.get('timing', {}).get('total_seconds', 0)
                }
                
                print(f"  ✓ Success - VM: {'Yes' if vm_detected else 'No'}, Handlers: {len(handlers)}")
                
            else:
                error = result.get('error', 'Analysis failed')
                results['summary']['failed'] += 1
                results['errors'].append({
                    'file': binary_path,
                    'error': error
                })
                print(f"  ✗ Failed: {error}")
                
        except Exception as e:
            error_msg = f"Exception during analysis: {str(e)}"
            results['summary']['failed'] += 1
            results['errors'].append({
                'file': binary_path,
                'error': error_msg
            })
            print(f"  ✗ Exception: {str(e)}")
    
    return results


def save_batch_results(results: Dict[str, Any], output_file: str = "batch_analysis_results.json"):
    """Save batch analysis results to JSON file."""
    
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n✓ Results saved to: {output_file}")
    except Exception as e:
        print(f"\n✗ Failed to save results: {e}")


def print_batch_summary(results: Dict[str, Any]):
    """Print a summary of batch analysis results."""
    
    summary = results['summary']
    
    print("\n" + "="*60)
    print("BATCH ANALYSIS SUMMARY")
    print("="*60)
    
    print(f"Total Files Processed: {summary['total_files']}")
    print(f"Successful Analyses: {summary['successful']}")
    print(f"Failed Analyses: {summary['failed']}")
    print(f"VM Protection Detected: {summary['vm_detected_count']}")
    print(f"Total VM Handlers Found: {summary['total_handlers']}")
    
    if summary['successful'] > 0:
        detection_rate = (summary['vm_detected_count'] / summary['successful']) * 100
        print(f"VM Detection Rate: {detection_rate:.1f}%")
    
    # Show individual results summary
    if results['individual_results']:
        print("\nIndividual Results:")
        print("-" * 40)
        
        for file_path, file_result in results['individual_results'].items():
            filename = Path(file_path).name
            vm_status = "VM" if file_result['vm_detected'] else "No VM"
            handlers = file_result['handler_count']
            confidence = file_result['confidence']
            
            print(f"  {filename:<30} | {vm_status:<6} | {handlers:>3} handlers | {confidence:>5.1%}")
    
    # Show errors if any
    if results['errors']:
        print(f"\nErrors ({len(results['errors'])}):")
        print("-" * 20)
        for error in results['errors'][:5]:  # Show first 5 errors
            filename = Path(error['file']).name
            print(f"  {filename}: {error['error']}")
        
        if len(results['errors']) > 5:
            print(f"  ... and {len(results['errors']) - 5} more errors")


def main():
    """Main function for batch analysis example."""
    
    # Example binary paths - update these with real files for testing
    sample_binaries = [
        "path/to/binary1.exe",
        "path/to/binary2.exe", 
        "path/to/vmprotect_sample.exe",
        "path/to/themida_sample.exe",
        "path/to/regular_binary.exe",
    ]
    
    # Alternative: scan a directory for binaries
    # sample_dir = Path("samples")
    # if sample_dir.exists():
    #     sample_binaries = [str(f) for f in sample_dir.glob("*.exe")]
    
    # Filter to only existing files for demo
    existing_files = [f for f in sample_binaries if Path(f).exists()]
    
    if not existing_files:
        print("No sample binaries found. Creating demo with non-existent files to show error handling...")
        existing_files = sample_binaries[:3]  # Use some non-existent files for demo
    
    print(f"VMDragonSlayer Batch Analysis Example")
    print(f"Processing {len(existing_files)} files...")
    
    # Perform batch analysis
    try:
        results = analyze_binary_batch(existing_files, AnalysisType.VM_DISCOVERY)
        
        # Print summary
        print_batch_summary(results)
        
        # Save results
        save_batch_results(results)
        
        # Check if any VMs were detected
        if results['summary']['vm_detected_count'] > 0:
            print(f"\n✓ Batch analysis completed - {results['summary']['vm_detected_count']} VM-protected files found")
            return True
        else:
            print(f"\n✓ Batch analysis completed - No VM protection detected")
            return True
            
    except Exception as e:
        print(f"\n✗ Batch analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("VMDragonSlayer Batch Analysis Example")
    print("=" * 50)
    
    success = main()
    
    if success:
        print("\n✓ Batch analysis example completed successfully")
        print("\nTo use with real binaries:")
        print("  1. Update sample_binaries list with actual file paths")
        print("  2. Or uncomment directory scanning code")
        print("  3. Run the script again")
    else:
        print("\n✗ Batch analysis example failed - check error messages above")
        sys.exit(1)
