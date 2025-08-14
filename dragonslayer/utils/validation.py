"""
Validation Utilities
===================

Validation utilities for VMDragonSlayer analysis results and configurations.
Consolidates validation functionality from workflow_integration and other modules.
"""

import os
import logging
import hashlib
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class ValidationLevel(Enum):
    """Validation severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class ValidationResult:
    """Result of a validation check"""
    is_valid: bool
    level: ValidationLevel
    message: str
    details: Dict[str, Any] = None
    suggestions: List[str] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}
        if self.suggestions is None:
            self.suggestions = []


class ValidationError(Exception):
    """Custom exception for validation errors"""
    
    def __init__(self, message: str, results: List[ValidationResult] = None):
        super().__init__(message)
        self.results = results or []


def validate_binary_file(file_path: Union[str, Path]) -> ValidationResult:
    """
    Validate a binary file for analysis.
    
    Args:
        file_path: Path to the binary file
        
    Returns:
        ValidationResult indicating if file is suitable for analysis
    """
    file_path = Path(file_path)
    
    # Check if file exists
    if not file_path.exists():
        return ValidationResult(
            is_valid=False,
            level=ValidationLevel.ERROR,
            message=f"File does not exist: {file_path}",
            suggestions=["Check the file path", "Ensure the file exists"]
        )
    
    # Check if it's a file (not directory)
    if not file_path.is_file():
        return ValidationResult(
            is_valid=False,
            level=ValidationLevel.ERROR,
            message=f"Path is not a file: {file_path}",
            suggestions=["Provide path to a file, not a directory"]
        )
    
    # Check file size
    file_size = file_path.stat().st_size
    if file_size == 0:
        return ValidationResult(
            is_valid=False,
            level=ValidationLevel.ERROR,
            message="File is empty",
            suggestions=["Provide a non-empty binary file"]
        )
    
    # Check for extremely large files (>1GB)
    if file_size > 1024 * 1024 * 1024:
        return ValidationResult(
            is_valid=True,  # Still valid but warning
            level=ValidationLevel.WARNING,
            message=f"Large file size: {file_size / (1024*1024):.1f} MB",
            details={"file_size_bytes": file_size},
            suggestions=["Consider using streaming analysis for large files"]
        )
    
    # Basic binary detection
    try:
        with open(file_path, 'rb') as f:
            header = f.read(64)  # Read first 64 bytes
        
        # Check for common executable signatures
        is_executable = False
        file_type = "unknown"
        
        if header.startswith(b'MZ'):
            is_executable = True
            file_type = "PE (Windows executable)"
        elif header.startswith(b'\x7fELF'):
            is_executable = True
            file_type = "ELF (Linux executable)"
        elif header[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                           b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe']:
            is_executable = True
            file_type = "Mach-O (macOS executable)"
        
        details = {
            "file_size_bytes": file_size,
            "file_type": file_type,
            "is_executable": is_executable,
            "header_hex": header[:16].hex()
        }
        
        if not is_executable:
            return ValidationResult(
                is_valid=True,  # Still valid for analysis
                level=ValidationLevel.WARNING,
                message=f"File may not be an executable (type: {file_type})",
                details=details,
                suggestions=["Ensure file is a binary executable for best results"]
            )
        
        return ValidationResult(
            is_valid=True,
            level=ValidationLevel.INFO,
            message=f"Valid binary file (type: {file_type})",
            details=details
        )
        
    except IOError as e:
        return ValidationResult(
            is_valid=False,
            level=ValidationLevel.ERROR,
            message=f"Cannot read file: {e}",
            suggestions=["Check file permissions", "Ensure file is not corrupted"]
        )


def validate_analysis_result(result: Dict[str, Any]) -> ValidationResult:
    """
    Validate an analysis result dictionary.
    
    Args:
        result: Analysis result to validate
        
    Returns:
        ValidationResult indicating if result is valid
    """
    required_fields = ['success', 'execution_time']
    missing_fields = []
    
    for field in required_fields:
        if field not in result:
            missing_fields.append(field)
    
    if missing_fields:
        return ValidationResult(
            is_valid=False,
            level=ValidationLevel.ERROR,
            message=f"Missing required fields: {', '.join(missing_fields)}",
            details={"missing_fields": missing_fields},
            suggestions=[f"Ensure analysis includes '{field}' field" for field in missing_fields]
        )
    
    # Check execution time validity
    exec_time = result.get('execution_time', 0)
    if not isinstance(exec_time, (int, float)) or exec_time < 0:
        return ValidationResult(
            is_valid=False,
            level=ValidationLevel.ERROR,
            message="Invalid execution_time value",
            details={"execution_time": exec_time},
            suggestions=["execution_time should be a non-negative number"]
        )
    
    # Check success field
    success = result.get('success')
    if not isinstance(success, bool):
        return ValidationResult(
            is_valid=False,
            level=ValidationLevel.ERROR,
            message="success field must be boolean",
            details={"success": success},
            suggestions=["success should be True or False"]
        )
    
    # Validate results structure if present
    if 'results' in result:
        results_data = result['results']
        if not isinstance(results_data, dict):
            return ValidationResult(
                is_valid=False,
                level=ValidationLevel.ERROR,
                message="results field must be a dictionary",
                suggestions=["Ensure results is a dictionary structure"]
            )
    
    return ValidationResult(
        is_valid=True,
        level=ValidationLevel.INFO,
        message="Analysis result is valid",
        details={"fields_present": list(result.keys())}
    )


def validate_configuration(config: Dict[str, Any]) -> List[ValidationResult]:
    """
    Validate a configuration dictionary.
    
    Args:
        config: Configuration to validate
        
    Returns:
        List of ValidationResult objects
    """
    results = []
    
    # Check for required configuration sections
    required_sections = ['analysis', 'ml', 'api']
    for section in required_sections:
        if section not in config:
            results.append(ValidationResult(
                is_valid=False,
                level=ValidationLevel.WARNING,
                message=f"Missing configuration section: {section}",
                suggestions=[f"Add '{section}' section to configuration"]
            ))
    
    # Validate analysis configuration
    if 'analysis' in config:
        analysis_config = config['analysis']
        
        # Check timeout values
        if 'timeout' in analysis_config:
            timeout = analysis_config['timeout']
            if not isinstance(timeout, (int, float)) or timeout <= 0:
                results.append(ValidationResult(
                    is_valid=False,
                    level=ValidationLevel.ERROR,
                    message="Invalid timeout value in analysis config",
                    details={"timeout": timeout},
                    suggestions=["Timeout should be a positive number"]
                ))
    
    # Validate API configuration
    if 'api' in config:
        api_config = config['api']
        
        # Check port number
        if 'port' in api_config:
            port = api_config['port']
            if not isinstance(port, int) or not (1 <= port <= 65535):
                results.append(ValidationResult(
                    is_valid=False,
                    level=ValidationLevel.ERROR,
                    message="Invalid port number in API config",
                    details={"port": port},
                    suggestions=["Port should be an integer between 1 and 65535"]
                ))
    
    # If no issues found, add success result
    if not results:
        results.append(ValidationResult(
            is_valid=True,
            level=ValidationLevel.INFO,
            message="Configuration is valid"
        ))
    
    return results


def check_dependencies() -> List[ValidationResult]:
    """
    Check for required and optional dependencies.
    
    Returns:
        List of ValidationResult objects for each dependency
    """
    results = []
    
    # Required dependencies
    required_deps = [
        ('logging', 'Standard library logging'),
        ('pathlib', 'Standard library path handling'),
        ('json', 'Standard library JSON support')
    ]
    
    for module_name, description in required_deps:
        try:
            __import__(module_name)
            results.append(ValidationResult(
                is_valid=True,
                level=ValidationLevel.INFO,
                message=f"Required dependency available: {description}",
                details={"module": module_name}
            ))
        except ImportError:
            results.append(ValidationResult(
                is_valid=False,
                level=ValidationLevel.CRITICAL,
                message=f"Missing required dependency: {module_name}",
                details={"module": module_name},
                suggestions=[f"Install {module_name} module"]
            ))
    
    # Optional dependencies
    optional_deps = [
        ('psutil', 'System and process monitoring'),
        ('z3', 'Z3 theorem prover for symbolic execution'),
        ('capstone', 'Disassembly framework'),
        ('pin', 'Intel Pin dynamic instrumentation'),
        ('fastapi', 'FastAPI web framework for REST API'),
        ('numpy', 'Numerical computing'),
        ('scikit-learn', 'Machine learning library')
    ]
    
    for module_name, description in optional_deps:
        try:
            __import__(module_name)
            results.append(ValidationResult(
                is_valid=True,
                level=ValidationLevel.INFO,
                message=f"Optional dependency available: {description}",
                details={"module": module_name}
            ))
        except ImportError:
            results.append(ValidationResult(
                is_valid=True,  # Still valid without optional deps
                level=ValidationLevel.WARNING,
                message=f"Optional dependency missing: {module_name}",
                details={"module": module_name, "description": description},
                suggestions=[f"Install {module_name} for {description}"]
            ))
    
    return results


def validate_file_hash(file_path: Union[str, Path], expected_hash: str, 
                      algorithm: str = 'sha256') -> ValidationResult:
    """
    Validate file hash.
    
    Args:
        file_path: Path to file
        expected_hash: Expected hash value
        algorithm: Hash algorithm ('md5', 'sha1', 'sha256')
        
    Returns:
        ValidationResult indicating if hash matches
    """
    file_path = Path(file_path)
    
    if not file_path.exists():
        return ValidationResult(
            is_valid=False,
            level=ValidationLevel.ERROR,
            message="File does not exist for hash validation"
        )
    
    try:
        hasher = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        
        actual_hash = hasher.hexdigest()
        
        if actual_hash.lower() == expected_hash.lower():
            return ValidationResult(
                is_valid=True,
                level=ValidationLevel.INFO,
                message=f"File hash validation successful ({algorithm})",
                details={"algorithm": algorithm, "hash": actual_hash}
            )
        else:
            return ValidationResult(
                is_valid=False,
                level=ValidationLevel.ERROR,
                message=f"File hash mismatch ({algorithm})",
                details={
                    "algorithm": algorithm,
                    "expected": expected_hash,
                    "actual": actual_hash
                },
                suggestions=["File may be corrupted or modified"]
            )
    
    except Exception as e:
        return ValidationResult(
            is_valid=False,
            level=ValidationLevel.ERROR,
            message=f"Hash validation failed: {e}",
            suggestions=["Check file permissions and integrity"]
        )


def create_validation_report(results: List[ValidationResult]) -> Dict[str, Any]:
    """
    Create a comprehensive validation report.
    
    Args:
        results: List of validation results
        
    Returns:
        Dictionary with validation report
    """
    report = {
        'total_checks': len(results),
        'passed': 0,
        'warnings': 0,
        'errors': 0,
        'critical': 0,
        'is_valid_overall': True,
        'summary': [],
        'details': []
    }
    
    for result in results:
        # Count by level
        if result.level == ValidationLevel.INFO and result.is_valid:
            report['passed'] += 1
        elif result.level == ValidationLevel.WARNING:
            report['warnings'] += 1
        elif result.level == ValidationLevel.ERROR:
            report['errors'] += 1
        elif result.level == ValidationLevel.CRITICAL:
            report['critical'] += 1
        
        # Overall validity
        if not result.is_valid and result.level in [ValidationLevel.ERROR, ValidationLevel.CRITICAL]:
            report['is_valid_overall'] = False
        
        # Add to details
        report['details'].append({
            'valid': result.is_valid,
            'level': result.level.value,
            'message': result.message,
            'details': result.details,
            'suggestions': result.suggestions
        })
    
    # Create summary
    report['summary'] = [
        f"Passed: {report['passed']}",
        f"Warnings: {report['warnings']}",
        f"Errors: {report['errors']}",
        f"Critical: {report['critical']}"
    ]
    
    return report
