"""
Platform Utilities
=================

Platform detection and system information utilities.
Consolidates platform-specific functionality from across the VMDragonSlayer codebase.
"""

import platform
import sys
import os
import subprocess
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class Architecture(Enum):
    """System architecture types"""
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    UNKNOWN = "unknown"


class OperatingSystem(Enum):
    """Operating system types"""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


@dataclass
class PlatformInfo:
    """Complete platform information"""
    os_type: OperatingSystem
    os_version: str
    architecture: Architecture
    cpu_count: int
    total_memory_gb: float
    python_version: str
    cpu_features: List[str]
    has_pin: bool = False
    has_docker: bool = False


def get_platform_info() -> PlatformInfo:
    """
    Get comprehensive platform information.
    
    Returns:
        PlatformInfo object with system details
    """
    # Detect OS
    system = platform.system().lower()
    if system == "windows":
        os_type = OperatingSystem.WINDOWS
    elif system == "linux":
        os_type = OperatingSystem.LINUX
    elif system == "darwin":
        os_type = OperatingSystem.MACOS
    else:
        os_type = OperatingSystem.UNKNOWN
    
    # Detect architecture
    machine = platform.machine().lower()
    if machine in ["x86_64", "amd64"]:
        arch = Architecture.X64
    elif machine in ["i386", "i686", "x86"]:
        arch = Architecture.X86
    elif machine.startswith("arm64") or machine == "aarch64":
        arch = Architecture.ARM64
    elif machine.startswith("arm"):
        arch = Architecture.ARM
    else:
        arch = Architecture.UNKNOWN
    
    # Get memory info
    try:
        import psutil
        total_memory = psutil.virtual_memory().total / (1024**3)  # GB
    except ImportError:
        total_memory = 0.0
    
    # Get CPU features
    cpu_features = []
    try:
        if os_type == OperatingSystem.WINDOWS:
            cpu_features = _get_windows_cpu_features()
        elif os_type == OperatingSystem.LINUX:
            cpu_features = _get_linux_cpu_features()
        elif os_type == OperatingSystem.MACOS:
            cpu_features = _get_macos_cpu_features()
    except Exception as e:
        logger.warning(f"Failed to get CPU features: {e}")
    
    # Check for Pin tool
    has_pin = _check_pin_availability()
    
    # Check for Docker
    has_docker = _check_docker_availability()
    
    return PlatformInfo(
        os_type=os_type,
        os_version=platform.platform(),
        architecture=arch,
        cpu_count=os.cpu_count() or 1,
        total_memory_gb=total_memory,
        python_version=sys.version,
        cpu_features=cpu_features,
        has_pin=has_pin,
        has_docker=has_docker
    )


def is_windows() -> bool:
    """Check if running on Windows"""
    return platform.system().lower() == "windows"


def is_linux() -> bool:
    """Check if running on Linux"""
    return platform.system().lower() == "linux"


def is_macos() -> bool:
    """Check if running on macOS"""
    return platform.system().lower() == "darwin"


def get_architecture() -> Architecture:
    """Get system architecture"""
    return get_platform_info().architecture


def get_cpu_features() -> List[str]:
    """Get available CPU features"""
    return get_platform_info().cpu_features


def _get_windows_cpu_features() -> List[str]:
    """Get CPU features on Windows"""
    features = []
    try:
        # Try to use wmic to get CPU info
        result = subprocess.run(
            ["wmic", "cpu", "get", "Name,Description,Family"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            # Parse basic info
            if "Intel" in result.stdout:
                features.append("intel")
            if "AMD" in result.stdout:
                features.append("amd")
        
        # Check for common features through Python
        import cpuinfo
        info = cpuinfo.get_cpu_info()
        if 'flags' in info:
            features.extend(info['flags'])
        
    except Exception:
        # Fallback to basic detection
        if "64" in platform.machine():
            features.append("x64")
        else:
            features.append("x86")
    
    return features


def _get_linux_cpu_features() -> List[str]:
    """Get CPU features on Linux"""
    features = []
    try:
        with open('/proc/cpuinfo', 'r') as f:
            content = f.read()
            
        # Extract flags
        for line in content.split('\n'):
            if line.startswith('flags'):
                flags = line.split(':')[1].strip().split()
                features.extend(flags)
                break
                
        # Extract other info
        if 'Intel' in content:
            features.append('intel')
        if 'AMD' in content:
            features.append('amd')
            
    except Exception as e:
        logger.warning(f"Failed to read /proc/cpuinfo: {e}")
        
    return features


def _get_macos_cpu_features() -> List[str]:
    """Get CPU features on macOS"""
    features = []
    try:
        # Use sysctl to get CPU info
        result = subprocess.run(
            ["sysctl", "-n", "machdep.cpu.features"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            features.extend(result.stdout.strip().split())
        
        # Check for Apple Silicon
        result = subprocess.run(
            ["sysctl", "-n", "machdep.cpu.brand_string"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and "Apple" in result.stdout:
            features.append("apple_silicon")
            
    except Exception as e:
        logger.warning(f"Failed to get macOS CPU features: {e}")
        
    return features


def _check_pin_availability() -> bool:
    """Check if Intel Pin is available"""
    try:
        # Check for pin executable in common locations
        pin_paths = [
            "pin",
            "/opt/pin/pin",
            "/usr/local/bin/pin",
            "C:\\pin\\pin.exe"
        ]
        
        for pin_path in pin_paths:
            try:
                result = subprocess.run(
                    [pin_path, "-h"],
                    capture_output=True, timeout=5
                )
                if result.returncode == 0:
                    return True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
                
    except Exception:
        pass
        
    return False


def _check_docker_availability() -> bool:
    """Check if Docker is available"""
    try:
        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True, timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# Additional utility functions
def get_temp_directory() -> str:
    """Get platform-appropriate temporary directory"""
    if is_windows():
        return os.environ.get('TEMP', 'C:\\temp')
    else:
        return '/tmp'


def get_executable_extension() -> str:
    """Get platform-appropriate executable extension"""
    return '.exe' if is_windows() else ''


def get_library_extension() -> str:
    """Get platform-appropriate library extension"""
    if is_windows():
        return '.dll'
    elif is_macos():
        return '.dylib'
    else:
        return '.so'
