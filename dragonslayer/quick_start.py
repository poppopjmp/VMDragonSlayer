#!/usr/bin/env python3
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
VMDragonSlayer Quick Start Script
===============================

Simple script to quickly start VMDragonSlayer with automatic dependency handling.

Usage:
    python quick_start.py
"""

import importlib
import subprocess
import sys
from pathlib import Path

# Add dragonslayer to path
sys.path.insert(0, str(Path(__file__).parent))


def install_package(package):
    """Install a package using pip"""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        return True
    except subprocess.CalledProcessError:
        return False


def check_and_install_core_deps():
    """Check and install core dependencies"""
    core_deps = [
        "numpy",
        "pandas",
        "scikit-learn",
        "fastapi",
        "uvicorn",
        "aiohttp",
        "capstone",
        "unicorn",
        "cryptography",
    ]

    missing = []
    for dep in core_deps:
        try:
            importlib.import_module(dep.replace("-", "_"))
        except ImportError:
            missing.append(dep)

    if missing:
        print(f"Installing {len(missing)} core dependencies...")
        for dep in missing:
            print(f"Installing {dep}...")
            if not install_package(dep):
                print(f"Failed to install {dep}")
                return False

    return True


def check_and_install_enterprise_deps():
    """Check and install enterprise dependencies (optional)"""
    enterprise_deps = ["plotly", "dash", "jinja2", "redis", "psutil"]

    missing = []
    for dep in enterprise_deps:
        try:
            importlib.import_module(dep.replace("-", "_"))
        except ImportError:
            missing.append(dep)

    if missing:
        print(f"Installing {len(missing)} enterprise dependencies...")
        for dep in missing:
            print(f"Installing {dep}...")
            install_package(dep)  # Don't fail if these don't install


def main():
    """Main quick start function"""
    print("🐉 VMDragonSlayer Quick Start")
    print("=" * 40)

    # Check core dependencies
    print("📦 Checking core dependencies...")
    if not check_and_install_core_deps():
        print(" Failed to install core dependencies")
        return 1

    # Check enterprise dependencies
    print("🏢 Checking enterprise dependencies...")
    check_and_install_enterprise_deps()

    # Try to import dragonslayer
    print("🚀 Starting VMDragonSlayer...")
    try:
        import dragonslayer
        from dragonslayer import get_api

        print(" VMDragonSlayer loaded successfully!")

        # Get API instance
        get_api()
        print(" API instance created")

        # Show available modules
        print("\n📋 Available modules:")

        try:
            if hasattr(dragonslayer, "GPU_AVAILABLE") and dragonslayer.GPU_AVAILABLE:
                print("   GPU Acceleration")
            else:
                print("  ⚠️ GPU Acceleration (install cupy for CUDA support)")
        except Exception:
            print("  ⚠️ GPU Acceleration (optional)")

        try:
            if (
                hasattr(dragonslayer, "ANALYTICS_AVAILABLE")
                and dragonslayer.ANALYTICS_AVAILABLE
            ):
                print("   Analytics Dashboard")
            else:
                print("  ⚠️ Analytics Dashboard (install plotly, dash)")
        except Exception:
            print("  ⚠️ Analytics Dashboard (optional)")

        try:
            if (
                hasattr(dragonslayer, "ANTI_EVASION_AVAILABLE")
                and dragonslayer.ANTI_EVASION_AVAILABLE
            ):
                print("   Anti-Evasion")
            else:
                print("  ⚠️ Anti-Evasion")
        except Exception:
            print("  ⚠️ Anti-Evasion (optional)")

        try:
            if (
                hasattr(dragonslayer, "ENTERPRISE_AVAILABLE")
                and dragonslayer.ENTERPRISE_AVAILABLE
            ):
                print("   Enterprise Integration")
            else:
                print("  ⚠️ Enterprise Integration (install redis, pika)")
        except Exception:
            print("  ⚠️ Enterprise Integration (optional)")

        print("\n💡 Quick usage:")
        print(">>> from dragonslayer import get_api")
        print(">>> api = get_api()")
        print(">>> result = api.analyze_file('sample.exe')")
        print(">>> print(result)")

        print("\n🎉 Ready to use VMDragonSlayer!")
        return 0

    except ImportError as e:
        print(f" Failed to import dragonslayer: {e}")
        return 1
    except Exception as e:
        print(f" Startup error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
