# Release and Build Guide

This document provides step-by-step instructions for building, testing, and releasing VMDragonSlayer.

## Table of Contents
- [Development Setup](#development-setup)
- [Building from Source](#building-from-source)
- [Plugin Builds](#plugin-builds)
- [Testing](#testing)
- [Release Process](#release-process)
- [Distribution](#distribution)

## Development Setup

### Prerequisites
- **Python**: 3.8+ (3.11+ recommended for development)
- **Git**: Latest stable version
- **Java**: JDK 17+ (for Ghidra plugin)
- **Gradle**: 7.0+ (for Ghidra plugin)

### Initial Setup
```bash
# Clone repository
git clone https://github.com/poppopjmp/vmdragonslayer.git
cd vmdragonslayer

# Create virtual environment
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate

# Install in development mode
pip install -e ".[dev,ml,web]"

# Install pre-commit hooks
pre-commit install

# Verify installation
python -c "import dragonslayer; print('Setup successful!')"
```

## Building from Source

### Python Package

#### Modern Build (Recommended)
```bash
# Install build tools
pip install build twine

# Build source distribution and wheel
python -m build

# Check package integrity
twine check dist/*

# Verify contents
tar -tzf dist/vmdragonslayer-*.tar.gz | head -20
unzip -l dist/vmdragonslayer-*.whl | head -20
```

#### Legacy Build (Fallback)
```bash
# Using setuptools directly
cd dragonslayer/
python setup.py sdist bdist_wheel

# Check outputs
ls -la dist/
```

### Build Verification
```bash
# Test installation from built package
pip install dist/vmdragonslayer-*.whl

# Run basic functionality test
python -c "
from dragonslayer.core import VMDragonSlayerConfig
from dragonslayer.analysis.vm_discovery import VMDetector
print('Package verification successful')
"
```

## Plugin Builds

### Ghidra Plugin

#### Prerequisites
```bash
# Set Ghidra installation path
export GHIDRA_INSTALL_DIR=/path/to/ghidra
# Windows PowerShell
$env:GHIDRA_INSTALL_DIR="C:\ghidra_11.4.1_PUBLIC"
```

#### Build Steps
```bash
cd plugins/ghidra

# Clean previous builds
gradle clean

# Build extension
gradle buildExtension

# Output location
ls -la dist/
# Should contain: vmdragonslayer_ghidra_*.zip
```

#### Manual Build (Alternative)
```bash
# Using Ghidra's build system directly
cd plugins/ghidra
$GHIDRA_INSTALL_DIR/support/gradle/gradle buildExtension
```

#### Installation
```bash
# Method 1: Via Ghidra GUI
# 1. Open Ghidra
# 2. File > Install Extensions
# 3. Select vmdragonslayer_ghidra_*.zip
# 4. Restart Ghidra

# Method 2: Manual installation
cp dist/vmdragonslayer_ghidra_*.zip $GHIDRA_INSTALL_DIR/Extensions/Ghidra/
```

### IDA Pro Plugin

#### Build (Copy-based)
```bash
# No compilation needed - pure Python
cd plugins/idapro

# Verify plugin structure
python -m py_compile vmdragonslayer_ida.py

# Package for distribution
zip -r vmdragonslayer_ida_plugin.zip vmdragonslayer_ida.py README.md
```

#### Installation
```bash
# Find IDA plugins directory
# Windows: %APPDATA%\Hex-Rays\IDA Pro\plugins\
# Linux: ~/.idapro/plugins/
# macOS: ~/.idapro/plugins/

# Copy plugin file
cp vmdragonslayer_ida.py $IDA_PLUGINS_DIR/
```

### Binary Ninja Plugin

#### Build
```bash
cd plugins/binaryninja

# Verify plugin structure
python -m py_compile vmdragonslayer_bn.py ui/__init__.py

# Package for distribution
zip -r vmdragonslayer_bn_plugin.zip * -x "*.pyc" "*/__pycache__/*"
```

#### Installation
```bash
# Binary Ninja user plugins directory
# Windows: %APPDATA%\Binary Ninja\plugins\
# Linux: ~/.binaryninja/plugins/
# macOS: ~/Library/Application Support/Binary Ninja/plugins/

# Copy plugin directory
cp -r plugins/binaryninja/vmdragonslayer_bn $BN_PLUGINS_DIR/
```

## Testing

### Unit Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=dragonslayer --cov-report=html --cov-report=term

# Run specific test categories
pytest -m "not slow"  # Skip slow tests
pytest -m "ml"        # Only ML tests
pytest tests/unit/    # Only unit tests
```

### Integration Tests
```bash
# Full integration test suite
pytest tests/integration/

# Plugin integration tests
pytest tests/integration/test_plugins.py
```

### Security Tests
```bash
# Static security analysis
bandit -r dragonslayer/

# Dependency vulnerability scan
pip-audit

# Secret scanning
detect-secrets scan --baseline .secrets.baseline
```

### Performance Tests
```bash
# Benchmark core functionality
pytest tests/performance/ -v

# Memory usage analysis
python -m memory_profiler tests/performance/test_memory_usage.py
```

## Release Process

### Pre-Release Checklist
- [ ] All CI checks passing
- [ ] Version bumped in `pyproject.toml`
- [ ] `CHANGELOG.md` updated
- [ ] Security scan clean
- [ ] Documentation updated
- [ ] Plugin builds verified

### Version Bumping
```bash
# Update version in pyproject.toml
# Example: "2.0.0" -> "2.1.0"

# Commit version bump
git add pyproject.toml CHANGELOG.md
git commit -m "chore: bump version to 2.1.0"
git tag v2.1.0
git push origin main --tags
```

### GitHub Release Creation
```bash
# Create release via GitHub CLI
gh release create v2.1.0 \
  --title "VMDragonSlayer v2.1.0" \
  --notes-file CHANGELOG.md \
  --draft

# Upload artifacts
gh release upload v2.1.0 \
  dist/vmdragonslayer-*.tar.gz \
  dist/vmdragonslayer-*.whl \
  plugins/ghidra/dist/vmdragonslayer_ghidra_*.zip \
  plugins/idapro/vmdragonslayer_ida_plugin.zip \
  plugins/binaryninja/vmdragonslayer_bn_plugin.zip
```

### PyPI Release
```bash
# Test upload to TestPyPI first
twine upload --repository testpypi dist/*

# Verify test installation
pip install --index-url https://test.pypi.org/simple/ vmdragonslayer

# Upload to production PyPI
twine upload dist/*
```

## Distribution

### Package Verification
```bash
# Verify package contents
python -m tarfile -l dist/vmdragonslayer-*.tar.gz

# Check metadata
python -m pkginfo dist/vmdragonslayer-*.whl

# Test installation in clean environment
docker run --rm -v $(pwd)/dist:/dist python:3.11 \
  bash -c "pip install /dist/vmdragonslayer-*.whl && python -c 'import dragonslayer; print(\"OK\")'"
```

### Security Artifacts
```bash
# Generate checksums
cd dist/
sha256sum * > SHA256SUMS
gpg --detach-sign --armor SHA256SUMS

# Generate SBOM (Software Bill of Materials)
pip install cyclonedx-bom
cyclonedx-py -o sbom.json
```

### Distribution Channels

#### Primary
- **PyPI**: `pip install vmdragonslayer`
- **GitHub Releases**: Binary distributions and plugins
- **GitHub Container Registry**: Docker images (future)

#### Secondary  
- **Conda-forge**: Community packaging (future)
- **Arch AUR**: Community packaging (future)
- **Homebrew**: macOS packaging (future)

## Troubleshooting

### Common Build Issues

#### Ghidra Plugin Build Fails
```bash
# Check Ghidra path
echo $GHIDRA_INSTALL_DIR
ls $GHIDRA_INSTALL_DIR/support/buildExtension.gradle

# Verify Java version
java -version  # Should be 17+

# Check Gradle version
gradle --version  # Should be 7.0+
```

#### Python Dependencies Fail
```bash
# Update pip and build tools
pip install --upgrade pip setuptools wheel

# Install with verbose output
pip install -e ".[dev]" -v

# Check for conflicting packages
pip check
```

#### Test Failures
```bash
# Run tests with verbose output
pytest -v --tb=long

# Check test environment
python -m pytest --collect-only

# Verify optional dependencies
python -c "
try:
    import torch; print('PyTorch: OK')
except: print('PyTorch: Missing')
try:
    import sklearn; print('sklearn: OK') 
except: print('sklearn: Missing')
"
```

### Performance Issues

#### Slow Tests
```bash
# Run only fast tests
pytest -m "not slow"

# Profile test execution
pytest --durations=10

# Parallel test execution
pytest -n auto  # Requires pytest-xdist
```

#### Large Package Size
```bash
# Analyze package contents
python -m zipfile -l dist/vmdragonslayer-*.whl | sort -k3 -n

# Check for included data files
find . -name "*.pkl" -o -name "*.pt" -o -name "*.pth" | head -10
```

## Automation

### GitHub Actions Integration
The repository includes automated CI/CD that:
- Runs on every push and PR
- Builds packages and plugins
- Runs security scans
- Publishes releases automatically

### Local Automation Scripts
```bash
# Full build and test cycle
./scripts/build-all.sh

# Release preparation
./scripts/prepare-release.sh v2.1.0

# Plugin distribution
./scripts/package-plugins.sh
```

---

For questions about builds or releases:
- **Issues**: [GitHub Issues](https://github.com/poppopjmp/vmdragonslayer/issues)
- **Discussions**: [GitHub Discussions](https://github.com/poppopjmp/vmdragonslayer/discussions)
- **Email**: build-support@vmdragonslayer.dev
