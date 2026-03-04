# Changelog

All notable changes to VMDragonSlayer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Public release preparation infrastructure
- Comprehensive security documentation (SECURITY.md)
- Contribution guidelines (CONTRIBUTING.md)
- Code of conduct (CODE_OF_CONDUCT.md)
- Modern Python packaging with pyproject.toml
- CI/CD pipeline with GitHub Actions
- Pre-commit hooks for code quality
- Security scanning with bandit and pip-audit
- Type checking configuration
- Documentation framework

### Changed
- **BREAKING**: Moved large model files out of git repository
- License classification corrected to GPL-3.0-or-later
- Improved error handling in model loading
- Enhanced plugin build documentation

### Security
- **CRITICAL**: Identified unsafe pickle loading vulnerability (CVE-PENDING-001)
- Added secure model loading recommendations
- Implemented dependency vulnerability scanning
- Added secrets detection in CI pipeline

### Fixed
- License inconsistency between LICENSE file and setup.py
- Hardcoded paths in Ghidra plugin build configuration
- Missing dependency specifications

### Deprecated
- Legacy setup.py installation (use pyproject.toml)
- Direct pickle.load() usage (use joblib with safety checks)

## [2.0.0] - Work in Progress

### Added
- Multi-engine VM detection framework
- Dynamic Taint Tracking (DTT) engine
- Symbolic Execution engine with ML-driven path prioritization
- Pattern analysis with hybrid rule-based and ML classification
- Ghidra, IDA Pro, and Binary Ninja plugin support
- REST API server with FastAPI
- Enterprise features (analytics dashboard, compliance framework)
- GPU acceleration support
- Machine learning pipeline with ensemble models

### Core Components
- **VM Discovery**: Dispatcher and handler table identification
- **Pattern Analysis**: Rule-based, similarity, and ML classification
- **Taint Tracking**: Intel Pin-driven byte-level analysis
- **Symbolic Execution**: Constraint solving and state tracking
- **Orchestrator**: Sequential, parallel, and adaptive workflows
- **ML Models**: Bytecode, VM detector, handler, and ensemble classifiers

### Plugin Integration
- **Ghidra**: Gradle-based plugin with UI integration
- **IDA Pro**: Python plugin with unified API
- **Binary Ninja**: Native plugin support
- **API Integration**: REST endpoints for remote analysis

### Data Management
- **Pattern Database**: JSON and SQLite-backed patterns
- **Model Registry**: Versioned ML model management
- **Configuration**: Environment-based configuration system
- **Schemas**: JSON schema validation for outputs

## [1.x] - Legacy Versions

Previous versions were internal development releases not suitable for public use.

## Security Advisories

### CVE-PENDING-001: Unsafe Model Loading
- **Severity**: Critical
- **Affected Versions**: All versions prior to 2.1.0
- **Description**: Pickle loading allows arbitrary code execution
- **Mitigation**: Do not load untrusted model files
- **Fix**: Planned for version 2.1.0 with secure joblib loading

## Migration Guide

### From Legacy Setup.py to PyProject.toml

**Old installation:**
```bash
cd dragonslayer/
pip install -e .
```

**New installation:**
```bash
pip install -e ".[dev,ml,web]"
```

### Model File Changes

**Breaking Change**: Large model files moved from git repository to releases.

**Old location:**
- `data/models/pretrained/*.pkl` (in git)

**New location:**
- Download from GitHub Releases
- Or use model download script: `python -m dragonslayer.utils.download_models`

### Security Updates Required

1. **Model Loading**: Replace direct pickle usage
   ```python
   # Old (UNSAFE)
   import pickle
   with open(model_path, 'rb') as f:
       model = pickle.load(f)
   
   # New (SAFER)
   import joblib
   model = joblib.load(model_path)  # With integrity verification
   ```

2. **Configuration**: Use environment variables
   ```python
   # Old
   DATABASE_PASSWORD = "hardcoded_password"
   
   # New
   DATABASE_PASSWORD = os.getenv("DB_PASSWORD")
   ```

## Development Workflow Changes

### Pre-Commit Hooks
New development workflow requires pre-commit hooks:
```bash
pip install pre-commit
pre-commit install
```

### Testing Requirements
- Minimum 70% code coverage for new features
- Security scan must pass (bandit)
- Type checking with mypy
- All quality gates must pass in CI

### Documentation Requirements
- Security impact assessment for all changes
- API documentation for new interfaces
- Plugin documentation for compatibility changes

## Acknowledgments

### Contributors
- van1sh (@poppopjmp) - Project lead and core development
- Security review team - Vulnerability identification
- Community contributors - Testing and feedback

### Dependencies
Major dependencies and their roles:
- **PyTorch**: Machine learning model support
- **scikit-learn**: Classical ML algorithms
- **FastAPI**: Web API framework
- **Ghidra**: Reverse engineering platform integration
- **Intel Pin**: Dynamic binary instrumentation

## Release Schedule

### 2.1.0 (Target: September 2025)
- **Focus**: Security fixes and public release readiness
- **Key Features**: Secure model loading, complete CI/CD
- **Breaking Changes**: Model file locations

### 2.2.0 (Target: Q4 2025)
- **Focus**: Performance optimization and UI improvements
- **Key Features**: Enhanced Ghidra integration, API v2
- **Breaking Changes**: Minimal, backward compatibility maintained

### 3.0.0 (Target: Q1 2026)
- **Focus**: Architecture modernization
- **Key Features**: Cloud deployment, microservices architecture
- **Breaking Changes**: Major API redesign

---

For more information about releases, see:
- [GitHub Releases](https://github.com/poppopjmp/vmdragonslayer/releases)
- [Security Advisories](https://github.com/poppopjmp/vmdragonslayer/security/advisories)
- [Migration Guides](https://vmdragonslayer.readthedocs.io/migration/)
