# Contributing to VMDragonSlayer

Thank you for your interest in contributing to VMDragonSlayer! This document provides guidelines for contributing to the project.

## Table of Contents
- [Development Environment Setup](#development-environment-setup)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Security Considerations](#security-considerations)

## Development Environment Setup

### Prerequisites
- **Python**: 3.8+ (3.11+ recommended)
- **Git**: Latest stable version
- **Optional**: Docker for isolated testing environments

### Environment Setup

1. **Clone the repository:**
```bash
git clone https://github.com/poppopjmp/VMDragonSlayer.git
cd VMDragonSlayer
```

2. **Create virtual environment:**
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS  
source venv/bin/activate
```

3. **Install development dependencies:**
```bash
pip install -e ".[dev,ml,web]"
```

4. **Install pre-commit hooks:**
```bash
pre-commit install
```

5. **Verify setup:**
```bash
python -c "import dragonslayer; print('Setup successful!')"
```

### Plugin Development Setup

#### Ghidra Plugin
```bash
cd plugins/ghidra
# Set Ghidra installation path
export GHIDRA_INSTALL_DIR=/path/to/ghidra
# Build plugin
gradle buildExtension
```

#### IDA Pro Plugin
- Copy `plugins/idapro/vmdragonslayer_ida.py` to IDA plugins directory
- Restart IDA Pro
- Plugin will appear in Edit > Plugins menu

#### Binary Ninja Plugin  
- Copy `plugins/binaryninja/` directory to Binary Ninja user plugins
- Restart Binary Ninja
- Plugin will appear in Plugins menu

## Coding Standards

### Python Code Style

We use the following tools to maintain code quality:

- **Formatter**: `black` (line length: 88)
- **Import sorting**: `isort`
- **Linter**: `ruff` (replaces flake8)  
- **Type checker**: `mypy`

### Running Quality Checks

```bash
# Format code
black dragonslayer/ tests/

# Sort imports
isort dragonslayer/ tests/

# Lint code
ruff check dragonslayer/ tests/

# Type checking
mypy dragonslayer/

# Run all checks
pre-commit run --all-files
```

### Code Style Guidelines

1. **Type Hints**: Use type hints for all function signatures
```python
def analyze_binary(file_path: Path, config: AnalysisConfig) -> AnalysisResult:
    """Analyze binary file with given configuration."""
    pass
```

2. **Documentation**: Use Google-style docstrings
```python
def extract_features(bytecode: bytes) -> Dict[str, Any]:
    """Extract features from bytecode.
    
    Args:
        bytecode: Raw bytecode to analyze
        
    Returns:
        Dictionary containing extracted features
        
    Raises:
        AnalysisError: If bytecode analysis fails
    """
    pass
```

3. **Error Handling**: Use specific exception types
```python
from dragonslayer.core.exceptions import AnalysisError, ConfigurationError

# Good
raise AnalysisError("Failed to parse bytecode at offset 0x1000")

# Avoid generic exceptions
raise Exception("Something went wrong")  # Bad
```

4. **Logging**: Use structured logging
```python
import logging
logger = logging.getLogger(__name__)

# Good
logger.info("Starting analysis", extra={"file_path": path, "size": file_size})

# Include context in error logs
logger.error("Analysis failed", extra={"error": str(e), "file_path": path})
```

## Testing Guidelines

### Test Structure
```
tests/
├── unit/                 # Unit tests for individual modules
│   ├── test_core/
│   ├── test_ml/
│   └── test_analysis/
├── integration/          # Integration tests
├── fixtures/            # Test data and fixtures
└── conftest.py         # Pytest configuration
```

### Writing Tests

1. **Test Naming**: Use descriptive test names
```python
def test_vm_detector_identifies_vmprotect_v3():
    """Test that VM detector correctly identifies VMProtect v3."""
    pass

def test_pattern_classifier_handles_malformed_bytecode():
    """Test pattern classifier gracefully handles malformed input."""
    pass
```

2. **Test Organization**: Group related tests in classes
```python
class TestVMDetector:
    """Tests for VMDetector class."""
    
    def test_detect_vmprotect(self):
        pass
        
    def test_detect_themida(self):
        pass
```

3. **Fixtures**: Use pytest fixtures for common test data
```python
@pytest.fixture
def sample_bytecode():
    """Sample bytecode for testing."""
    return bytes.fromhex("48656c6c6f20576f726c64")

@pytest.fixture
def vm_detector(tmp_path):
    """VM detector instance with test configuration."""
    config = VMDetectorConfig(model_path=tmp_path / "test_model.pkl")
    return VMDetector(config)
```

4. **Mocking**: Mock external dependencies and file I/O
```python
from unittest.mock import Mock, patch

@patch('dragonslayer.ml.model.joblib.load')
def test_model_loading(mock_load):
    """Test model loading with mocked file I/O."""
    mock_load.return_value = {'model': Mock(), 'metadata': {}}
    # Test implementation
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=dragonslayer --cov-report=html

# Run specific test file
pytest tests/unit/test_core/test_config.py

# Run tests with specific marker
pytest -m "slow"
```

### Coverage Requirements

- **Minimum**: 70% overall coverage
- **Core modules**: 85% coverage required
- **New features**: 90% coverage required
- **Exclude**: Plugin code and optional dependencies

## Pull Request Process

### Before Submitting

1. **Check Requirements**:
   - [ ] All tests pass
   - [ ] Code coverage meets requirements
   - [ ] Pre-commit hooks pass
   - [ ] Documentation updated (if applicable)
   - [ ] CHANGELOG.md updated

2. **Branch Naming**:
   - `feature/description` - New features
   - `bugfix/description` - Bug fixes
   - `docs/description` - Documentation updates
   - `security/description` - Security fixes

### PR Template

```markdown
## Description
Brief description of changes made.

## Type of Change
- [ ] Bug fix
- [ ] New feature  
- [ ] Breaking change
- [ ] Documentation update
- [ ] Security fix

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed

## Security Considerations
- [ ] No security implications
- [ ] Security review required
- [ ] Updates security documentation

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] CHANGELOG.md updated
```

### Review Process

1. **Automated Checks**: CI must pass
2. **Peer Review**: At least one approval required
3. **Security Review**: Required for security-related changes
4. **Maintainer Review**: Final approval from maintainers

## Issue Reporting

### Bug Reports

Use the bug report template:

```markdown
**Bug Description**
Clear description of the bug.

**Reproduction Steps**
1. Step one
2. Step two
3. Observed behavior

**Expected Behavior**
What should have happened.

**Environment**
- OS: [e.g., Windows 10, Ubuntu 20.04]
- Python version: [e.g., 3.11.2]
- VMDragonSlayer version: [e.g., 2.0.1]
- Plugin versions: [if applicable]

**Additional Context**
Logs, screenshots, or other context.
```

### Feature Requests

Use the feature request template:

```markdown
**Feature Description**
Clear description of the requested feature.

**Use Case**
Why is this feature needed?

**Proposed Solution**
How should this feature work?

**Alternatives Considered**
Other approaches considered.

**Additional Context**
Mockups, examples, or references.
```

## Security Considerations

### Security-First Development

1. **Threat Modeling**: Consider security implications of all changes
2. **Input Validation**: Validate all external inputs
3. **Dependency Management**: Keep dependencies updated
4. **Secret Management**: Never commit secrets or credentials

### Reporting Security Issues

**DO NOT** create public issues for security vulnerabilities. Instead:
- Email: security@vmdragonslayer.com
- Include: Detailed description, reproduction steps, impact assessment

### Security Review Requirements

The following changes require security review:
- Model loading/serialization code
- Network communication code
- File I/O operations
- Plugin interfaces
- Authentication/authorization code
- Cryptographic implementations

## Recognition

Contributors will be recognized in:
- `CONTRIBUTORS.md` file
- Release notes
- Project documentation

### Contribution Types

We value all types of contributions:
- **Code**: Features, bug fixes, optimizations
- **Documentation**: Improvements, translations, examples  
- **Testing**: Test cases, bug reports, regression testing
- **Design**: UI/UX improvements, graphics, logos
- **Community**: Issue triage, user support, evangelism

## Getting Help

### Communication Channels

- **GitHub Discussions**: General questions and discussions
- **GitHub Issues**: Bug reports and feature requests  
- **Email**: contribute@vmdragonslayer.com
- **Discord**: [Link when available]

### Mentorship

New contributors can request mentorship:
- Comment on beginner-friendly issues
- Reach out via email or discussions
- Join community calls (when scheduled)

## Code of Conduct

This project adheres to the [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

---

**Thank you for contributing to VMDragonSlayer!**

For questions about this guide, please create an issue or reach out to the maintainers.
