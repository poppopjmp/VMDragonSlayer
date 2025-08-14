"""
Test configuration for VMDragonSlayer test suite.
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch

# Test fixtures and utilities

@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield Path(tmp_dir)

@pytest.fixture
def sample_config():
    """Create a sample configuration for testing."""
    return {
        "analysis": {
            "vm_detection": {
                "enabled": True,
                "confidence_threshold": 0.8
            },
            "pattern_analysis": {
                "enabled": True,
                "use_ml": True
            }
        },
        "ml": {
            "model_cache_size": 3,
            "batch_size": 32,
            "device_preference": "cpu"
        }
    }

@pytest.fixture
def mock_model():
    """Create a mock ML model for testing."""
    model = Mock()
    model.predict.return_value = [1]
    model.predict_proba.return_value = [[0.2, 0.8]]
    return model

@pytest.fixture
def sample_bytecode():
    """Sample bytecode for testing."""
    return bytes.fromhex("4889e54883ec20488b7df8488b75f0")

# Test markers
pytest_slow = pytest.mark.slow
pytest_ml = pytest.mark.ml
pytest_integration = pytest.mark.integration
pytest_gpu = pytest.mark.gpu

# Skip conditions for optional dependencies
try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

try:
    import sklearn
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

skip_if_no_torch = pytest.mark.skipif(
    not TORCH_AVAILABLE, reason="PyTorch not available"
)

skip_if_no_sklearn = pytest.mark.skipif(
    not SKLEARN_AVAILABLE, reason="scikit-learn not available"
)

# Test utilities
def create_mock_binary_file(path: Path, size: int = 1024) -> Path:
    """Create a mock binary file for testing."""
    path.write_bytes(b"MZ" + b"\x00" * (size - 2))
    return path

def create_mock_model_file(path: Path) -> Path:
    """Create a mock model file for testing."""
    import joblib
    mock_model = Mock()
    mock_model.predict.return_value = [1]
    joblib.dump({"model": mock_model, "metadata": {"version": "test"}}, path)
    return path
