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
Test configuration for VMDragonSlayer test suite.
"""

import tempfile
from importlib.util import find_spec
from pathlib import Path
from unittest.mock import Mock

import pytest

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
            "vm_detection": {"enabled": True, "confidence_threshold": 0.8},
            "pattern_analysis": {"enabled": True, "use_ml": True},
        },
        "ml": {"model_cache_size": 3, "batch_size": 32, "device_preference": "cpu"},
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
TORCH_AVAILABLE = find_spec("torch") is not None
SKLEARN_AVAILABLE = find_spec("sklearn") is not None

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
