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
Tests for VMDragonSlayer core configuration module.
"""

import json
from unittest.mock import mock_open, patch

import pytest

from dragonslayer.core.config import MLConfig


class TestMLConfig:
    """Tests for MLConfig dataclass."""

    def test_ml_config_defaults(self):
        """Test MLConfig has correct default values."""
        config = MLConfig()

        assert config.model_cache_size == 3
        assert config.batch_size == 32
        assert config.max_sequence_length == 1024
        assert config.memory_optimization is True
        assert config.device_preference == "auto"
        assert config.confidence_threshold == 0.8

    def test_ml_config_custom_values(self):
        """Test MLConfig with custom values."""
        config = MLConfig(
            model_cache_size=5,
            batch_size=64,
            device_preference="cuda",
            confidence_threshold=0.9,
        )

        assert config.model_cache_size == 5
        assert config.batch_size == 64
        assert config.device_preference == "cuda"
        assert config.confidence_threshold == 0.9

    def test_ml_config_framework_preferences(self):
        """Test ML framework preference defaults."""
        config = MLConfig()

        assert config.use_pytorch is True
        assert config.use_sklearn is True
        assert config.use_tensorflow is False


class TestVMDragonSlayerConfig:
    """Tests for main configuration class."""

    def test_config_initialization(self, temp_dir):
        """Test configuration initialization."""
        config_file = temp_dir / "test_config.json"
        config_data = {"ml": {"model_cache_size": 5, "batch_size": 64}}

        with open(config_file, "w") as f:
            json.dump(config_data, f)

        # This would test actual config loading if implemented
        # config = VMDragonSlayerConfig.from_file(config_file)
        # assert config.ml.model_cache_size == 5

    def test_config_environment_variables(self):
        """Test configuration loading from environment variables."""
        with patch.dict("os.environ", {"VMDS_ML_BATCH_SIZE": "128"}):
            # This would test env var loading if implemented
            pass

    def test_config_validation(self):
        """Test configuration validation."""
        # Test invalid confidence threshold
        with pytest.raises(ValueError):
            MLConfig(confidence_threshold=1.5)  # Should be 0-1

    @patch("builtins.open", new_callable=mock_open, read_data='{"test": "data"}')
    def test_config_file_loading(self, mock_file):
        """Test configuration file loading with mocked file."""
        # This would test file loading implementation
        pass

    def test_config_defaults_complete(self):
        """Test that all required configuration sections have defaults."""
        config = MLConfig()

        # Verify critical settings have defaults
        assert hasattr(config, "pattern_database_path")
        assert hasattr(config, "model_registry_path")
        assert hasattr(config, "default_epochs")
        assert hasattr(config, "learning_rate")

    def test_config_serialization(self, temp_dir):
        """Test configuration can be serialized and deserialized."""
        config = MLConfig(
            model_cache_size=10, batch_size=128, confidence_threshold=0.95
        )

        # Test dictionary conversion
        config_dict = config.__dict__
        assert config_dict["model_cache_size"] == 10
        assert config_dict["batch_size"] == 128
        assert config_dict["confidence_threshold"] == 0.95

    def test_config_path_resolution(self, temp_dir):
        """Test that configuration paths are resolved correctly."""
        config = MLConfig(
            pattern_database_path="data/pattern_database.json",
            model_registry_path="data/model_registry.db",
        )

        # Test paths are strings (basic validation)
        assert isinstance(config.pattern_database_path, str)
        assert isinstance(config.model_registry_path, str)
        assert "pattern_database.json" in config.pattern_database_path


# Integration-style tests
class TestConfigurationIntegration:
    """Integration tests for configuration management."""

    def test_config_workflow(self, temp_dir):
        """Test complete configuration workflow."""
        # Create test config file
        config_file = temp_dir / "vmds_config.json"
        config_data = {
            "ml": {
                "model_cache_size": 5,
                "batch_size": 64,
                "confidence_threshold": 0.9,
                "device_preference": "cpu",
            }
        }

        with open(config_file, "w") as f:
            json.dump(config_data, f)

        # Verify file was created
        assert config_file.exists()

        # Test reading back
        with open(config_file) as f:
            loaded_data = json.load(f)

        assert loaded_data["ml"]["model_cache_size"] == 5
        assert loaded_data["ml"]["confidence_threshold"] == 0.9

    def test_config_error_handling(self):
        """Test configuration error handling."""
        # Test invalid values
        with pytest.raises((ValueError, TypeError)):
            MLConfig(model_cache_size="invalid")  # Should be int

        with pytest.raises((ValueError, TypeError)):
            MLConfig(batch_size=-1)  # Should be positive

    @pytest.mark.parametrize("device", ["auto", "cpu", "cuda"])
    def test_device_preferences(self, device):
        """Test various device preference settings."""
        config = MLConfig(device_preference=device)
        assert config.device_preference == device

    @pytest.mark.parametrize("threshold", [0.0, 0.5, 0.8, 1.0])
    def test_confidence_thresholds(self, threshold):
        """Test various confidence threshold settings."""
        config = MLConfig(confidence_threshold=threshold)
        assert config.confidence_threshold == threshold
