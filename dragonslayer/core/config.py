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
VMDragonSlayer Core Configuration Management
==========================================

Centralized configuration management for the VMDragonSlayer system.
Provides type-safe configuration with validation and environment variable support.
"""

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

logger = logging.getLogger(__name__)


@dataclass
class MLConfig:
    """Machine Learning configuration"""

    model_cache_size: int = 3
    batch_size: int = 32
    max_sequence_length: int = 1024
    memory_optimization: bool = True
    device_preference: str = "auto"  # "auto", "cpu", "cuda"
    pattern_database_path: str = "data/pattern_database.json"
    confidence_threshold: float = 0.8

    # Framework preferences
    use_pytorch: bool = True
    use_sklearn: bool = True
    use_tensorflow: bool = False

    # Model training
    default_epochs: int = 100
    early_stopping_patience: int = 10
    learning_rate: float = 0.001
    validation_split: float = 0.2

    # Feature extraction
    max_features: int = 1000
    use_feature_selection: bool = True
    feature_selection_k: int = 100

    # Model registry
    model_registry_path: str = "data/model_registry.db"
    auto_model_cleanup: bool = True
    max_model_versions: int = 10

    def __post_init__(self):
        """Validate configuration values"""
        if self.model_cache_size < 1:
            raise ValueError("model_cache_size must be at least 1")
        if self.batch_size < 1:
            raise ValueError("batch_size must be at least 1")
        if not 0.0 <= self.confidence_threshold <= 1.0:
            raise ValueError("confidence_threshold must be between 0.0 and 1.0")
        if not 0.0 <= self.learning_rate <= 1.0:
            raise ValueError("learning_rate must be between 0.0 and 1.0")
        if not 0.0 <= self.validation_split <= 1.0:
            raise ValueError("validation_split must be between 0.0 and 1.0")


@dataclass
class APIConfig:
    """API service configuration"""

    host: str = "127.0.0.1"
    port: int = 8000
    workers: int = 4
    timeout: int = 300
    max_file_size_mb: int = 100
    enable_auth: bool = True
    enable_websockets: bool = True
    cors_origins: list = field(default_factory=lambda: ["*"])

    def __post_init__(self):
        """Validate configuration values"""
        if not 1 <= self.port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        if self.workers < 1:
            raise ValueError("workers must be at least 1")
        if self.timeout < 1:
            raise ValueError("timeout must be at least 1")


@dataclass
class AnalysisConfig:
    """Analysis engine configuration"""

    default_analysis_type: str = "hybrid"
    max_analysis_time: int = 600  # seconds
    enable_caching: bool = True
    cache_size: int = 1000
    enable_parallel_processing: bool = True
    max_parallel_jobs: int = 4
    memory_limit_mb: int = 2048
    temp_dir: str = "temp"

    def __post_init__(self):
        """Validate configuration values"""
        valid_types = [
            "vm_discovery",
            "pattern_analysis",
            "taint_tracking",
            "symbolic_execution",
            "hybrid",
            "batch",
        ]
        if self.default_analysis_type not in valid_types:
            raise ValueError(f"default_analysis_type must be one of {valid_types}")
        if self.max_analysis_time < 1:
            raise ValueError("max_analysis_time must be at least 1")
        if self.max_parallel_jobs < 1:
            raise ValueError("max_parallel_jobs must be at least 1")


@dataclass
class InfrastructureConfig:
    """Infrastructure configuration"""

    log_level: str = "INFO"
    log_file: str = "vmdragonslayer.log"
    monitoring_enabled: bool = True
    metrics_port: int = 8080
    health_check_interval: int = 60
    enable_debug: bool = False

    def __post_init__(self):
        """Validate configuration values"""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.log_level.upper() not in valid_levels:
            raise ValueError(f"log_level must be one of {valid_levels}")
        if not 1 <= self.metrics_port <= 65535:
            raise ValueError("metrics_port must be between 1 and 65535")


@dataclass
class VMDragonSlayerConfig:
    """Main VMDragonSlayer system configuration"""

    version: str = "1.0.0"
    ml: MLConfig = field(default_factory=MLConfig)
    api: APIConfig = field(default_factory=APIConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    infrastructure: InfrastructureConfig = field(default_factory=InfrastructureConfig)

    # Directory paths
    data_dir: str = "data"
    models_dir: str = "models"
    logs_dir: str = "logs"
    cache_dir: str = "cache"

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return asdict(self)

    def update_from_dict(self, config_dict: Dict[str, Any]) -> None:
        """Update configuration from dictionary"""
        for section, values in config_dict.items():
            if hasattr(self, section) and isinstance(values, dict):
                section_obj = getattr(self, section)
                for key, value in values.items():
                    if hasattr(section_obj, key):
                        setattr(section_obj, key, value)
                    else:
                        logger.warning(f"Unknown config key: {section}.{key}")
            elif hasattr(self, section):
                setattr(self, section, values)
            else:
                logger.warning(f"Unknown config section: {section}")


class ConfigManager:
    """Centralized configuration manager for VMDragonSlayer"""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager.

        Args:
            config_path: Optional path to configuration file
        """
        self.config_path = config_path or self._find_config_file()
        self._config = VMDragonSlayerConfig()
        self._loaded = False

        # Load configuration if file exists
        if self.config_path and Path(self.config_path).exists():
            self.load()
        else:
            # Apply environment variable overrides
            self._apply_env_overrides()

    def _find_config_file(self) -> Optional[str]:
        """Find configuration file in standard locations"""
        search_paths = [
            "vmdragonslayer_config.yml",
            "config/vmdragonslayer_config.yml",
            "config/config.yml",
            os.path.expanduser("~/.vmdragonslayer/config.yml"),
            "/etc/vmdragonslayer/config.yml",
        ]

        for path in search_paths:
            if Path(path).exists():
                logger.info(f"Found config file: {path}")
                return path

        logger.info("No config file found, using defaults")
        return None

    def load(self, config_path: Optional[str] = None) -> None:
        """
        Load configuration from file.

        Args:
            config_path: Optional path to configuration file
        """
        if config_path:
            self.config_path = config_path

        if not self.config_path or not Path(self.config_path).exists():
            logger.warning(f"Config file not found: {self.config_path}")
            return

        try:
            with open(self.config_path) as f:
                if self.config_path.endswith(".json"):
                    config_dict = json.load(f)
                elif self.config_path.endswith((".yml", ".yaml")):
                    config_dict = yaml.safe_load(f)
                else:
                    raise ValueError(f"Unsupported config format: {self.config_path}")

            # Update configuration
            self._config.update_from_dict(config_dict)
            self._loaded = True

            # Apply environment variable overrides
            self._apply_env_overrides()

            logger.info(f"Configuration loaded from: {self.config_path}")

        except Exception as e:
            logger.error(f"Failed to load config from {self.config_path}: {e}")
            raise

    def save(self, config_path: Optional[str] = None) -> None:
        """
        Save configuration to file.

        Args:
            config_path: Optional path to save configuration
        """
        save_path = config_path or self.config_path or "vmdragonslayer_config.yml"

        try:
            # Ensure directory exists
            Path(save_path).parent.mkdir(parents=True, exist_ok=True)

            with open(save_path, "w") as f:
                if save_path.endswith(".json"):
                    json.dump(self._config.to_dict(), f, indent=2)
                else:
                    yaml.dump(self._config.to_dict(), f, default_flow_style=False)

            logger.info(f"Configuration saved to: {save_path}")

        except Exception as e:
            logger.error(f"Failed to save config to {save_path}: {e}")
            raise

    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides"""
        env_mappings = {
            "VMDS_LOG_LEVEL": ("infrastructure", "log_level"),
            "VMDS_API_HOST": ("api", "host"),
            "VMDS_API_PORT": ("api", "port"),
            "VMDS_WORKERS": ("api", "workers"),
            "VMDS_MAX_FILE_SIZE": ("api", "max_file_size_mb"),
            "VMDS_ML_DEVICE": ("ml", "device_preference"),
            "VMDS_ANALYSIS_TYPE": ("analysis", "default_analysis_type"),
            "VMDS_MEMORY_LIMIT": ("analysis", "memory_limit_mb"),
            "VMDS_DEBUG": ("infrastructure", "enable_debug"),
        }

        for env_var, (section, key) in env_mappings.items():
            if env_var in os.environ:
                value = os.environ[env_var]

                # Type conversion
                if key in ["port", "workers", "max_file_size_mb", "memory_limit_mb"]:
                    value = int(value)
                elif key in ["enable_debug"]:
                    value = value.lower() in ("true", "1", "yes", "on")

                # Apply override
                section_obj = getattr(self._config, section)
                setattr(section_obj, key, value)
                logger.info(
                    f"Applied env override: {env_var} -> {section}.{key} = {value}"
                )

    @property
    def config(self) -> VMDragonSlayerConfig:
        """Get current configuration"""
        return self._config

    def get_section(self, section_name: str) -> Any:
        """Get configuration section"""
        if hasattr(self._config, section_name):
            return getattr(self._config, section_name)
        else:
            raise ValueError(f"Unknown configuration section: {section_name}")

    def update_section(self, section_name: str, **kwargs) -> None:
        """Update configuration section"""
        if hasattr(self._config, section_name):
            section_obj = getattr(self._config, section_name)
            for key, value in kwargs.items():
                if hasattr(section_obj, key):
                    setattr(section_obj, key, value)
                    logger.info(f"Updated config: {section_name}.{key} = {value}")
                else:
                    logger.warning(f"Unknown config key: {section_name}.{key}")
        else:
            raise ValueError(f"Unknown configuration section: {section_name}")

    def is_loaded(self) -> bool:
        """Check if configuration was loaded from file"""
        return self._loaded


# Global configuration manager instance
_config_manager = None


def get_config_manager(config_path: Optional[str] = None) -> ConfigManager:
    """Get global configuration manager instance"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_path)
    return _config_manager


def get_config(config_path: Optional[str] = None) -> VMDragonSlayerConfig:
    """Get current configuration"""
    return get_config_manager(config_path).config


def configure(**kwargs) -> None:
    """Update global configuration"""
    config_manager = get_config_manager()
    for section, values in kwargs.items():
        if isinstance(values, dict):
            config_manager.update_section(section, **values)
        else:
            logger.warning(f"Configuration section must be a dict: {section}")


# Convenience functions for common configuration access
def get_ml_config() -> MLConfig:
    """Get ML configuration"""
    return get_config().ml


def get_api_config() -> APIConfig:
    """Get API configuration"""
    return get_config().api


def get_analysis_config() -> AnalysisConfig:
    """Get analysis configuration"""
    return get_config().analysis


def get_infrastructure_config() -> InfrastructureConfig:
    """Get infrastructure configuration"""
    return get_config().infrastructure
