"""
Configuration Management for VMDragonSlayer

"""

import copy
import os
import logging
import threading
from pathlib import Path
from typing import Dict, Any, Optional
import yaml

from .exceptions import ConfigurationError, ValidationError


logger = logging.getLogger(__name__)


class Config:
    """Central configuration management class."""
    
    # Default configuration values
    DEFAULTS = {
        'logging': {
            'level': 'INFO',
            'file': 'logs/vmds.log',
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        },
        'analysis': {
            'timeout': 1800,
            'max_threads': 4
        },
        'pin': {
            'path': 'pin/pin.exe',
            'timeout': 900,
            'ia32_tool': 'VMDragonTaint.x32.dll',
            'intel64_tool': 'VMDragonTaint.x64.dll'
        },
        'api': {
            'host': '127.0.0.1',
            'port': 8000,
            'workers': 4
        },
        'vmprotect': {
            'trace_depth': 100000,
            'enable_symbolic': True,
            'llvm_opt_level': 'O3',
            'skip_optimization': False,
            'validation_threshold': 0.85
        },
        'symbolic_execution': {
            'solver_timeout_ms': 10000,
            'max_paths': 64,
            'max_depth': 1000,
            'max_loop_iters': 3,
            'memory_limit_mb': 2048,
        },
    }
    
    def __init__(self, config_dir: Optional[Path] = None, environment: str = 'development'):

        self.environment = environment
        self.config_dir = config_dir or self._find_config_dir()
        self._config: Dict[str, Any] = {}
        
        # Load configuration in order of precedence
        self._load_defaults()
        self._load_yaml_config()
        self._load_env_variables()
        
        logger.info(f"Configuration loaded for environment: {environment}")
    
    def _find_config_dir(self) -> Path:
        """Find the configuration directory."""
        # Check environment variable first
        if 'VMDS_CONFIG_DIR' in os.environ:
            return Path(os.environ['VMDS_CONFIG_DIR'])
        
        # Look for config/ relative to project root
        current = Path(__file__).parent
        while current.parent != current:
            config_path = current / 'config'
            if config_path.exists():
                return config_path
            current = current.parent
        
        # Default to config/ in current directory
        return Path('config')
    
    def _load_defaults(self):
        """Load default configuration values (deep copy so mutations are isolated)."""
        self._config = copy.deepcopy(self.DEFAULTS)
    
    def _load_yaml_config(self):
        """Load YAML configuration file based on environment.

        Checks for environment-specific file first (e.g. vmdragonslayer_development.yml),
        then falls back to the generic vmdragonslayer.yml.
        """
        candidates = [
            self.config_dir / f'vmdragonslayer_{self.environment}.yml',
            self.config_dir / 'vmdragonslayer.yml',
        ]

        for config_file in candidates:
            if config_file.exists():
                try:
                    with open(config_file, 'r') as f:
                        yaml_config = yaml.safe_load(f)
                        if yaml_config:
                            self._merge_config(yaml_config)
                            logger.info(f"Loaded config from {config_file}")
                            return
                except Exception as e:
                    logger.warning(f"Failed to load config from {config_file}: {e}")

        logger.warning(
            "No config file found (tried %s), using defaults",
            ", ".join(str(c) for c in candidates),
        )
    
    def _load_env_variables(self):
        """Load configuration from environment variables."""
        if 'VMDS_LOGGING_LEVEL' in os.environ:
            self._config['logging']['level'] = os.environ['VMDS_LOGGING_LEVEL']
        

        if 'VMDS_ANALYSIS_TIMEOUT' in os.environ:
            try:
                self._config['analysis']['timeout'] = int(os.environ['VMDS_ANALYSIS_TIMEOUT'])
            except ValueError:
                logger.warning("Invalid VMDS_ANALYSIS_TIMEOUT value")
        
        if 'VMDS_PIN_PATH' in os.environ:
            self._config['pin']['path'] = os.environ['VMDS_PIN_PATH']
        
        if 'VMDS_API_HOST' in os.environ:
            self._config['api']['host'] = os.environ['VMDS_API_HOST']
        
        if 'VMDS_API_PORT' in os.environ:
            try:
                self._config['api']['port'] = int(os.environ['VMDS_API_PORT'])
            except ValueError:
                logger.warning("Invalid VMDS_API_PORT value")
    
    def _merge_config(self, new_config: Dict[str, Any]):
        """Recursively merge new configuration into existing config."""
        self._deep_merge(self._config, new_config)

    @staticmethod
    def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> None:
        """Recursively merge *override* into *base* in-place."""
        for key, value in override.items():
            if (
                isinstance(value, dict)
                and key in base
                and isinstance(base[key], dict)
            ):
                Config._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:

        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):

        keys = key.split('.')
        config = self._config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def get_section(self, section: str) -> Dict[str, Any]:

        return self._config.get(section, {})
    
    def validate(self):
        """Validate configuration values (B53 — comprehensive).

        Checks types, ranges, and consistency for all known sections.
        Raises :class:`ValidationError` on the first invalid field
        or :class:`ConfigurationError` for legacy compat.
        Warns on unrecognised top-level keys.
        """
        errors: list[str] = []

        # --- Known top-level sections ---
        known_sections = set(self.DEFAULTS.keys()) | {
            "data", "paths", "metroplex",
        }
        for key in self._config:
            if key not in known_sections:
                logger.warning("Unknown config section '%s' — typo?", key)

        # -- pin path --
        pin_path = self.get('pin.path')
        if pin_path and not Path(pin_path).exists():
            logger.warning("Pin binary not found at: %s", pin_path)

        # -- analysis.timeout --
        timeout = self.get('analysis.timeout')
        if not isinstance(timeout, int) or timeout <= 0:
            errors.append(f"analysis.timeout must be a positive int, got {timeout!r}")

        # -- analysis.max_threads --
        max_threads = self.get('analysis.max_threads')
        if max_threads is not None:
            if not isinstance(max_threads, int) or max_threads < 1:
                errors.append(f"analysis.max_threads must be >= 1, got {max_threads!r}")

        # -- api.port --
        port = self.get('api.port')
        if not isinstance(port, int) or port < 1 or port > 65535:
            errors.append(f"api.port must be int in 1-65535, got {port!r}")

        # -- api.workers --
        workers = self.get('api.workers')
        if workers is not None:
            if not isinstance(workers, int) or workers < 1:
                errors.append(f"api.workers must be >= 1, got {workers!r}")

        # -- logging.level --
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        level = self.get('logging.level', 'INFO')
        if isinstance(level, str) and level.upper() not in valid_levels:
            errors.append(f"logging.level must be one of {valid_levels}, got {level!r}")

        # -- symbolic_execution section (B53) --
        solver_timeout = self.get('symbolic_execution.solver_timeout_ms')
        if solver_timeout is not None:
            if not isinstance(solver_timeout, int) or solver_timeout < 100:
                errors.append(
                    f"symbolic_execution.solver_timeout_ms must be >= 100, got {solver_timeout!r}"
                )

        max_paths = self.get('symbolic_execution.max_paths')
        if max_paths is not None:
            if not isinstance(max_paths, int) or max_paths < 1:
                errors.append(f"symbolic_execution.max_paths must be >= 1, got {max_paths!r}")

        max_depth = self.get('symbolic_execution.max_depth')
        if max_depth is not None:
            if not isinstance(max_depth, int) or max_depth < 1:
                errors.append(f"symbolic_execution.max_depth must be >= 1, got {max_depth!r}")

        mem_limit = self.get('symbolic_execution.memory_limit_mb')
        if mem_limit is not None:
            if not isinstance(mem_limit, int) or mem_limit < 64:
                errors.append(
                    f"symbolic_execution.memory_limit_mb must be >= 64, got {mem_limit!r}"
                )

        # -- vmprotect.validation_threshold --
        vt = self.get('vmprotect.validation_threshold')
        if vt is not None:
            if not isinstance(vt, (int, float)) or not (0.0 <= vt <= 1.0):
                errors.append(
                    f"vmprotect.validation_threshold must be in [0,1], got {vt!r}"
                )

        # Raise first error for backwards compat (single-error contract)
        if errors:
            raise ValidationError(
                errors[0],
                field=errors[0].split(" ")[0],
                constraint="range/type check",
                details={"all_errors": errors},
            )
    
    def __repr__(self) -> str:
        return f"Config(environment='{self.environment}', config_dir='{self.config_dir}')"


# Global configuration instance
_config_instance: Optional[Config] = None
_config_lock = threading.Lock()


def get_config(environment: Optional[str] = None) -> Config:
    """
    Get global configuration instance.

    """
    global _config_instance

    if _config_instance is not None:
        return _config_instance

    with _config_lock:
        # Double-check after acquiring lock
        if _config_instance is None:
            env = environment or os.environ.get('VMDS_ENVIRONMENT', 'development')
            _config_instance = Config(environment=env)

    return _config_instance


def reset_config():
    global _config_instance
    with _config_lock:
        _config_instance = None
