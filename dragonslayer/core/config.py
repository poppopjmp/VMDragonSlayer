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
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            'console': False,
        },
        'analysis': {
            'timeout': 1800,
            'max_threads': 4,
            'enable_caching': False,
        },
        'tracing': {
            'backend': 'auto',
            'timeout': 300,
            'max_instructions': 100000,
            'capture_registers': True,
            'capture_memory': True,
            'trace_output_dir': 'traces/',
            'unicorn': {'follow_calls': True},
            'triton': {'symbolic': True, 'taint': True},
            'angr': {'auto_load_libs': False},
            'qiling': {'rootfs': '', 'multithread': False},
        },
        'api': {
            'host': '127.0.0.1',
            'port': 8000,
            'workers': 4,
            'enable_cors': False,
            'debug': False,
        },
        'vmprotect': {
            'trace_depth': 100000,
            'enable_symbolic': True,
            'llvm_opt_level': 'O3',
            'skip_optimization': False,
            'validation_threshold': 0.85,
            'confidence_threshold': 0.8,
            'max_handler_size': 10000,
        },
        'dispatcher': {
            'max_trace_length': 500000,
            'early_exit_confidence': 0.9,
        },
        'symbolic_execution': {
            'solver_timeout_ms': 10000,
            'max_paths': 64,
            'max_depth': 1000,
            'max_loop_iters': 3,
            'memory_limit_mb': 2048,
        },
        'data': {
            'patterns_db': 'data/patterns/vmprotect_handlers.json',
            'models_dir': 'data/models/',
            'samples_dir': 'data/samples/',
            'schemas_dir': 'data/schemas/',
        },
        'paths': {
            'workspace_root': '.',
            'logs_dir': 'logs/',
            'temp_dir': 'temp/',
            'output_dir': 'output/',
        },
    }
    
    def __init__(
        self,
        config_dir: Optional[Path] = None,
        environment: str = 'development',
        *,
        validate_on_load: bool = True,
    ):

        self.environment = environment
        self.config_dir = config_dir or self._find_config_dir()
        self._config: Dict[str, Any] = {}
        # B64: Thread-safe access to _config for concurrent API requests
        self._lock = threading.RLock()
        
        # Load configuration in order of precedence
        self._load_defaults()
        self._load_yaml_config()
        self._load_env_variables()

        # B57: Auto-validate after loading — catches misconfigurations early.
        if validate_on_load:
            try:
                self.validate()
            except ValidationError as exc:
                logger.error("Configuration validation failed: %s", exc)
                raise
        
        logger.info("Configuration loaded for environment: %s", environment)
    
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
    
    def _load_defaults(self) -> None:
        """Load default configuration values (deep copy so mutations are isolated)."""
        self._config = copy.deepcopy(self.DEFAULTS)
    
    def _load_yaml_config(self) -> None:
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
                            logger.info("Loaded config from %s", config_file)
                            return
                except (OSError, yaml.YAMLError, ValueError, TypeError, KeyError) as e:
                    logger.warning("Failed to load config from %s: %s", config_file, e)

        logger.warning(
            "No config file found (tried %s), using defaults",
            ", ".join(str(c) for c in candidates),
        )
    
    def _load_env_variables(self) -> None:
        """Load configuration from environment variables.

        Supports both legacy hardcoded keys and the B64 generic convention:
        ``VMDS_<SECTION>__<KEY>=value`` where ``__`` maps to ``.`` in the
        config hierarchy.  For example ``VMDS_SYMBOLIC_EXECUTION__MAX_PATHS=128``
        sets ``symbolic_execution.max_paths`` to ``128``.  Integer and float
        values are auto-parsed; everything else stays as a string.
        """
        # Legacy hardcoded overrides (kept for backwards compat)
        if 'VMDS_LOGGING_LEVEL' in os.environ:
            self._config['logging']['level'] = os.environ['VMDS_LOGGING_LEVEL']
        

        if 'VMDS_ANALYSIS_TIMEOUT' in os.environ:
            try:
                self._config['analysis']['timeout'] = int(os.environ['VMDS_ANALYSIS_TIMEOUT'])
            except ValueError:
                logger.warning("Invalid VMDS_ANALYSIS_TIMEOUT value")
        
        if 'VMDS_TRACING_BACKEND' in os.environ:
            self._config['tracing']['backend'] = os.environ['VMDS_TRACING_BACKEND']
        
        if 'VMDS_API_HOST' in os.environ:
            self._config['api']['host'] = os.environ['VMDS_API_HOST']
        
        if 'VMDS_API_PORT' in os.environ:
            try:
                self._config['api']['port'] = int(os.environ['VMDS_API_PORT'])
            except ValueError:
                logger.warning("Invalid VMDS_API_PORT value")

        # B64: Generic VMDS_ prefix convention
        for env_key, env_val in os.environ.items():
            if not env_key.startswith("VMDS_") or "__" not in env_key:
                continue
            # Strip prefix and convert VMDS_SECTION__KEY → section.key
            path = env_key[5:].lower().replace("__", ".")
            # Auto-parse numeric and boolean values
            parsed: Any = env_val
            if env_val.lower() in ("true", "yes", "1", "on"):
                parsed = True
            elif env_val.lower() in ("false", "no", "0", "off"):
                parsed = False
            else:
                try:
                    parsed = int(env_val)
                except ValueError:
                    try:
                        parsed = float(env_val)
                    except ValueError:
                        pass
            self.set(path, parsed)
    
    def _merge_config(self, new_config: Dict[str, Any]) -> None:
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
        """Retrieve a configuration value by dotted key path."""
        keys = key.split('.')
        with self._lock:
            value = self._config

            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default

            return value
    
    def set(self, key: str, value: Any) -> None:
        """Set a configuration value by dotted key path."""
        keys = key.split('.')
        with self._lock:
            config = self._config

            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]

            config[keys[-1]] = value
    
    def get_section(self, section: str) -> Dict[str, Any]:
        # B66: return deep-copy so callers can't mutate internal state
        with self._lock:
            return copy.deepcopy(self._config.get(section, {}))
    
    def validate(self) -> None:
        """Validate configuration values (B53 — comprehensive).

        Checks types, ranges, and consistency for all known sections.
        Raises :class:`ValidationError` on the first invalid field
        or :class:`ConfigurationError` for legacy compat.
        Warns on unrecognised top-level keys.
        """
        errors: list[str] = []

        # --- Known top-level sections ---
        known_sections = set(self.DEFAULTS.keys()) | {
            "metroplex",
            # Legacy — kept for backward compat if users still have pin: in YAML
            "pin",
        }
        for key in self._config:
            if key not in known_sections:
                logger.warning("Unknown config section '%s' — typo?", key)

        # -- tracing.backend --
        valid_backends = {"auto", "unicorn", "triton", "angr", "qiling", "file"}
        trace_backend = self.get('tracing.backend', 'auto')
        if isinstance(trace_backend, str) and trace_backend.lower() not in valid_backends:
            errors.append(
                f"tracing.backend must be one of {valid_backends}, got {trace_backend!r}"
            )

        # -- tracing.timeout --
        trace_timeout = self.get('tracing.timeout')
        if trace_timeout is not None:
            if not isinstance(trace_timeout, int) or trace_timeout <= 0:
                errors.append(
                    f"tracing.timeout must be a positive int, got {trace_timeout!r}"
                )

        # -- tracing.max_instructions --
        max_instr = self.get('tracing.max_instructions')
        if max_instr is not None:
            if not isinstance(max_instr, int) or max_instr < 1:
                errors.append(
                    f"tracing.max_instructions must be >= 1, got {max_instr!r}"
                )

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

        # -- dispatcher settings --
        dtrace = self.get('dispatcher.max_trace_length')
        if dtrace is not None:
            if not isinstance(dtrace, int) or dtrace < 1:
                errors.append(
                    f"dispatcher.max_trace_length must be >= 1, got {dtrace!r}"
                )
        dexit = self.get('dispatcher.early_exit_confidence')
        if dexit is not None:
            if not isinstance(dexit, (int, float)) or not (0.0 <= dexit <= 1.0):
                errors.append(
                    f"dispatcher.early_exit_confidence must be in [0,1], got {dexit!r}"
                )

        # Raise with ALL errors summarised
        if errors:
            summary = "; ".join(errors)
            raise ValidationError(
                f"{len(errors)} config error(s): {summary}",
                field=errors[0].split(" ")[0],
                constraint="range/type check",
                details={"all_errors": errors},
            )

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Return a deep-copy of the active configuration dict."""
        with self._lock:
            return copy.deepcopy(self._config)
    
    def __repr__(self) -> str:
        return f"Config(environment='{self.environment}', config_dir='{self.config_dir}')"


# Global configuration instance
_config_instance: Optional[Config] = None
_config_lock = threading.Lock()


def get_config(environment: Optional[str] = None) -> Config:
    """
    Get global configuration instance.

    Warns if *environment* differs from the already-created singleton.
    """
    global _config_instance

    if _config_instance is not None:
        if (
            environment is not None
            and environment != _config_instance.environment
        ):
            import warnings
            warnings.warn(
                f"get_config(environment={environment!r}) called but "
                f"singleton already created with "
                f"environment={_config_instance.environment!r}. "
                f"Returning existing instance.  Call reset_config() first "
                f"to change environments.",
                stacklevel=2,
            )
        return _config_instance

    with _config_lock:
        # Double-check after acquiring lock
        if _config_instance is None:
            env = environment or os.environ.get('VMDS_ENVIRONMENT', 'development')
            _config_instance = Config(environment=env)

    return _config_instance


def reset_config() -> None:
    """Reset the global configuration singleton to *None*."""
    global _config_instance
    with _config_lock:
        _config_instance = None
