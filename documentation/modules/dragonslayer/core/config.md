# dragonslayer.core.config

Path: `dragonslayer/core/config.py`

## Purpose
Typed configuration management with file (YAML/JSON) loading and environment overrides.

## Public API
- Dataclasses: `VMDragonSlayerConfig`, `MLConfig`, `APIConfig`, `AnalysisConfig`, `InfrastructureConfig`
- Manager: `ConfigManager`
  - `load()`, `save()`, `get_section(name)`, `update_section(name, **kwargs)`, `is_loaded()`
- Helpers: `get_config_manager`, `get_config`, `configure`, `get_ml_config`, `get_api_config`, `get_analysis_config`, `get_infrastructure_config`

## Example
```python
from dragonslayer.core.config import get_config, configure
cfg = get_config()
print(cfg.api.port)
configure(api={"port": 9000})
```

## Related
- Back to [Modules](../../../03-modules.md)
