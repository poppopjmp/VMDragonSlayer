# dragonslayer.core

Purpose: Core framework components including configuration, orchestrator, API facade, and exceptions.

## Public Modules
- `api.py` — VMDragonSlayerAPI facade around the orchestrator
- `orchestrator.py` — Orchestrates analysis workflows and components
- `config.py` — Typed configuration with env and file loading
- `exceptions.py` — System error hierarchy and helpers

## Quick Usage
```python
from dragonslayer.core.api import VMDragonSlayerAPI

api = VMDragonSlayerAPI()
print(api.get_supported_analysis_types())
res = api.analyze_file("sample.exe", analysis_type="hybrid")
print(res.get("success"), res.get("results"))
```

## Related
- Source: `dragonslayer/core/`
- See [Modules](../../../03-modules.md)
