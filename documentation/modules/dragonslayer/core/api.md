# dragonslayer.core.api

Path: `dragonslayer/core/api.py`

## Purpose
Unified facade for VMDragonSlayer capabilities: file/bytes analysis, configuration, workflow control, and status/metrics.

## Public API
- Class `VMDragonSlayerAPI`
  - `analyze_file(file_path: str, analysis_type: str = "hybrid", **options) -> dict`
  - `analyze_binary_data(binary_data: bytes, analysis_type: str = "hybrid", metadata: dict|None=None, **options) -> dict`
  - `analyze_binary_data_async(...) -> AnalysisResult`
  - `detect_vm_structures(file_path: str) -> dict`
  - `analyze_patterns(file_path: str) -> dict`
  - `track_taint(file_path: str, **options) -> dict`
  - `execute_symbolically(file_path: str, **options) -> dict`
  - `get_status() -> dict`, `get_metrics() -> dict`, `configure(**kwargs) -> None`
  - `get_supported_analysis_types() -> List[str]`, `get_supported_workflow_strategies() -> List[str]`
  - `validate_binary(file_path: str) -> dict`
- Module helpers: `get_api`, `analyze_file`, `analyze_binary_data`, `get_status`

## Usage Examples
```python
from dragonslayer.core.api import VMDragonSlayerAPI
api = VMDragonSlayerAPI()
res = api.analyze_file("sample.exe", analysis_type="vm_discovery")
print(res["success"], res.get("results", {}))
```

Async:
```python
import asyncio
from dragonslayer.core.api import VMDragonSlayerAPI

async def main():
    api = VMDragonSlayerAPI()
    with open("sample.exe", "rb") as f:
        data = f.read()
    result = await api.analyze_binary_data_async(data, analysis_type="hybrid")
    print(result.request_id, result.success)
asyncio.run(main())
```

## Implementation Notes
- Delegates to `dragonslayer.core.orchestrator.Orchestrator`.
- Validates inputs via `dragonslayer.core.exceptions` helpers and raises `AnalysisError` / `InvalidDataError`.

## Related
- Orchestrator: `dragonslayer/core/orchestrator.py`
- Back to [Modules](../../../03-modules.md)
