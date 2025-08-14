# dragonslayer.core.orchestrator

Path: `dragonslayer/core/orchestrator.py`

## Purpose
Coordinates analysis components with strategies, metrics, and async execution. Provides `AnalysisRequest`, `AnalysisResult`, `AnalysisType`, and `WorkflowStrategy`.

## Public API
- Class `Orchestrator`
  - `analyze_binary(binary_path: str, analysis_type: str = "hybrid", **options) -> dict`
  - `execute_analysis(request: AnalysisRequest) -> AnalysisResult` (async)
  - `get_status() -> dict`, `configure(**kwargs) -> None`, `shutdown() -> None` (async)
- Enums: `AnalysisType`, `WorkflowStrategy`
- Dataclasses: `AnalysisRequest`, `AnalysisResult`

## Usage Example
```python
from dragonslayer.core.orchestrator import Orchestrator, AnalysisRequest, AnalysisType
import asyncio

async def main():
    o = Orchestrator()
    req = AnalysisRequest(b"\x90\x90\x90", analysis_type=AnalysisType.HYBRID)
    res = await o.execute_analysis(req)
    print(res.success, res.results)
asyncio.run(main())
```

## Implementation Notes
- Lazy-loads components from `dragonslayer.analysis.*` packages.
- Tracks metrics (execution time, memory, CPU when psutil is available).

## Related
- API facade: `dragonslayer/core/api.py`
- Back to [Modules](../../../03-modules.md)
