# dragonslayer.core.exceptions

Path: `dragonslayer/core/exceptions.py`

## Purpose
Centralized exception hierarchy and validation helpers for consistent error handling.

## Public API
- Base: `VMDragonSlayerError(message, error_code=None, details=None, cause=None)` with `.to_dict()`
- Analysis: `AnalysisError`, `BinaryAnalysisError`, `VMDetectionError`, `PatternAnalysisError`, `TaintTrackingError`, `SymbolicExecutionError`
- API/Config/Data/Resource/Network/Workflow families
- Helpers: `handle_exception`, `create_error_response`, validators `validate_not_none`, `validate_not_empty`, `validate_type`, `validate_range`, `validate_choices`

## Example
```python
from dragonslayer.core.exceptions import validate_not_none, AnalysisError

def run(x):
    validate_not_none(x, "x")
    # ...
```

## Related
- Back to [Modules](../../../03-modules.md)
