# dragonslayer.analysis.vm_discovery.detector

Path: `dragonslayer/analysis/vm_discovery/detector.py`

## Purpose
Unified VM detector combining pattern, structure, handler, and dispatcher analysis.

## Public API
- Enums: `VMType`, `HandlerType`
- Dataclasses: `VMHandler`, `VMStructure`
- Class `VMDetector(config: dict | None=None)`
  - `detect_vm_structures(binary_data: bytes) -> dict`
  - `detect_vm_structures_async(binary_data: bytes) -> dict` (async)
  - Convenience: `analyze_binary(binary_data: bytes) -> dict`, `extract_handlers(binary_data: bytes) -> list`, `classify_instructions(binary_data: bytes) -> dict`
  - Ops: `get_statistics() -> dict`, `clear_cache() -> None`, `cleanup() -> None` (async)

## Example
```python
from dragonslayer.analysis.vm_discovery.detector import VMDetector

with open("sample.exe", "rb") as f:
    data = f.read()

vm = VMDetector()
result = vm.detect_vm_structures(data)
print(result["vm_detected"], result.get("confidence"))
```

## Related
- Back to [Modules](../../../../03-modules.md)
