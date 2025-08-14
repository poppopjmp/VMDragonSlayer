# dragonslayer.analysis.taint_tracking.tracker

Path: `dragonslayer/analysis/taint_tracking/tracker.py`

## Purpose
Dynamic taint tracking engine for VM analysis: taint sources/types, propagation, events, and statistics.

## Public API
- Enums: `TaintType`, `TaintScope`, `OperationType`
- Dataclasses: `TaintInfo`, `TaintEvent`, `TaintPropagation`
- Class `TaintTracker(config: VMDragonSlayerConfig | None)`
  - `mark_tainted(address: int, taint_info: TaintInfo | None=None) -> TaintInfo`
  - `is_tainted(address: int) -> bool`, `get_taint_info(address: int) -> TaintInfo | None`, `clear_taint(address: int) -> None`
  - `propagate_taint(source_addr: int, target_addr: int, operation: OperationType, operation_specific_data: dict | None=None) -> TaintInfo | None`
  - `propagate_rotate_carry(taint_info: TaintInfo, carry_flag_tainted: bool, operation_type: str = "rotate") -> TaintInfo`
  - Register helpers: `set_register_taint`, `get_register_taint`, `is_register_tainted`
  - Stats and export: `get_statistics() -> dict`, `get_taint_summary() -> dict`, `find_propagation_chains() -> list`, `export_events() -> list`, `clear_all() -> None`

## Example
```python
from dragonslayer.analysis.taint_tracking.tracker import TaintTracker, TaintInfo, TaintType, OperationType

tracker = TaintTracker()
info = tracker.mark_tainted(0x401000, TaintInfo(vector=1, labels={"input"}, source_type=TaintType.INPUT))
tracker.propagate_taint(0x401000, 0x401004, OperationType.COPY)
print(tracker.is_tainted(0x401004))
```

## Related
- Back to [Modules](../../../../03-modules.md)
