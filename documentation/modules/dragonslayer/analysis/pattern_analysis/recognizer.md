# dragonslayer.analysis.pattern_analysis.recognizer

Path: `dragonslayer/analysis/pattern_analysis/recognizer.py`

## Purpose
Unified pattern recognition for VM bytecode with semantic patterns, features, and matching.

## Public API
- Class `PatternRecognizer(config: VMDragonSlayerConfig | None)`
  - `add_pattern(pattern: SemanticPattern) -> None`
  - `get_pattern(name: str) -> Optional[SemanticPattern]`
  - `get_patterns_by_category(category: str) -> List[SemanticPattern]`
  - `recognize_patterns(bytecode_sequence: List[int], context: dict|None=None) -> List[PatternMatch]` (async)
  - `clear_cache() -> None`, `get_statistics() -> dict`
- Dataclasses: `SemanticPattern`, `PatternMatch`

## Example
```python
import asyncio
from dragonslayer.analysis.pattern_analysis.recognizer import PatternRecognizer

async def demo():
    rec = PatternRecognizer()
    seq = [0x50, 0x01, 0x50, 0x02, 0x51]  # matches VM_ADD signature
    matches = await rec.recognize_patterns(seq)
    for m in matches:
        print(m.pattern_name, m.confidence)
asyncio.run(demo())
```

## Related
- Back to [Modules](../../../../03-modules.md)
