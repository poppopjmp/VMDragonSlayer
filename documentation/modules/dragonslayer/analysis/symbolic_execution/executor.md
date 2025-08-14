# dragonslayer.analysis.symbolic_execution.executor

Path: `dragonslayer/analysis/symbolic_execution/executor.py`

## Purpose
Symbolic execution engine with prioritization, constraints, and path exploration.

## Public API
- Enums: `ConstraintType`, `PathPriority`, `ExecutionState`
- Dataclasses: `SymbolicConstraint`, `SymbolicValue`, `ExecutionContext`, `ExecutionResult`
- Class `SymbolicExecutor(config: VMDragonSlayerConfig | None)`
  - `execute(initial_context: ExecutionContext, instruction_handler: callable | None=None) -> ExecutionResult` (async)

## Example
```python
import asyncio
from dragonslayer.analysis.symbolic_execution.executor import (
    SymbolicExecutor, ExecutionContext, SymbolicValue
)

async def run():
    ctx = ExecutionContext(pc=0, registers={"eax": SymbolicValue("eax", is_input=True)})
    ex = SymbolicExecutor()
    result = await ex.execute(ctx)
    print(result.total_paths, result.execution_time)

asyncio.run(run())
```

## Related
- Back to [Modules](../../../../03-modules.md)
