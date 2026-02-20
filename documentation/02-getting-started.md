# Getting Started

## Prerequisites

- Python ≥ 3.10
- z3-solver, capstone, unicorn, LIEF, networkx (installed automatically)

## Install

```bash
pip install -e .
```

Optional extras:

```bash
pip install -e ".[ml]"     # scikit-learn, numpy
pip install -e ".[api]"    # FastAPI, uvicorn
pip install -e ".[dev]"    # pytest, ruff, mypy
```

## Quick Start — CLI

```bash
# Check installation
vmdragonslayer info

# Analyse a binary
vmdragonslayer analyze path/to/sample.exe

# Start the API server
vmdragonslayer serve --host 0.0.0.0 --port 8000
```

## Quick Start — Python

```python
from dragonslayer.core import Orchestrator

orch = Orchestrator()
result = orch.analyze("path/to/sample.exe")
print(result)
```

## Quick Start — Devirtualisation Pipeline

```python
from dragonslayer.core.pipeline import Pipeline
from dragonslayer.plugins import PluginContext

ctx = PluginContext(binary_path="sample.exe")
pipeline = Pipeline(stages=["discover", "semantics", "devirtualize"])
result = pipeline.run(ctx)
for handler in result.get("opcode_table", []):
    print(handler)
```

## Configuration

Create `vmdragonslayer.yml` (or use the default in `config/`):

```yaml
analysis:
  timeout: 300
  bit_width: 64
logging:
  level: INFO
```

## Running Tests

```bash
python -m pytest --tb=short -q
```

Current suite: 831 passed, 7 skipped.
