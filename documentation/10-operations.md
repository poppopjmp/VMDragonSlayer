# Operations & Performance

Operational notes for running the API, enabling GPU acceleration, and measuring performance.

## Running the API

Programmatic start:

```python
from dragonslayer.api.server import run_server

run_server(host="0.0.0.0", port=8000, workers=1)
```

Module entry:

```pwsh
python -m dragonslayer.api.server
```

Recommendations:
- Place the server behind a reverse proxy (nginx) for TLS/headers.
- Tune `workers` based on CPU and workload characteristics; orchestrator is async but CPU-bound engines may benefit from more processes.
- Configure CORS and auth via `core.config.get_api_config()` settings.

## GPU acceleration

Install GPU extras to enable optional acceleration in modules that support it:

- Extras group: `gpu` (see `pyproject.toml`) — e.g., CuPy (`cupy-cuda12x`) and `pynvml`.
- Ensure CUDA drivers/libraries match the CuPy build.

Runtime checks should gracefully degrade to CPU when GPU libs are unavailable.

## Performance testing

- Use `pytest -m performance` (or a dedicated directory) for micro/meso benchmarks.
- Profile hot paths in analysis engines (vm discovery, pattern recognition) and cache stable intermediate results.
- Track latency and resource metrics via `/metrics` and augment with external monitoring.

## Determinism & reproducibility

- Keep `PYTHONHASHSEED` fixed in CI when comparing outputs.
- Use `tools/determinism_runner.py` to verify identical outputs across repeated runs.

## Troubleshooting

- Check `/health` and `/status` for quick diagnostics; inspect `/metrics` for counters and active connections.
- Common import errors often stem from optional extras; consult `pyproject.toml` optional-dependencies.
