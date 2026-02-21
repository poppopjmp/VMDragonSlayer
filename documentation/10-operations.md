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

## Dispatcher Configuration (B102)

The dispatcher finder system reads tuning knobs from the `dispatcher:` section
of `config/vmdragonslayer.yml`.  Both values have safe defaults and are clamped
to valid ranges.

```yaml
dispatcher:
  max_trace_length: 500000     # Max trace records before subsampling
  early_exit_confidence: 0.9   # Skip remaining finders above this threshold
```

| Key | Type | Default | Range | Effect |
|-----|------|---------|-------|--------|
| `max_trace_length` | int | `500000` | `1 – 10,000,000` | Traces longer than this are uniformly sub-sampled to this size before analysis.  Lower values trade coverage for speed; higher values improve accuracy on very long traces but increase memory and CPU cost. |
| `early_exit_confidence` | float | `0.9` | `0.01 – 1.0` | When any dispatcher finder reports confidence ≥ this threshold, remaining finders are skipped.  Set to `1.0` to always run all finders. |

**Operational notes:**

- Sub-sampling emits an `INFO` log on the first occurrence per process, then
  `DEBUG` on subsequent triggers, to avoid log flooding in batch pipelines.
- Early-exit successes are logged at `INFO` level with the protector name and
  confidence score.
- Out-of-range config values are clamped with a `WARNING` log explaining the
  adjustment.

## Troubleshooting

- Check `/health` and `/status` for quick diagnostics; inspect `/metrics` for counters and active connections.
- Common import errors often stem from optional extras; consult `pyproject.toml` optional-dependencies.
