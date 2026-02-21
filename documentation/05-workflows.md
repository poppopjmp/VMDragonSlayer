# Workflows

End-to-end flows describe how inputs travel through the orchestrator, analysis engines, and back to API clients. This page outlines the canonical sequences and where to extend or customize them.

## High-level Orchestration

1) Client submits an analysis request (file path or bytes, plus `analysis_type`).
2) `dragonslayer.core.orchestrator.Orchestrator` validates the request, loads configuration, and selects a `WorkflowStrategy`.
3) The orchestrator dispatches to one or more engines (`vm_discovery`, `pattern_analysis`, `taint_tracking`, `symbolic_execution`).
4) Engine(s) emit partial results and metrics; orchestrator aggregates into an `AnalysisResult`.
5) Results are validated (optionally against `analysis_result_schema.json`) and returned or persisted.

See: `documentation/modules/dragonslayer/core/orchestrator.md` for API and types.

## Typical Sequences

### VM Discovery only
- Input → `VMDetector.detect_vm_structures[_async]` → VM presence, type, handlers, regions → Aggregation → Output.

### Pattern Analysis pipeline
- Input → Feature extraction → `PatternRecognizer.recognize_patterns` (async) → Matches + classification → Aggregation → Output.

### Hybrid (discovery → taint → symbolic)
- Input → VM Discovery → Identify handler entry points → `TaintTracker` for data-flow to sensitive sinks → `SymbolicExecutor` for path feasibility → Aggregation → Output.

## Multi-Protector Devirtualisation

The system supports devirtualisation of VMProtect, Themida, and Code Virtualizer VMs:

1. **Detection** — `VMDetector` identifies the protector type from binary signatures, section names, and watermarks.
2. **Dispatcher Recovery** — `DispatcherAnalyzer` locates the dispatch loop and handler table. Each protector has a distinct dispatcher shape:
   - VMProtect: indirect jump via handler table indexed by fetched opcode
   - Themida: EDI-based context structure, ESI as vIP, pushad/popad frames
   - Code Virtualizer: LODSB+XLAT fetch-decrypt cycle, ESP-based context
3. **Handler Extraction** — Handlers are identified via boundary analysis and bytecode correlation.
4. **Bytecode Decoding** — Protector-specific decoders (`ThemidaBytecodeDecoder`, `CVBytecodeDecoder`) parse the bytecode stream.
5. **Devirtualisation** — `devirtualize_themida()` / `devirtualize_cv()` / pipeline `devirtualize` stage produces native-equivalent pseudocode.

## Trace Collection & Export

### Collecting a Trace

```python
from dragonslayer.analysis.trace_collector import collect_trace, TraceConfig

config = TraceConfig(arch="x86_64", max_instructions=50000)
result = collect_trace(binary_data, config=config)
# result.trace is an ExecutionTrace
```

The collector auto-selects a backend (Unicorn built-in, or Triton/angr/Qiling if available). Traces can also be imported from files or plugin output.

### Exporting to RE Tools

```python
from dragonslayer.analysis.trace_export import export_trace, OutputFormat

export_trace(result.trace, "out.ida.json", format=OutputFormat.IDA)    # IDA annotation JSON
export_trace(result.trace, "out.ghidra.py", format=OutputFormat.GHIDRA) # Ghidra Jython script
export_trace(result.trace, "out.json", format=OutputFormat.JSON)        # Full-fidelity JSON
```

### CLI Export

```bash
vmdragonslayer export sample.exe -f ida -o sample.ida.json
vmdragonslayer export sample.exe -f ghidra -o sample.ghidra.py
vmdragonslayer export sample.exe -f csv -o sample.csv
```

### RE Tool Plugin Loading

- **IDA Pro**: Copy `plugins/idapro/dragonslayer_ida.py` to `<IDA>/plugins/`. Run via `Edit → Plugins → DragonSlayer` or `Ctrl+Shift+D`.
- **Ghidra**: Copy `plugins/ghidra/dragonslayer_ghidra.py` to `~/.ghidra/<version>/scripts/`. Run via Script Manager.
- **Binary Ninja**: Copy `plugins/binaryninja/` to `~/.binaryninja/plugins/dragonslayer/`. Use `Plugins → DragonSlayer` menu.

All three plugins accept pre-exported annotation JSON or can run live analysis from within the RE tool.

## ML Training Workflow

1. Generate synthetic training data across all supported protectors:
   ```python
   from dragonslayer.ml.trainer import generate_multi_protector_data, train_and_save_model
   data = generate_multi_protector_data(samples_per_category=20)
   report = train_and_save_model(data, model_path="handler_model.pkl")
   ```
2. The trainer applies jitter transforms (NOP insertion, register renaming, dead-code injection) to create realistic handler variation.
3. GradientBoosting or RandomForest classifiers trained on 132-feature vectors achieve >98% accuracy on synthetic data.
4. Trained models are loaded by the orchestrator at runtime for handler classification.

## Files involved

- `dragonslayer/core/orchestrator.py` — Top-level analysis dispatch
- `dragonslayer/core/pipeline.py` — Multi-stage pipeline with per-stage timeouts
- `dragonslayer/analysis/handler_semantics.py` — Handler classification (13 VM operations)
- `dragonslayer/analysis/pseudocode.py` — Pseudocode emission
- `dragonslayer/analysis/mba_simplifier.py` — MBA expression simplification
- `dragonslayer/analysis/dataflow.py` — Cross-handler data-flow analysis
- `dragonslayer/analysis/themida_devirt.py` — Themida devirtualisation pipeline
- `dragonslayer/analysis/cv_devirt.py` — Code Virtualizer devirtualisation pipeline
- `dragonslayer/analysis/trace_collector.py` — Trace collection facade
- `dragonslayer/analysis/trace_export.py` — Multi-format trace export
- `dragonslayer/ml/trainer.py` — ML training with multi-protector synthetic data
- `dragonslayer/plugins/__init__.py` — Plugin ABC and `PluginContext`

## Extending Workflows

Add a new engine: implement a module under `dragonslayer/analysis/<engine>/`,
export a clear sync API, and wire it into the pipeline's stage registry.

Add a new protector: create `<protector>_devirt.py` following the pattern in
`themida_devirt.py` — define a bytecode decoder, handler extractor, and
top-level `devirtualize_<protector>()` function.

Add a new export format: use the `@_register_format` decorator in
`trace_export.py` to register a new renderer for `OutputFormat`.