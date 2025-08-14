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

- VM Discovery only
	- Input → `VMDetector.detect_vm_structures[_async]` → VM presence, type, handlers, regions → Aggregation → Output.

- Pattern Analysis pipeline
	- Input → Feature extraction → `PatternRecognizer.recognize_patterns` (async) → Matches + classification → Aggregation → Output.

- Hybrid (discovery → taint → symbolic)
	- Input → VM Discovery → Identify handler entry points → `TaintTracker` for data-flow to sensitive sinks → `SymbolicExecutor` for path feasibility → Aggregation → Output.

## Files involved

- `dragonslayer/core/orchestrator.py` — Orchestrator, `AnalysisType`, request/result models, async execution.
- `dragonslayer/analysis/vm_discovery/detector.py` — VM detection primitives.
- `dragonslayer/analysis/pattern_analysis/recognizer.py` — Pattern recognition.
- `dragonslayer/analysis/taint_tracking/tracker.py` — Taint propagation.
- `dragonslayer/analysis/symbolic_execution/executor.py` — Symbolic execution.
- `dragonslayer/workflows/` — Higher-level workflow helpers (`integration.py`, `manager.py`, `pipeline.py`).

## Result Contract

All workflows should conform to `data/schemas/analysis_result_schema.json`. Use `tools/schema_validate.py` during development to catch mismatches.

## Extending Workflows

- Add a new engine: implement a focused module under `dragonslayer/analysis/<engine>/`, export a clear async/sync API, and wire it in the orchestrator’s strategy selection.
- Compose pipelines: add a coordinator in `dragonslayer/workflows/` that sequences engines and normalizes their partial outputs.
- Record provenance: persist intermediate artifacts, and register new models in the model registry when introducing learned components.
