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

- `dragonslayer/core/orchestrator.py` — Top-level analysis dispatch
- `dragonslayer/core/pipeline.py` — Multi-stage pipeline with per-stage timeouts
- `dragonslayer/analysis/handler_semantics.py` — Handler classification (13 VM operations)
- `dragonslayer/analysis/pseudocode.py` — Pseudocode emission
- `dragonslayer/analysis/mba_simplifier.py` — MBA expression simplification
- `dragonslayer/analysis/dataflow.py` — Cross-handler data-flow analysis
- `dragonslayer/plugins/__init__.py` — Plugin ABC and `PluginContext`

## Extending Workflows

Add a new engine: implement a module under dragonslayer/analysis/<engine>/,
export a clear sync API, and wire it into the pipeline's stage registry.
