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

- **`dragonslayer/unified_analysis.py`** — Main orchestration layer with feature management
- **`dragonslayer/core/orchestrator.py`** — Core orchestrator with workflow strategies  
- **`dragonslayer/analysis/pattern_analysis/extended_recognizer.py`** — Extended pattern engine
- **`dragonslayer/ml/ml_detection.py`** — ML detection with ensemble methods
- **`dragonslayer/analysis/symbolic_execution/symbolic_engine.py`** — Symbolic execution engine
- **`dragonslayer/analysis/multi_arch/cross_platform_detector.py`** — Multi-architecture support
- **`dragonslayer/analysis/anti_evasion/security_extensions.py`** — Security extensions
- **`dragonslayer/realtime/analysis_engine.py`** — Real-time analysis engine
- **`dragonslayer/workflows/`** — Higher-level workflow coordination

## Enhanced Result Contract

Results now include extended metadata and confidence scoring conforming to `data/schemas/analysis_result_schema.json`. Use `tools/schema_validate.py` during development to catch mismatches.

```json
{
  "analysis_engines": ["extended_patterns", "ml_detection", "symbolic"],
  "confidence_scores": {
    "pattern_analysis": 0.92,
    "ml_detection": 0.87,
    "symbolic_validation": 0.95,
    "overall_confidence": 0.91
  },
  "multi_arch_results": {
    "detected_architectures": ["x86", "x64"],
    "cross_platform_correlation": true
  },
  "security_assessment": {
    "anti_debugging": true,
    "evasion_techniques": ["timing_checks", "environment_detection"],
    "stealth_required": false
  }
}
```

## Extending Workflows

- Add a new engine: implement a focused module under `dragonslayer/analysis/<engine>/`, export a clear async/sync API, and wire it in the orchestrator’s strategy selection.
- Compose pipelines: add a coordinator in `dragonslayer/workflows/` that sequences engines and normalizes their partial outputs.
- Record provenance: persist intermediate artifacts, and register new models in the model registry when introducing learned components.
