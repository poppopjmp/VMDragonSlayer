# Modules

Index of primary packages and key modules.

> **Note**: This listing reflects modules that actually exist in the
> codebase as of Phase 11 (dev-0.9.1, 831 tests).

## Core System (`dragonslayer/core/`)

- `api.py` — Unified facade for analysis and configuration
- `orchestrator.py` — Coordinates analysis workflows; temp-dir cleanup; `shutdown()` method
- `config.py` — Typed configuration with recursive `_deep_merge`, thread-safe `get_config()`
- `exceptions.py` — Error hierarchy with structured error codes
- `pipeline.py` — Multi-stage pipeline; per-stage timeouts; `avg_confidence`; `devirtualize` stage

## Analysis Engine (`dragonslayer/analysis/`)

### Top-level analysis modules

- `binary_format.py` — Unified PE / ELF / Mach-O binary parser (LIEF + struct fallback)
- `trace_engine.py` — Built-in Unicorn-based trace engine
- `trace_ingestion.py` — Bridges plugin dicts / text traces into unified `ExecutionTrace`
- `cfg.py` — Instruction-level and handler-level CFG reconstruction (networkx)
- `handler_semantics.py` — Classifies native instructions per handler → 13 VM operations
- `bytecode_extract.py` — Extracts raw VM bytecode by correlating vIP values and memory reads
- `mba_simplifier.py` — MBA expression simplifier: 31 z3-proven rules + linear MBA decomposition + iterative deep simplify
- `pseudocode.py` — Width-qualified SSA and structured C-like pseudocode emission
- `dataflow.py` — Cross-handler data-flow: reaching definitions, dead variables, live ranges, phi nodes

### `vm_discovery/`

- `detector.py` — Heuristic VM presence detection (entropy, section names, watermarks)
- `handler_boundaries.py` — vIP-based handler boundary segmentation
- `dispatcher.py` — Dispatcher loop identification and handler dispatch table recovery
- `analyzer.py` — Higher-level VM topology analysis
- `database.py` — Known VM protector signature database

### `pattern_analysis/`

- `recognizer.py` — Byte-pattern matching against instruction sequences (YARA or regex)
- `classifier.py` — Classifies matched patterns into VM handler categories
- `database.py` — Pattern database storage and querying
- `yara_engine.py` — YARA-based high-performance byte-level matching

### `taint_tracking/`

- `tracker.py` — Register + memory taint propagation with SIB addressing
- `analyzer.py` — TaintAnalyzer orchestration
- `dtt_executor.py` — Dynamic taint tracking combined with symbolic execution
- `vm_taint_tracker.py` — VM-specialised taint tracker with virtual register presets

### `symbolic_execution/`

- `executor.py` — Symbolic executor: drives z3 state through instructions, forks on branches
- `state.py` — Symbolic state: registers (sub-register aliasing), memory (symbolic aliasing), path constraints
- `lifter.py` — Capstone-based lifting of x86/x64 to simplified IR
- `solver.py` — z3 constraint solving for opaque predicates and expression simplification

### `anti_evasion/`

- `environment_normalizer.py` — Anti-debug / anti-analysis detection and neutralisation

## Machine Learning (`dragonslayer/ml/`)

- `pipeline.py` — Feature extraction from analysis artefacts
- `model.py` — `VMHandlerModel` weighted-rule classifier (+ optional scikit-learn)
- `handler_classifier.py` — Bridge connecting ML pipeline to devirtualisation
- `classifier.py` — `VMClassifier` high-level entry point
- `trainer.py` — Training infrastructure with metric collection
- `ensemble.py` — Multi-model combination (majority/weighted vote)

## GPU (`dragonslayer/gpu/`) — stubs

- `engine.py`, `memory.py`, `optimizer.py`, `profiler.py` — Interface stubs for future GPU acceleration

## LLM (`dragonslayer/llm/`)

- `analyzer.py` — LLM-assisted analysis via litellm (OpenAI, Anthropic, Ollama, Azure)

## Plugin Framework (`dragonslayer/plugins/`)

- `__init__.py` — `Plugin` ABC, `PluginRegistry`, `PluginContext`
- `_storage.py` — Storage backends (Memory, LocalFile, Elasticsearch)
- `static/` — PE, ELF, Mach-O, certificate, string extraction plugins
- `dynamic/` — angr, Triton, Qiling, Blackfyre, BinExport, Strelka plugins
- `enrichment/` — Binary similarity, function similarity, VectorShare
- `reporting/` — Markdown report generator, network graph extraction

## API (`dragonslayer/api/`)

- `server.py` — FastAPI REST server (`/analyze`, `/health`, `/status`, WebSocket `/ws`)
- `client.py` — Python HTTP clients (API server + Metroplex gateway)

- **utils** — Supporting utilities for memory management, performance monitoring, and platform abstraction

See detailed API shapes in [APIs](./04-apis.md). Each module page links back here.
