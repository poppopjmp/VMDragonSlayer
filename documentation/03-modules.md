# Modules

Index of primary packages and key modules. Paths link to source and docs where available.

> **Note**: This listing reflects modules that actually exist in the codebase as of Phase 6 (dev-0.9.1).

## Core System

- **core**
	- `dragonslayer/core/api.py` — Unified facade for analysis and configuration
	- `dragonslayer/core/orchestrator.py` — Coordinates analysis workflows; temp-dir cleanup via try/finally; `shutdown()` method
	- `dragonslayer/core/config.py` — Typed configuration with recursive `_deep_merge`, thread-safe `get_config()` singleton
	- `dragonslayer/core/exceptions.py` — Error hierarchy and validators (`from __future__ import annotations` for 3.14 compat)
	- `dragonslayer/core/pipeline.py` — Multi-stage analysis pipeline; wires `avg_confidence` into result_data

- **api**
	- `dragonslayer/api/server.py` — FastAPI server with lifespan context manager, async rate limiter (`asyncio.Lock`), CORS fix
	- `dragonslayer/api/client.py` — HTTP client for interacting with the server
	- `dragonslayer/api/endpoints.py` — API endpoint definitions

## Analysis Engine

- **analysis**
	- `vm_discovery/` — VMDetector and structural detection
		- `detector.py` — Section entropy with correct slice, PE/ELF section parsing
		- `analyzer.py` — VM topology analysis
		- `database.py` — Signature database (`import re` at module level)
		- `dispatcher.py` — `DispatcherAnalyzer` with jump-table scanning, 64-bit `entry_size` support
	- `pattern_analysis/` — PatternRecognizer and pattern detection
		- `recognizer.py` — Core pattern recognition; offset fix, UnboundLocalError fix, `re.escape()` safety
		- `classifier.py` — ML-enhanced pattern classification
		- `database.py` — Pattern database management
	- `taint_tracking/` — Dynamic taint analysis engine
		- `tracker.py` — Register + memory taint propagation; `reset()`, public `process_instruction()`, `reg_taint`/`mem_taint` properties
		- `analyzer.py` — TaintAnalyzer orchestration (calls `reset()` before each run)
		- `dtt_executor.py` — DTT execution driver
		- `vm_taint_tracker.py` — VM-aware tracker with virtual register presets (vmprotect_x64/x86, themida_x64)
	- `symbolic_execution/` — Symbolic execution and path exploration
		- `executor.py` — Core symbolic executor; test vs cmp distinction, LEA `_resolve_effective_address()`, deque worklist
		- `lifter.py` — Binary lifting; int3→SYSTEM, mov MEMORY_WRITE
		- `solver.py` — z3 constraint solving; `_constraint_stack` push/pop sync
		- `state.py` — Symbolic state; `_last_cmp` attribute, fork propagation, `read_memory` size from `bit_width`
	- `anti_evasion/` — Anti-analysis countermeasures
		- `environment_normalizer.py` — Section-aware scanning; per-pattern confidence (`_ANTI_DISASM_CONFIDENCE`), int3 non-patchable

## Machine Learning

- **ml**
	- `classifier.py` — `VMClassifier` high-level entry point
	- `model.py` — Abstract `BaseModel` / `VMHandlerModel` with `train()`/`predict()`/`save()`/`load()` contract
	- `trainer.py` — `ModelTrainer` with metric collection, `TrainingResult`, `prepare_training_data()`
	- `pipeline.py` — `FeatureExtractor` (configurable feature_spec), `FeatureVector` dataclass
	- `ensemble.py` — `EnsembleClassifier` (majority vote), `WeightedEnsemble` (weighted strategy)

## GPU Acceleration

- **gpu**
	- `__init__.py` — `gpu_available()` with guarded torch/CUDA imports
	- `engine.py` — `GPUEngine` device management and data transfer interface
	- `memory.py` — `GPUMemoryManager` allocation tracking
	- `optimizer.py` — `GPUOptimizer` block-size recommendation
	- `profiler.py` — `GPUProfiler` wall-clock timing (works without GPU hardware)

## LLM Integration

- **llm**
	- `analyzer.py` — LLM-assisted analysis via litellm; regex JSON fence stripping, `reset_llm_analyzer()` singleton reset

## Plugin Ecosystem

- **plugins**
	- `__init__.py` — `PluginRegistry` with duplicate warnings, auto-discovery, thread-safe `PluginContext`
	- `_storage.py` — `MemoryBackend` (with `threading.Lock`), `LocalFileBackend` (batch flush in `store_bulk`)
	- `dynamic/` — angr (`simgr.move()` pattern), triton (tainted_write filter), binexport, qiling
	- `enrichment/` — similarity (ssdeep pre-computed hashes, pefile close), llm, vt, yara
	- `static/` — capstone, pefile, strings, yara
	- `reporting/` — json, markdown, html, sarif

- **enterprise**
	- `enterprise_architecture.py` — Enterprise deployment support
	- `compliance_framework.py` — Compliance and governance
	- `api_integration.py` — Enterprise API integrations

- **utils** — Supporting utilities for memory management, performance monitoring, and platform abstraction

See detailed API shapes in [APIs](./04-apis.md). Each module page links back here.
