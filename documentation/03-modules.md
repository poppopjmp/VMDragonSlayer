# Modules

Index of primary packages and key modules. Paths link to source and docs where available.

- core
	- `dragonslayer/core/api.py` — Unified facade for analysis and configuration
	- `dragonslayer/core/orchestrator.py` — Coordinates analysis workflows and components
	- `dragonslayer/core/config.py` — Typed configuration and env overrides
	- `dragonslayer/core/exceptions.py` — Error hierarchy and validators

- api
	- `dragonslayer/api/server.py` — FastAPI server exposing analysis endpoints
	- `dragonslayer/api/client.py` — HTTP client for interacting with the server

- analysis
	- vm_discovery — VMDetector and structural detection (docs: modules/dragonslayer/analysis/vm_discovery/detector.md)
	- pattern_analysis — PatternRecognizer and pattern DB (docs: modules/dragonslayer/analysis/pattern_analysis/recognizer.md)
	- taint_tracking — TaintTracker engine (docs: modules/dragonslayer/analysis/taint_tracking/tracker.md)
	- symbolic_execution — SymbolicExecutor engine (docs: modules/dragonslayer/analysis/symbolic_execution/executor.md)

- ml, gpu, ui, utils, workflows, enterprise — supporting subsystems

See detailed API shapes in [APIs](./04-apis.md). Each module page links back here.
