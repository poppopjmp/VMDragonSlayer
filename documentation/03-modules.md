# Modules

Index of primary packages and key modules. Paths link to source and docs where available.

## Core System

- **core**
	- `dragonslayer/core/api.py` — Unified facade for analysis and configuration
	- `dragonslayer/core/orchestrator.py` — Coordinates analysis workflows and components
	- `dragonslayer/core/config.py` — Typed configuration and environment overrides
	- `dragonslayer/core/exceptions.py` — Error hierarchy and validators

- **api**
	- `dragonslayer/api/server.py` — FastAPI server exposing analysis endpoints
	- `dragonslayer/api/client.py` — HTTP client for interacting with the server
	- `dragonslayer/api/endpoints.py` — API endpoint definitions
	- `dragonslayer/api/transfer.py` — Data transfer utilities

## Analysis Engine

- **analysis**
	- `vm_discovery/` — VMDetector and structural detection (docs: modules/dragonslayer/analysis/vm_discovery/detector.md)
	- `pattern_analysis/` — PatternRecognizer and extended pattern detection
		- `recognizer.py` — Core pattern recognition
		- `extended_recognizer.py` — Extended VM pattern matching with metamorphic support
		- `classifier.py` — ML-enhanced pattern classification
		- `database.py` — Pattern database management
	- `taint_tracking/` — Dynamic taint analysis engine (docs: modules/dragonslayer/analysis/taint_tracking/tracker.md)
	- `symbolic_execution/` — Symbolic execution and path exploration
		- `executor.py` — Core symbolic executor
		- `symbolic_engine.py` — Extended symbolic analysis with SMT solving
		- `lifter.py` — Binary lifting utilities
		- `solver.py` — Constraint solving interface
	- `multi_arch/` — Cross-platform architecture support
		- `cross_platform_detector.py` — Multi-architecture VM detection
	- `anti_evasion/` — Anti-analysis countermeasures
		- `environment_normalizer.py` — Environment normalization
		- `security_extensions.py` — Advanced evasion detection and mitigation

## Machine Learning & Intelligence

- **ml**
	- `classifier.py` — Core ML classification engine
	- `ml_detection.py` — ML-based VM detection with ensemble methods
	- `model.py` — Model management and persistence
	- `trainer.py` — Training pipeline and optimization
	- `pipeline.py` — ML processing pipelines
	- `ensemble.py` — Ensemble method implementations

- **analytics**
	- `intelligence.py` — Threat intelligence integration
	- `metrics.py` — Performance and accuracy metrics
	- `reporting.py` — Analysis report generation
	- `dashboard.py` — Real-time analytics dashboard

## Real-time & Performance

- **realtime**
	- `analysis_engine.py` — Real-time analysis capabilities with streaming support

- **gpu**
	- `engine.py` — GPU-accelerated analysis engine
	- `memory.py` — GPU memory management
	- `optimizer.py` — Performance optimization
	- `profiler.py` — GPU performance profiling

## Integration & Extensions

- **unified_analysis.py** — Unified analysis orchestration layer integrating all components

- **workflows**
	- `manager.py` — Workflow orchestration and management
	- `pipeline.py` — Analysis pipeline definitions
	- `integration.py` — External tool integration

- **ui**
	- `dashboard.py` — Web-based analysis dashboard
	- `interface.py` — User interface components
	- `widgets.py` — Dashboard widgets and visualizations
	- `charts.py` — Chart and graph generation

- **enterprise**
	- `enterprise_architecture.py` — Enterprise deployment support
	- `compliance_framework.py` — Compliance and governance
	- `api_integration.py` — Enterprise API integrations

- **utils** — Supporting utilities for memory management, performance monitoring, and platform abstraction

See detailed API shapes in [APIs](./04-apis.md). Each module page links back here.
