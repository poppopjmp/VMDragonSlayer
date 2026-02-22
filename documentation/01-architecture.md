# Architecture

VMDragonSlayer is organised into five layers.  Data flows top-down
through the pipeline; each layer only depends on layers below it.

```
┌─────────────────────────────────────────────┐
│                  API / CLI                   │  dragonslayer/api/, cli.py
├─────────────────────────────────────────────┤
│               Core / Pipeline               │  dragonslayer/core/
├──────────────┬──────────────┬───────────────┤
│   Analysis   │      ML      │    Plugins    │  dragonslayer/analysis/,
│   Engine     │              │               │  ml/, plugins/
├──────────────┴──────────────┴───────────────┤
│            Shared Utilities                  │  dragonslayer/utils/
└─────────────────────────────────────────────┘
```

## 1  Core (`dragonslayer/core/`)

| Module | Purpose |
|--------|---------|
| `orchestrator.py` | Top-level façade — dispatches analysis jobs, aggregates results |
| `pipeline.py` | Sequential multi-stage pipeline with shared `PluginContext`; narrowed exception handling (Batch 1) |
| `config.py` | YAML-based configuration (`vmdragonslayer.yml`); schema in `data/schemas/config_schema.json`; reports all validation errors at once |
| `exceptions.py` | Centralised exception hierarchy with error codes |
| `__init__.py` | Public API surface — re-exports 6 exception classes + 4 pipeline classes |

## 2  Analysis Engine (`dragonslayer/analysis/`)

The devirtualisation pipeline runs these stages in order:

| # | Stage | Module(s) | Inputs → Outputs |
|---|-------|-----------|------------------|
| 1 | **Binary loading** | `binary_format.py` | raw bytes → `ParsedBinary` (sections, VA mapping) |
| 2 | **Trace acquisition** | `trace_engine.py` | binary + entry → `ExecutionTrace` via Unicorn |
| 3 | **Trace ingestion** | `trace_ingestion.py` | plugin dicts / text → unified `ExecutionTrace` |
| 4 | **VM discovery** | `vm_discovery/detector.py`, `handler_boundaries.py`, `dispatcher.py` | trace → VM presence, handler boundaries, dispatch table |
| 5 | **CFG** | `cfg.py` | instructions / handlers → instruction-CFG + handler-CFG (networkx) |
| 6 | **Handler semantics** | `handler_semantics.py` | native instructions per handler → `HandlerSemantic` (vPush, vAdd, vLoad, …) |
| 7 | **Bytecode extraction** | `bytecode_extract.py` | trace + vIP reads → `BytecodeStream` / `OpcodeMap` |
| 8 | **Symbolic execution** | `symbolic_execution/` | instructions → z3 symbolic state, path constraints |
| 9 | **MBA simplification** | `mba_simplifier.py` | z3 BitVec expressions → simplified equivalents (31 rules + linear MBA decomposition) |
| 10 | **Data-flow analysis** | `dataflow.py` | opcode table + CFG → reaching defs, dead vars, live ranges |
| 11 | **Pseudocode emission** | `pseudocode.py` | opcode table + CFG → linear SSA / structured C-like output |

Supporting analysis modules:

| Module | Purpose |
|--------|---------|
| `pattern_analysis/` | Pattern database, YARA engine, recognizer, classifier |
| `taint_tracking/` | Forward taint propagation, VM-specialised taint, DTT executor |
| `anti_evasion/` | Anti-debug / anti-analysis technique detection and neutralisation |

## 3  ML (`dragonslayer/ml/`)

| Module | Purpose |
|--------|---------|
| `pipeline.py` | Feature extraction from analysis artefacts; mnemonic sets are `frozenset` for immutability |
| `model.py` | VM handler classifier (weighted-rule + optional scikit-learn); pickle fallbacks removed — requires joblib |
| `handler_classifier.py` | Bridge between ML pipeline and devirtualisation |
| `trainer.py` | Training infrastructure |
| `ensemble.py` | Multi-model combination (stub) |

## 4  Plugin Framework (`dragonslayer/plugins/`)

Plugins implement the `Plugin` ABC and run inside the pipeline's
`PluginContext`.  `_execute_with_timeout` uses `ThreadPoolExecutor`
for clean timeout handling.  `PluginContext.storage` is typed
`StorageBackend | None` via `TYPE_CHECKING`.  Four built-in stages:

| Stage | Directory | Examples |
|-------|-----------|----------|
| Static analysis | `plugins/static/` | PE, ELF, Mach-O, certificate, string extraction |
| Dynamic analysis | `plugins/dynamic/` | angr, Triton, Qiling, Blackfyre, BinExport, Strelka |
| Enrichment | `plugins/enrichment/` | Binary similarity, function similarity, VectorShare |
| Reporting | `plugins/reporting/` | Markdown report, network graph |

External tool bridges live under `plugins/` at the repo root:
`plugins/ghidra/`, `plugins/idapro/`, `plugins/binaryninja/`.

## 5  API (`dragonslayer/api/`)

| Module | Purpose |
|--------|---------|
| `server.py` | FastAPI REST server (`/analyze`, `/health`, `/status`, WebSocket `/ws`) |
| `client.py` | Python clients for the API and Metroplex gateway |

## 6  GPU (`dragonslayer/gpu/`)

Interface stubs for future GPU-accelerated pattern matching —
`engine.py`, `memory.py`, `optimizer.py`, `profiler.py`.
Not yet functional.

## Data Flow

```
Binary ──► ParsedBinary ──► Unicorn Trace ──► ExecutionTrace
                                                     │
                             ┌───────────────────────┘
                             ▼
                      VM Discovery
                     (detector, boundaries, dispatcher)
                             │
                             ▼
                      Handler Semantics ──► OpcodeTable
                             │
                      ┌──────┴──────┐
                      ▼             ▼
               Symbolic Exec   Bytecode Extract
                      │             │
                      ▼             ▼
               MBA Simplify   BytecodeStream
                      │
                      ▼
               Data-Flow Analysis
                      │
                      ▼
               Pseudocode Emission
```