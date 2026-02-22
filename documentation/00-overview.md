# VMDragonSlayer

VM-protector devirtualisation framework targeting VMProtect, Themida,
and similar code-virtualisation obfuscators.  Analyses x86/x64 binaries
to recover the original operations hidden inside VM interpreters.

## What Works Today

| Capability | Module(s) | Status |
|------------|-----------|--------|
| Binary loading (PE / ELF / Mach-O) | `analysis/binary_format.py` | Functional (LIEF + fallback) |
| Execution tracing (Unicorn) | `analysis/trace_engine.py` | Functional |
| Trace ingestion (text / plugin dict) | `analysis/trace_ingestion.py` | Functional |
| VM presence detection | `analysis/vm_discovery/detector.py` | Functional |
| Handler boundary identification | `analysis/vm_discovery/handler_boundaries.py` | Functional |
| Dispatcher reconstruction | `analysis/vm_discovery/dispatcher.py` | Functional |
| Handler semantics extraction | `analysis/handler_semantics.py` | Functional — 13 VM operations |
| Symbolic execution (z3) | `analysis/symbolic_execution/` | Functional — sub-register aliasing, symbolic memory aliasing |
| MBA simplification | `analysis/mba_simplifier.py` | Functional — 31 rules + linear MBA decomposition + iterative deep simplify |
| Bytecode extraction | `analysis/bytecode_extract.py` | Functional |
| CFG reconstruction (networkx) | `analysis/cfg.py` | Functional |
| Cross-handler data-flow | `analysis/dataflow.py` | Functional — reaching defs, dead vars, live ranges |
| Pseudocode emission | `analysis/pseudocode.py` | Functional — width-qualified SSA + structured C-like |
| Pattern matching (YARA / regex) | `analysis/pattern_analysis/` | Functional |
| Taint tracking | `analysis/taint_tracking/` | Functional |
| Anti-evasion | `analysis/anti_evasion/` | Functional |
| ML handler classification | `ml/` | Functional (rule-based + optional scikit-learn) |
| Plugin framework | `plugins/` | Functional — static, dynamic, enrichment, reporting |
| REST API (FastAPI) | `api/server.py` | Functional |
| GPU acceleration | `gpu/` | **Stubs only** |

## Architecture (High Level)

```
Binary ──► ParsedBinary ──► Unicorn Trace ──► ExecutionTrace
                                                    │
                            ┌───────────────────────┘
                            ▼
                     VM Discovery (detect → boundaries → dispatch)
                            │
                            ▼
                     Handler Semantics ──► OpcodeTable
                            │
                     ┌──────┴──────┐
                     ▼             ▼
              Symbolic Exec   Bytecode Extract
                     │
                     ▼
              MBA Simplification
                     │
                     ▼
              Data-Flow Analysis
                     │
                     ▼
              Pseudocode Emission
```

See [01-architecture.md](01-architecture.md) for full module-by-module detail.

## Test Suite

3 812+ tests, 44 skipped.  Run with:

```bash
python -m pytest --tb=short -q
```

See `Home.md` for the full index and quick navigation to all sections.
