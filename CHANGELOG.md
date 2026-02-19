# Changelog

All notable changes to VMDragonSlayer are documented here.

## [Unreleased] — dev-0.9.1

### Bug Fixes (Phase A)
- **Pipeline pattern DB path** — Fixed `parents[1]` → `parents[2]` to correctly resolve project root
- **Taint analysis type mismatch** — Pipeline now lifts instructions via `InstructionLifter` before passing to `TaintAnalyzer`
- **Duplicated VM discovery** — Orchestrator delegates to `VMDetector` instead of inline heuristics (~80 lines removed)
- **YAML config never loads** — Added fallback from `vmdragonslayer_{env}.yml` to `vmdragonslayer.yml`
- **max_workers never used** — `_run_plugin_stage` now uses `ThreadPoolExecutor(max_workers=N)` instead of sequential loop
- **entry_point_patterns dead code** — `database.match()` now scans `entry_point_patterns` via regex matching
- **Anti-evasion false positives** — Instruction scanning restricted to executable sections (PE `IMAGE_SCN_MEM_EXECUTE`, ELF `SHF_EXECINSTR`)

### New Features (Phase B — Analysis Engines)
- **Real symbolic execution semantics** — `SymbolicExecutor` now processes mov, add/sub, and/or/xor, shl/shr/sar/rol/ror, push/pop, lea, cmp/test, inc/dec, neg/not, xchg, movzx/movsx with z3 BitVec operations; branch constraints via `_build_branch_constraint()`; enhanced opaque predicate detection (trivial + z3-proven)
- **Triton taint engine wiring** — Triton plugin taints VM context registers, tracks taint flow per instruction, extracts path constraints from symbolised branches
- **angr handler exploration** — SimulationManager-based handler boundary detection with max_blocks cap and active state limit
- **Dispatcher identification** — New `DispatcherAnalyzer` module with jump-table scanning (`jmp [reg*4+disp32]`), handler table reconstruction, opcode→address mapping; integrated as `dispatcher_analysis` pipeline stage
- **Virtual register tracking** — `VMTaintTracker` maps native registers to VM roles via presets (`vmprotect_x64`, `vmprotect_x86`, `themida_x64`); improved handler boundary detection with untaint/retaint patterns
- **Memory taint propagation** — `TaintTracker._process_instruction()` now reads/writes `_mem_taint` for memory operations (was dead code)

### New Features (Phase C — Depth)
- **LLM few-shot examples** — Handler classification (3 examples), deobfuscation hints (2 examples), code recovery (1 example), pattern explanation (1 example) added to prompts
- **VM-focused reporter** — Report now includes protector identification, dispatcher/handler table, symbolic execution summary, taint analysis with virtual register map and flow statistics

### New Features (Phase D — Robustness)
- **Plugin timeout** — `Plugin.safe_execute()` supports configurable per-plugin timeout via class attr or config; runs execute() in daemon thread with hard abort
- **Thread-safe shared_data** — `PluginContext` gains `threading.Lock` and `set_shared()`/`get_shared()`/`update_shared()` accessors; pipeline uses thread-safe writes during concurrent plugin execution

### Tests
- 160 tests total (159 pass, 1 skipped for z3-solver)
- Updated config test assertions to match actual YAML values
- Restored `_PATTERN_EXPLANATION_PROMPT` after accidental deletion

## [0.0.1] — Baseline

Initial tagged baseline before improvement cycle.
- 159 tests passing
- Core framework: orchestrator, pipeline, config, exceptions, API client
- 16 plugins across 4 stages (static/dynamic/enrichment/reporting)
- Analysis modules: vm_discovery, pattern_analysis, symbolic_execution, taint_tracking, anti_evasion
- LLM integration via litellm
