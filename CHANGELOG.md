# Changelog

All notable changes to VMDragonSlayer are documented here.

## [Unreleased] — dev-0.9.1

### Phase 6 — Hardening & Completeness (12 commits)

#### Critical Bug Fixes
- **`from __future__ import annotations`** — Added to `exceptions.py` for Python 3.14 forward-compat (`aa9a70a`)
- **Taint dict-as-int crash** — Pipeline now uses `dispatcher_addresses` key instead of passing a dict where an int was expected (`aa9a70a`)
- **Dead `pipeline_config`** — Removed unreachable variable assignment in pipeline (`aa9a70a`)
- **Temp dir leak** — Orchestrator and pipeline temp dirs wrapped in `try/finally` with `shutil.rmtree` (`aa9a70a`, `c408a9d`)
- **Config `_merge_config`/`_deep_merge` corruption** — Repaired literal `\n` syntax error from prior session edit (`a656e80`)

#### Symbolic Execution Fixes
- **test vs cmp opaque predicate** — `test` now AND-checks, `cmp` now SUB-checks (were identical) (`aa9a70a`)
- **LEA dereference bug** — New `_resolve_effective_address()` handles `[base + index*scale + disp]` without dereferencing (`fbc56a9`)
- **push/pop symbolic SP** — Stack pointer now correctly decremented/incremented with z3 BitVec ops (`fbc56a9`)
- **`_last_cmp` attribute** — Added to `SymbolicState` with proper `fork()` propagation (`fbc56a9`)
- **`read_memory` default size** — Uses `bit_width // 8` instead of hardcoded 4 (`fbc56a9`)
- **int3 → SYSTEM** — Lifter maps `int3` to `SYSTEM` instruction type (`fbc56a9`)
- **mov MEMORY_WRITE** — Lifter sets memory destination type for `mov [mem], reg` (`fbc56a9`)
- **Deque worklist** — Replaced list-based worklist with `collections.deque` for O(1) popleft (`fbc56a9`)
- **Solver push/pop sync** — `_constraint_stack` properly syncs with z3 solver push/pop (`fbc56a9`)

#### VM Discovery & Pattern Analysis Fixes
- **Section entropy slice** — Detector entropy calculation now slices section data correctly (`0855481`)
- **64-bit dispatcher entries** — `entry_size` parameter supports 8-byte handler table entries (`0855481`)
- **`import re` out of loop** — Pattern database moves regex import to module level (`0855481`)
- **SequenceRecognizer offset** — Fixed off-by-one in match offset calculation (`0855481`)
- **UnboundLocalError** — Recognizer returns empty list on unmatched path instead of referencing undefined var (`0855481`)
- **Regex escape** — Signature patterns passed through `re.escape()` to prevent injection (`0855481`)

#### Taint Tracking & Thread Safety
- **TaintTracker `reset()`** — New method clears register/memory taint state; called before each analysis run (`18cc720`)
- **Public API** — `process_instruction()` and `reg_taint`/`mem_taint` properties exposed (`18cc720`)
- **MemoryBackend `threading.Lock`** — Storage backends guarded for concurrent access (`18cc720`)
- **`get_config()` double-checked locking** — Thread-safe singleton with `threading.Lock` (`18cc720`)
- **Config `_deep_merge`** — Recursive dict merge replaces shallow `dict.update()` (`18cc720`)

#### Resource Leaks & Cleanup
- **`VMDragonSlayerAPI.shutdown()`** — Properly cleans up HTTP client on exit (`c408a9d`)
- **Double-serialize fix** — Orchestrator no longer JSON-encodes already-dict results (`c408a9d`)
- **Plugin discovery logging** — Warnings downgraded for expected missing optional plugins (`c408a9d`)

#### API & Server Improvements
- **CORS `allow_credentials=False`** — Fixes invalid wildcard + credentials combo per CORS spec (`8c9c0db`)
- **Lifespan context manager** — Replaces deprecated `@app.on_event("startup"/"shutdown")` (`8c9c0db`)
- **Async rate limiter** — `check_rate_limit()` uses `asyncio.Lock` for thread safety (`8c9c0db`)
- **Exception handler shadowing** — `InvalidDataError` now re-raised to global handler (`8c9c0db`)
- **`asyncio.get_running_loop()`** — Replaces deprecated `get_event_loop()` (`8c9c0db`)
- **Logger f-string → %s** — Lazy formatting for all logger calls (`8c9c0db`)

#### Plugin Fixes
- **angr `simgr.move()` pattern** — Replaces broken iterate-while-stashing loop (`fe593fd`)
- **Sorted Counter for deterministic MD5** — angr and triton plugins produce stable hashes (`fe593fd`)
- **Triton `tainted_write` filter** — Only includes actually-tainted registers (`fe593fd`)
- **ssdeep pre-computed hashes** — `compute_similarity()` accepts stored hashes (fixes always-0.0 DB lookups) (`fe593fd`)
- **pefile `close()`** — PE objects closed in `finally` to prevent handle leaks (`fe593fd`)

#### ML Module (New — was 100% empty stubs)
- **`BaseModel` / `VMHandlerModel`** — Abstract base with `train()`/`predict()`/`save()`/`load()` contract; VM handler specialization (`69d6c1d`)
- **`FeatureExtractor` / `FeatureVector`** — Configurable feature specification, dataclass output (`69d6c1d`)
- **`ModelTrainer` / `TrainingResult`** — Training loop with metric collection, data preparation (`69d6c1d`)
- **`VMClassifier`** — High-level classifier entry point (`69d6c1d`)
- **`EnsembleClassifier` / `WeightedEnsemble`** — Majority-vote and weighted ensemble strategies (`69d6c1d`)

#### GPU Module (New — was 100% empty stubs)
- **`gpu_available()`** — Runtime detection with guarded torch/CUDA imports (`69d6c1d`)
- **`GPUEngine`** — Device management and data transfer interface (`69d6c1d`)
- **`GPUMemoryManager`** — Allocation tracking interface (`69d6c1d`)
- **`GPUOptimizer`** — Block-size recommendation interface (`69d6c1d`)
- **`GPUProfiler`** — Wall-clock timing that works without GPU hardware (`69d6c1d`)

#### LLM Improvements
- **JSON fence stripping** — `re.sub()` removes markdown code fences from LLM output (`c605346`)
- **`reset_llm_analyzer()`** — Singleton reset for testing (`c605346`)

#### Performance & Quality
- **`LocalFileBackend.store_bulk`** — Batch flush (single fsync) instead of per-item writes (`d72fbf2`)
- **`avg_confidence` in result_data** — Pipeline wires average confidence into pattern analysis + plugin stage results (`d72fbf2`)

#### Anti-Evasion Tuning
- **`call_next` confidence 0.70 → 0.30** — Reduces PIC false positives (`1112c01`)
- **int3 `patchable=False`** — Interrupt-based techniques not auto-patched (`1112c01`)
- **Per-pattern confidence overrides** — `_ANTI_DISASM_CONFIDENCE` dict enables pattern-level tuning (`1112c01`)

### Phase 5 — Audit & Implementation (18 items, 14 commits)

#### Bug Fixes (Phase A)
- **Pipeline pattern DB path** — Fixed `parents[1]` → `parents[2]` to correctly resolve project root
- **Taint analysis type mismatch** — Pipeline now lifts instructions via `InstructionLifter` before passing to `TaintAnalyzer`
- **Duplicated VM discovery** — Orchestrator delegates to `VMDetector` instead of inline heuristics (~80 lines removed)
- **YAML config never loads** — Added fallback from `vmdragonslayer_{env}.yml` to `vmdragonslayer.yml`
- **max_workers never used** — `_run_plugin_stage` now uses `ThreadPoolExecutor(max_workers=N)` instead of sequential loop
- **entry_point_patterns dead code** — `database.match()` now scans `entry_point_patterns` via regex matching
- **Anti-evasion false positives** — Instruction scanning restricted to executable sections (PE `IMAGE_SCN_MEM_EXECUTE`, ELF `SHF_EXECINSTR`)

#### New Features (Phase B — Analysis Engines)
- **Real symbolic execution semantics** — `SymbolicExecutor` now processes mov, add/sub, and/or/xor, shl/shr/sar/rol/ror, push/pop, lea, cmp/test, inc/dec, neg/not, xchg, movzx/movsx with z3 BitVec operations; branch constraints via `_build_branch_constraint()`; enhanced opaque predicate detection (trivial + z3-proven)
- **Triton taint engine wiring** — Triton plugin taints VM context registers, tracks taint flow per instruction, extracts path constraints from symbolised branches
- **angr handler exploration** — SimulationManager-based handler boundary detection with max_blocks cap and active state limit
- **Dispatcher identification** — New `DispatcherAnalyzer` module with jump-table scanning (`jmp [reg*4+disp32]`), handler table reconstruction, opcode→address mapping; integrated as `dispatcher_analysis` pipeline stage
- **Virtual register tracking** — `VMTaintTracker` maps native registers to VM roles via presets (`vmprotect_x64`, `vmprotect_x86`, `themida_x64`); improved handler boundary detection with untaint/retaint patterns
- **Memory taint propagation** — `TaintTracker._process_instruction()` now reads/writes `_mem_taint` for memory operations (was dead code)

#### New Features (Phase C — Depth)
- **LLM few-shot examples** — Handler classification (3 examples), deobfuscation hints (2 examples), code recovery (1 example), pattern explanation (1 example) added to prompts
- **VM-focused reporter** — Report now includes protector identification, dispatcher/handler table, symbolic execution summary, taint analysis with virtual register map and flow statistics

#### New Features (Phase D — Robustness)
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
