# Changelog

All notable changes to VMDragonSlayer are documented here.

## [Unreleased] — dev-0.9.1

### Phase 9 — Correctness & Depth Improvements (12 commits)

Phase 9 addresses the top-10 correctness and depth issues identified by an expert
audit. Every change is backed by targeted unit tests and cross-module integration
tests, bringing the total to **430 tests (430 pass, 7 skip)**.

#### Enhanced — Symbolic Execution EFLAGS (`analysis.symbolic_execution`)
- **Explicit flag modelling** — `SymbolicState.flags` dict tracks ZF/CF/SF/OF individually, replacing the fragile `_last_cmp` hack (`f70085a`)
- `update_flags_arith()`, `update_flags_logic()`, `update_flags_inc_dec()` update flags correctly for arithmetic (sub/cmp), logic (and/or/xor/test), and inc/dec instructions
- `_build_branch_constraint` in `SymbolicExecutor` reads `state.flags` directly for jz/jnz/jl/jg/etc.
- `fork()` deep-copies flags so child states are independent
- 8 unit tests

#### Enhanced — Memory-Aware Taint Tracking (`analysis.taint_tracking.tracker`)
- **SIB addressing support** — `_extract_memory_address` rewritten to parse `[base+index*scale+disp]` patterns with Intel and AT&T syntax (`85884b8`)
- `_resolve_addr_expr()` evaluates x86 SIB address expressions given concrete register values
- `_process_instruction` and `analyze` thread `register_values` from trace instructions for concrete address resolution
- 8 unit tests

#### Enhanced — Dispatcher Back-Edge Scoring (`analysis.symbolic_execution.executor`)
- `_find_dispatcher` now scores each indirect jump by counting back-edges within ±64 bytes, preferring the dispatcher with most inbound control flow (`0e803ef`)
- 3 unit tests

#### Fixed — Push/Pop with Symbolic SP (`analysis.symbolic_execution.executor`)
- SP initialised to concrete stack base (`0x7FFF0000`) in `execute_handler`, keeping SP concrete while other registers are symbolic (`52f35ce`)
- Symbolic SP fallback attempts z3 concretisation via `solver.check()`
- 2 unit tests

#### Enhanced — MBA 3-Variable Support (`analysis.mba_simplifier`)
- Added `_known_rules_3` with 5 proven 3-variable rewrite rules (triple XOR commutativity, De Morgan's 3-var, XOR+AND distribution, etc.) (`3251b37`)
- `simplify_expr` tries all permutations of 2-var and 3-var rule templates
- `simplify_mba` auto-detects variable names from expression text
- 4 unit tests

#### Fixed — `emit_structured` Loop Depth (`analysis.pseudocode`)
- Tracks `open_loops` counter, emits one `}` per opened `while(true){` block, preventing unbalanced braces (`da2d7fd`)
- 1 unit test

#### Enhanced — Pipeline Per-Stage Timeout (`core.pipeline`)
- Each stage runs in a `ThreadPoolExecutor` future with `cfg.timeout` deadline (`eab1f15`)
- **Fixed**: `shutdown(wait=False, cancel_futures=True)` so a timed-out stage no longer blocks the pipeline (`1798b03`)
- 1 unit test

#### Fixed — `has_indirect_branch` Feature (`ml.pipeline`)
- Now inspects operand strings for register names or memory dereferences (e.g., `[rax]`, `jmp rcx`) instead of the broken positional heuristic (`02b0da5`)
- 4 unit tests

#### Fixed — Register Extraction Heuristic (`analysis.trace_ingestion`, `analysis.handler_semantics`)
- Replaced broken set-iteration "first-reg = write" with mnemonic-aware `_extract_reg_reads_writes()` classifying each operand as read, write, or both (`e123436`)
- Handles mov, add, sub, cmp, test, push, pop, xchg, lea, mul, div, and more
- Word-boundary regex (`_REG_RE`) prevents r8/r12/r15 false matches
- Shared by `trace_ingestion` and `handler_semantics._taint_slice`
- 8 unit tests

#### New — VMProtect vAdd Handler End-to-End Test (`tests/test_vmprotect_trace.py`)
- Synthetic-but-faithful VMProtect vAdd trace (11 instructions, 4+ memory accesses, handler marker, dispatch control flow) (`78237d4`)
- 8 tests exercising trace ingestion, taint propagation, handler semantics, symbolic execution, pseudocode emission, and full pipeline

#### New — Phase 9 Integration Tests (`tests/test_phase9_integration.py`)
- 21 cross-module integration tests covering EFLAGS→branch, SIB memory taint, dispatcher→semantics, MBA 2/3-var, pipeline timeout, register extraction, pseudocode emission, symbolic state fork, and full trace→pseudocode chain (`1798b03`)

#### Test Suite
- **430 tests** (430 pass, 7 skip — all yara-python)
- New test files: `test_vmprotect_trace`, `test_phase9_integration`
- Trajectory: 362 (Phase 8 end) → 401 (9 fixes) → 409 (VMProtect trace) → 430 (integration)

---

### Phase 8 — Deep Integration & Real Analysis Engines (14 commits)

Phase 8 transforms VMDragonSlayer from a framework with data-starved scaffolding
into a tool where **dynamic plugins produce per-instruction execution traces** that
flow through trace ingestion, handler classification, symbolic execution, and
pseudocode emission.

#### Bug Fixes
- **`_run_devirtualize` type bugs** — Fixed 4 type errors: passes `ExecutionTrace` (not lifted list); uses `vip_candidate.name` (not `.register`) (`3510ff2`)
- **`label_from_heuristics` empty-string match** — Partial-match loop now skips empty `op_lower` to avoid false positives (`f394ced`)

#### Dependency Changes
- **z3-solver is now non-optional** — Hard `import z3` everywhere; removed all conditional guards and skip markers (`7b49397`)
- **Python ≥ 3.10 required** — Code uses `X | Y` union syntax; pyproject.toml updated with 3.10–3.14 classifiers (`7b49397`)
- **Core deps added** — `lief>=0.14.0`, `networkx>=3.0`, `click>=8.0` moved to hard requirements (`7b49397`)

#### Enhanced — Triton Plugin (`plugins.dynamic.triton_analyzer`)
- Per-instruction register snapshots (rax–r15, eax–eip) after every `processing()` call
- Memory hooks: `GET_CONCRETE_MEMORY_VALUE` / `SET_CONCRETE_MEMORY_VALUE` capture reads/writes
- Emits `instruction_trace[]` with address, size, raw_bytes, disassembly, registers, memory_accesses, is_tainted
- Published to `ctx.shared_data['triton']` for downstream ingestion (`e5c9e13`)

#### Enhanced — Qiling Plugin (`plugins.dynamic.qiling_analyzer`)
- `ql.hook_code` for per-instruction tracing with Capstone disassembly
- `ql.hook_mem_read` / `ql.hook_mem_write` for memory access tracking
- Configurable `max_instructions` cap (default 200K)
- Publishes `instruction_trace` + `memory_accesses` to `shared_data['qiling']` (`fcf94f5`)

#### Enhanced — angr Plugin (`plugins.dynamic.angr_analyzer`)
- `_extract_handler_traces`: per-handler symbolic execution with per-instruction data
- Architecture-aware register lists via `_get_reg_names`
- Publishes enriched `handler_traces` in `shared_data['angr']` (`445df7e`)

#### Enhanced — BinExport & Blackfyre Plugins
- **BinExport**: Walks basic blocks → instructions extracting mnemonics, operands, addresses; builds call_graph_edges and per-function mnemonic lists (`ad0959e`)
- **Blackfyre**: Per-function mnemonics list, per-instruction address/operand extraction, callee/caller cross-reference lists (`ad0959e`)
- Both feed downstream vector generation (vector_share, function_similarity)

#### Rewritten — Trace Ingestion Adapters (`analysis.trace_ingestion`)
- `_ingest_triton`: reads enriched `instruction_trace[]` with registers, raw_bytes, memory_accesses
- `_ingest_angr`: reads `handler_traces[].instructions` with register snapshots
- `_ingest_qiling`: reads `instruction_trace[]` with register snapshots and memory accesses
- All adapters produce `TraceInstruction` with populated size, raw_bytes, registers (`827bb60`)

#### Enhanced — Handler Semantics (`analysis.handler_semantics`)
- Added mov/movzx/movsx/movsxd/lea/cmov\*/set\*/xchg/bswap to `_MNEMONIC_MAP` (`858597f`)
- Context-aware mov: LOAD (memory source) vs STORE (memory destination) via `_mnemonic_to_vm_op()`
- `_JUNK_MNEMONICS` + `_filter_junk`: removes opaque predicates, nop-equivalents, dead code
- Intel `[...]` and AT&T `(...)` memory syntax support
- **Taint-based semantic slicing**: `_taint_slice` uses TaintTracker to identify VM context data-flow (`2dac08a`)

#### Enhanced — Pseudocode Emission (`analysis.pseudocode`)
- **SSA def-use chains**: `_DefUseNamer` tracks VM stack operations with semantic variable names (sum_0, ld_1, stk_2, arg_0) (`d66da6b`)
- `_format_instruction_ssa` formats pseudocode using def-use chains
- `_OP_PREFIX` maps: ADD→"sum", SUB→"diff", LOAD→"ld", POP→"stk", etc.
- Fixed back-edge detection to handle both index-based and address-based graph nodes

#### New — MBA Simplification (`analysis.mba_simplifier`)
- 11 z3-proven rewrite rules: and_or→add, xor_and→add, XNOR, complement_sub, double_not, etc.
- `verify_equivalence`: z3 proof that two expressions are bit-accurate equivalent
- `simplify_expr`: pattern-match known rules, fall back to `z3.simplify(som=True)`
- `simplify_mba`: text interface with recursive-descent C-style expression parser
- `simplify_batch`: batch processing with `MBAStats`
- `simplify_handler_operands`: regex-driven in-place MBA rewrite on disassembly strings
- 15 tests (`a0c7145`)

#### New — Handler-Local Symbolic Execution (`analysis.symbolic_execution.executor`)
- `execute_handler(handler_bytes, handler_address)`: fresh symbolic state with symbolic input registers; steps through handler; MBA simplification of final register expressions
- `execute_handler_from_trace(trace_instructions)`: consumes trace instruction dicts
- `HandlerSymbolicSummary` dataclass: address, final_registers, simplified_registers, memory_writes, constraints, input_symbols
- Integrates with `mba_simplifier.simplify_expr` for expression reduction (`443f205`)

#### New — ML Handler Classifier & Training Pipeline (`ml/`)
- `extract_handler_features()`: 15-D feature vector (instruction_count, mnemonic ratios, memory flags, operand width, block count) (`c2b7ba5`)
- `VMHandlerModel`: weighted-rule heuristic scoring + optional sklearn RandomForest
- `label_from_heuristics()`: derives labels from handler semantic operations via `_OP_TO_LABEL`
- `prepare_training_data()`: handler dicts → (features, labels) pairs
- `ModelTrainer.train()`: sklearn RF when available, heuristic validation fallback
- 7 handler categories: arithmetic, logic, stack, load_store, branch, nop, unknown

#### New — Integration Tests (`tests/test_integration.py`)
- 16 end-to-end integration tests exercising the full devirtualisation pipeline
- Tests: trace→vIP→boundaries→semantics→pseudocode, Triton ingestion, MBA round-trip, handler symbolic execution, Z3 opaque predicates, ML classifier pipeline, cross-module data structures (`f394ced`)

#### Test Suite
- **362 tests** (362 pass, 7 skip — all yara-python)
- z3-solver skip eliminated (now a hard dependency)
- New test files: `test_integration`, `test_mba_simplifier`

---

### Phase 7 — Devirtualisation Pipeline (15 commits)

The central achievement of Phase 7 is a **complete devirtualisation data path**:
dynamic traces can now be ingested, segmented into per-handler slices, classified
by semantic operation, and emitted as human-readable pseudocode.

#### Bug Fixes
- **Taint analyzer reset ordering** — `reset()` now runs *before* taint application, not after (`ff71676`)
- **Thread-safe server counters** — `asyncio.Lock` protects `/analyze` request/error counts (`1259112`)

#### New — CLI Entry Point (`dragonslayer.cli`)
- `vmdragonslayer analyze` — run analysis on a binary file
- `vmdragonslayer serve` — launch the REST API server
- `vmdragonslayer info` — print version and config summary
- 7 Click tests (`118ff91`)

#### New — YARA-based Pattern Matching (`analysis.pattern_analysis.yara_engine`)
- `YaraEngine` wraps `yara-python` as an optional backend
- `compile_rules()`, `scan_bytes()`, `YaraMatch` result model
- Integrated into `PatternRecognizer` as fallback strategy
- 12 tests (`e859672`)

#### New — Push/Ret Dispatcher Detection (`analysis.vm_discovery.dispatcher`)
- Detects `push handler; ret` trampolines (common in Themida)
- Multi-step heuristic: indirect-jump table → computed-jump → push/ret
- 8 tests (`9422ee8`)

#### New — Shared LIEF Binary Parser (`analysis.binary_format`)
- `parse_binary()` returns `ParsedBinary` (sections, entrypoint, imports, exports)
- Replaces duplicate manual PE parsing in `VMDetector` and `EnvironmentNormalizer`
- 14 tests (`c6d2626`)

#### New — Trace Ingestion (`analysis.trace_ingestion`)
- `ExecutionTrace` data model: instructions, memory accesses, control flow, handler markers
- Five ingestion paths: `parse_trace_text()`, `from_shared_data()`, `from_triton_result()`, `from_angr_result()`, `from_qiling_result()`
- `to_lifted_instructions()` re-lifts via capstone or falls back to `_SimpleInstruction`
- 17 tests (`b79dc2b`)

#### New — vIP Identification & Handler Boundaries (`analysis.vm_discovery.handler_boundaries`)
- `identify_vip_register()` scores candidates by monotonic ratio, alignment, dispatcher correlation
- `segment_trace()` slices execution trace into per-handler `HandlerBoundary` segments
- Two strategies: dispatcher-address based, vIP-change based
- 18 tests (`2c2ee99`)

#### New — CFG Reconstruction (`analysis.cfg`)
- `build_instruction_cfg()` — address-level control flow graph
- `build_handler_cfg()` — handler-level CFG with back-edge detection
- `extract_basic_blocks()`, `analyse_cfg()` → `CFGStats`, `find_dominators()`
- 19 tests (`f8e7c1c`)

#### New — VM Bytecode Extraction (`analysis.bytecode_extract`)
- `extract_bytecode()` correlates memory reads with handler boundaries
- `BytecodeStream`, `OpcodeMap`, `VMOpcode` data models
- Fallback: `_build_from_boundaries_only` when no memory accesses available
- 13 tests (`01123ef`)

#### New — ML Handler Classifier (`ml.handler_classifier`)
- `TrainedHandlerModel` bridges scikit-learn to devirt path
- Heuristic fallback when no trained model is available
- Feature vector: instruction_count, vip_delta, handler_span, insn_density
- 10 tests (`ff5ad32`)

#### New — Handler Semantics & Opcode Table (`analysis.handler_semantics`)
- `analyse_handler_semantics()` maps each handler to a `VMOperation` (add, sub, xor, load, store, push, pop, jcc, jmp, call, ret, nop, …)
- Mnemonic histogram scoring with push/pop de-weighting (0.3×)
- `SemanticOpcodeTable` with opcode lookup, summary, and serialisation
- 24 tests (`ed339fa`)

#### New — Pseudocode Emission (`analysis.pseudocode`)
- `emit_linear()` — one line per VM instruction, no control flow
- `emit_structured()` — uses handler-level CFG for `if/while/goto`
- `emit_c_like()` — wraps structured in typed function with variable declarations
- `emit_pseudocode()` — convenience style dispatcher
- 16 tests (`f79717a`)

#### Refactored — Pipeline Engine Runners (`core.pipeline`)
- `_run_stage()` helper eliminates try/except + timing boilerplate
- New `devirtualize` pipeline stage chains: trace ingestion → vIP identification → handler segmentation → semantic analysis → pseudocode emission
- Wired into `create_full_pipeline()` and `create_vmprotect_devirt_pipeline()` profiles
- 10 tests (`d86cb25`)

#### Documentation (this commit)
- README: updated architecture diagram, capability table, repo structure, test counts
- CHANGELOG: Phase 7 entries for all 15 commits

#### Test Suite
- **335+ tests** (327 pass, 8 skip — 1 z3-solver, 7 yara-python)
- New test files: `test_cli`, `test_yara_engine`, `test_dispatcher`, `test_binary_format`, `test_trace_ingestion`, `test_handler_boundaries`, `test_cfg`, `test_bytecode_extract`, `test_handler_classifier`, `test_handler_semantics`, `test_pseudocode`, `test_pipeline_devirt`

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
