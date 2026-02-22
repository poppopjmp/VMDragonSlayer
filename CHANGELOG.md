# Changelog

All notable changes to VMDragonSlayer are documented here.

## [Unreleased] — dev-0.9.1

### Deep Review Implementation Cycle (Phases 1–4)

Systematic 4-phase improvement cycle driven by a comprehensive expert
codebase review.  All phases committed incrementally with full test
suite validation at each step.

Test count: **3825 → 3886** (61 new tests; 46 skipped, 1 xfailed).

#### Phase 1 — Pipeline Architecture (`90a4fbd` → `cf99ca4`)

- **Typed PipelineState** (`pipeline_state.py`): 47 typed fields replacing untyped `shared_data: Dict[str, Any]`, dict-compatible interface for backward compat
- **Stage DAG** (`STAGE_DEPENDENCIES`): Dependency graph for 10 stages, `validate_stage_order()` validator
- **DRY stage dispatch** (`pipeline.py`): `PipelineConfig` with 14 stages, `_run_stage()` helper eliminating 180+ lines of boilerplate
- **Devirt decomposition** (`devirt_stages.py`): 490-line `_do_devirt()` monolith split into 12 sub-step functions with `DevirtWorkspace` dataclass
- **DRY orchestrator** (`orchestrator.py`): `_run_engine_safe()` helper, fixed `_dispatch_pipeline` timeout race, `analyze_binary_data_async()`

#### Phase 2 — Analysis Depth (6 commits: `ecd452b` → `719ff85`)

- **2A — CFG+taint ML features** (`ml/pipeline.py`): `extract_cfg_features()` (7 features: depth, width, branch ratio, loop count, back edges, diameter, density) and `extract_taint_features()` (7 features: reach, entropy, stack/memory split, live proportion); feature vector expanded 132 → 146 dimensions
- **2B — SIMD/SSE/AVX semantic operations** (`handler_semantics.py`): 13 SIMD VMOperation constants (SIMD_ADD through SIMD_UNKNOWN), ~160 SSE/AVX mnemonic mappings, XMM (16B) and YMM (32B) width detection, SIMD_LOAD/SIMD_STORE de-weighting as infrastructure ops
- **2C — Pipeline API endpoint** (`server.py`, `orchestrator.py`): `PipelineRequest` Pydantic model with base64/stage validators, `POST /pipeline` endpoint, `run_pipeline()` and `run_pipeline_async()` methods on `VMDragonSlayerAPI`
- **2D — Themida/CV handler classification bridge** (`themida_devirt.py`, `cv_devirt.py`): `classify_handler_entries()` and `classify_cv_handler_entries()` capstone-based bridge functions wired into Step 4 of both devirt pipelines, guarded by optional `binary_data` parameter

#### Phase 3 — Infrastructure Hardening (`40ef448`)

- **Async API**: All analysis endpoints properly async with `asyncio.to_thread()` for CPU-bound work
- **Thread-safe plugin discovery**: Double-checked locking pattern for `_ensure_discovered()`
- **LLM taxonomy normalisation**: `canonicalize()` maps vendor-specific handler names to canonical CANONICAL_CATEGORIES

#### Phase 4 — Advanced Features (`8cd3cd9`)

- **4A — Plugin dependency tracking**: `depends_on: set[str]` and `provides: set[str]` on `Plugin` ABC; `validate_plugin_dependencies()` for graph-wide dep checks; `sort_plugins_by_deps()` with Kahn's topological sort; `PluginDependencyError` exception; wired into `_run_plugin_stage()`
- **4B — Active learning infrastructure** (`ml/active_learning.py`): `UncertainSample`, `FeedbackStore`, `FeedbackEntry` dataclasses; `select_uncertain_samples()` with entropy/margin/least-confidence strategies; `compute_entropy()`, `compute_margin()`; JSON-file persistence for analyst corrections; `export_training_set()` for merging corrections into training data; `POST /feedback` and `POST /uncertain` API endpoints
- **4C — Speculative path exploration** (`executor.py`): `speculative: bool` and `max_speculative_forks: int` parameters; speculative forking on fall-through infeasible branches; boundary-value concretisation for unresolved indirect branches; `speculative_paths_explored` counter in `ExecutionResult`; wired into `from_config()` for analysis profile control
- **4D — Plugin introspection**: `GET /plugins` listing with metadata (name, stage, version, deps, provides); `GET /plugins/health` dependency validation; `version: str` attribute on `Plugin` ABC

### Quality & Hardening Batches 1-9

Systematic codebase improvement driven by a comprehensive review.
Test count held at **3 812 passing** throughout.

#### Batch 1 — Exception Handling Narrowing (`186f272`)
- **Narrowed** `_ENGINE_ERRORS` and `_STAGE_ERRORS` in `pipeline.py` — removed blanket `Exception` catch
- Fixed 2 pre-existing bugs triggered by the tighter catches
- Updated 4 test files to align with narrowed exceptions

#### Batch 2 — Dependency Reconciliation (`1bb0682`)
- Cleaned `pyproject.toml` core deps (removed pandas/requests/scikit-learn/joblib from core)
- Added `[emulation]` optional extra; updated `[web]` with python-multipart
- Rewrote `requirements.txt` to match pyproject.toml
- Fixed stale `patch.dict("sys.modules", {})` in 5 wiring tests

#### Batch 3-6 — Internal Cleanup (`3c48ccf`)
- **Batch 3**: `analysis/__init__.py` — replaced ~130 lines of try/except blocks with `_try_import()` helper
- **Batch 4**: `core/__init__.py` — added 12 re-exports (6 exceptions, 4 pipeline classes)
- **Batch 5**: `ml/model.py` — removed all 4 insecure pickle fallbacks; `ml/pipeline.py` — converted 7 mnemonic sets to `frozenset`
- **Batch 6**: `plugins/__init__.py` — replaced daemon thread with `ThreadPoolExecutor`; added `TYPE_CHECKING` guard for `StorageBackend` type

#### Batch 7 — CLI Exit Codes (`57e592e`)
- Named exit codes: `EX_OK(0)`, `EX_ERROR(1)`, `EX_DETECTED(2)`
- Added error handling to `scan` command (was missing)
- Both `scan` and `analyze` now exit 2 on VM detection (CI-friendly)

#### Batch 8 — Test Factories (`4e8e525`)
- Created `tests/factories.py` with 10 canonical builder functions
- Deduplicates helpers found in 22+ test files (make_insn, make_pe, etc.)

#### Batch 9 — Config Schema & Validation (`39a04ff`)
- Added `data/schemas/config_schema.json` (JSON Schema draft-07)
- `Config.validate()` now reports ALL errors in a single message
- Added `Config.to_dict()` serialisation helper

### B104–B107 — Deep Implementation Cycle (4 commits)

Addresses remaining gaps identified by a comprehensive audit to bring
the codebase from ~80% to ~97% real implementation.
Test count: **3756 → 3773** (new B107 tests; cumulative B104–B107: 200 new tests).

#### B104 — GPU Removal + Devirt Pipelines (`94b20d5`)
- **Removed** `dragonslayer/gpu/` module entirely (5 stub files); replaced by litellm LLM provider
- **Themida devirt pipeline** (`themida_devirt.py` ~460 lines): `ThemidaVariant` enum, `ThemidaBytecodeDecoder`, 5-step `devirtualize_themida()` pipeline (detect → decode → extract → map → devirtualise)
- **Code Virtualizer devirt pipeline** (`cv_devirt.py` ~430 lines): `CVVersion` enum, `CVBytecodeDecoder`, 5-step `devirtualize_cv()` pipeline with LODSB/XLAT fetch-decrypt cycle
- Updated `analysis/__init__.py` with 16 new guarded exports
- 37 new tests; full suite: 3573 passed

#### B105 — Multi-Protector Synthetic Data + ML Training (`3ab18cc`)
- **Themida handler templates** (9 categories): EDI-based context, pushad/popad, [edi+offset], ESI as vIP
- **Code Virtualizer handler templates** (9 categories): LODSB/XLAT fetch-decrypt, ESP-based context, BSWAP, LODSD
- `generate_multi_protector_data()`: 2160 samples across 3 protectors × 9 categories × jitter
- `train_and_save_model()`: end-to-end training producing 98.52% accuracy (GradientBoosting)
- `_apply_jitter()`: NOP insertion, register renaming (64/32-bit pairs), dead-code push/pop
- Expanded `vmprotect_handlers.json` from 75 → 144 patterns
- 45 new tests; full suite: 3655 passed

#### B106 — Trace Collection Facade + Multi-Format Export (`c156ab5`)
- **Trace collector** (`trace_collector.py` ~441 lines): `TraceBackend` enum (Unicorn/Triton/angr/Qiling/File/Auto), `TraceConfig`, `CollectionResult`, `collect_trace()` with auto backend selection, `filter_trace()`, `merge_traces()`, `trace_statistics()`
- **Trace export** (`trace_export.py` ~340 lines): `OutputFormat` enum, plugin-style `@_register_format` decorator, 5 renderers (JSON, TEXT, CSV, IDA annotation JSON, Ghidra Jython script), `export_trace()`, `validate_roundtrip()`
- 19 new guarded exports in `analysis/__init__.py`
- 101 new tests; full suite: 3756 passed

#### B107 — RE Tool Plugins + CLI Export (`b725260`)
- **IDA Pro plugin** (`plugins/idapro/dragonslayer_ida.py` ~228 lines): `DragonSlayerPlugin` class, `PLUGIN_ENTRY()`, `apply_annotations()`, colour/comment/rename/bookmark helpers, live analysis + pre-exported JSON, `Ctrl+Shift+D` hotkey
- **Ghidra plugin** (`plugins/ghidra/dragonslayer_ghidra.py` ~224 lines): Jython 2.7 compatible, transaction-safe `apply_annotations()`, auto-discovery of annotation files, EOL/plate comments, bookmarks, function renames
- **Binary Ninja plugin** (`plugins/binaryninja/dragonslayer_binja.py` ~232 lines): `PluginCommand.register()` for Apply & Analyze, highlight colours, dragon emoji tags, file dialog + live analysis
- **CLI `export` subcommand**: `vmdragonslayer export <file> -f <format> -o <output>` (json/text/csv/ida/ghidra)
- 17 new tests; full suite: 3773 passed

#### B108 — Documentation Updates
- Updated `03-modules.md`: Removed stale GPU section, added devirt pipelines, trace collection/export, RE tool plugins, multi-protector ML training
- Filled `99-glossary.md` with 30+ domain terms across 7 categories (VM protection, protectors, analysis techniques, data structures, ML, infrastructure)
- Expanded `05-workflows.md` with multi-protector devirtualisation flow, trace collection & export examples, CLI export usage, RE tool plugin installation, ML training workflow
- Updated CHANGELOG with B104–B108 entries

### Phase 11 — Devirtualisation Pipeline Completion (10 commits)

Phase 11 implements the full VMProtect devirtualisation pipeline end-to-end,
addressing all 10 gaps identified in the deep audit (rated 4.5/10 → target 9.0/10).
Test count: **541 → 831** (290 new tests, 7 skipped).

#### Batch 1 — x86 Instruction Handlers + Operand-Size EFLAGS (`6ccf453`)
- 45+ instruction handlers (ADC, SBB, IMUL, DIV, BSF, BT, SETcc, CMOVcc, MOVZX/SX, etc.)
- Operand-size–aware EFLAGS updates (SF uses correct sign bit for 8/16/32/64-bit)
- `_HANDLER_TABLE` dispatch dict for O(1) instruction lookup
- 70 new tests

#### Batch 2 — Symbolic Handler Classification (`8a56541`)
- Expression pattern-matching in `handler_semantics.py` for z3 symbolic expressions
- Classifies handlers by inspecting symbolic output expressions (XOR → vXor, ADD → vAdd, etc.)
- `_classify_by_expression()` with z3 structural matching
- 22 new tests

#### Batch 3 — Bytecode Extraction Fix (`09d542f`)
- `bytecode_extract.py` reads real bytes via `ParsedBinary.read_va()` instead of placeholders
- 13 new tests

#### Batch 4 — Pipeline + Dispatcher Wiring (`7243f14`)
- `devirtualize` stage in `pipeline.py` chains: discover → semantics → pseudocode
- `DispatcherAnalyzer` integrated with trace-based handler identification
- 10 new tests

#### Batch 5 — Opaque Predicate Detection (`a325ac1`)
- Path-context–aware opaque predicate analysis in `solver.py`
- Arithmetic patterns (`x*(x-1) & 1 == 0`, `x^x == 0`, etc.)
- 20 new tests

#### Batch 6 — Pseudocode Operand Widths (`0b00ce1`)
- Width-qualified casts: `*(DWORD*)(addr)` for LOAD/STORE operations
- Per-variable type declarations in C-like output (`uint32_t`, `uint8_t`, etc.)
- `_WIDTH_CAST`, `_WIDTH_TYPE` dictionaries; `PseudocodeResult.var_widths`
- 28 new tests

#### Batch 7 — Symbolic Memory Aliasing (`d377795`)
- `AliasResult` (MUST/MAY/NO) for symbolic address aliasing queries
- z3-powered `query_alias()` with `_try_concretise()` uniqueness check
- Symbolic store forwarding: `_forward_from_symbolic_store()` searches most-recent stores
- `read_memory()` / `write_memory()` rewritten for symbolic address support
- 31 new tests

#### Batch 8 — Cross-Handler Data-Flow (`f9d2b20`)
- New module `analysis/dataflow.py`: `VarDef`, `VarUse`, `LiveRange`, `PhiNode`, `DataFlowResult`
- `_StackTracker` models abstract VM stack across handlers
- `compute_data_flow()`: reaching definitions, dead variables, live ranges
- `_compute_phi_nodes()` at CFG merge points (networkx)
- `eliminate_dead_vars()`: textual pass removing dead assignments
- 27 new tests

#### Batch 9 — Multi-Handler Integration Tests (`ac5dc36`)
- Synthetic 4-handler VMProtect trace (vPush + vPush + vAdd + vLoad)
- End-to-end tests: trace ingestion → semantics → pseudocode → data-flow → pipeline
- 17 new tests

#### Batch 10 — MBA Deep Canonicalization (`dd1a612`)
- **Linear MBA decomposition**: corner-point evaluation extracts minterm coefficients (1–4 variables)
- Coefficient signature lookup tables for 20 common 2-variable operations + 5 single-variable
- `_build_minterm_sum()` fallback for 3+ variable reconstruction
- `_simplify_children()`: bottom-up z3 sub-expression simplification
- `simplify_expr_deep()`: iterative fixed-point combining 4 techniques (sub-expr → rules → linear MBA → z3)
- `_ast_size()` cost model for preferring smaller expressions
- Non-linear expression rejection via SHA-512–derived probe values
- `MBAResult.iterations` field tracks convergence rounds
- 52 new tests

#### Batch 11 — Documentation Refresh
- Rewrote `01-architecture.md` from 3-line placeholder to full architecture doc
- Rewrote `02-getting-started.md` with install, quick-start, and configuration
- Rewrote `00-overview.md` to describe actual capabilities (removed phantom modules)
- Updated `03-modules.md` with all Phase 10–11 modules (removed phantom `enterprise/`)
- Fixed `05-workflows.md` (removed 8 phantom file references, added real module paths)
- Fixed `Home.md` (removed links to non-existent `07-plugins.md`, `09-testing-and-quality.md`)
- Updated CHANGELOG with Phase 11 entries

### Phase 10 — Core Engine Hardening (7 commits)

Phase 10 addresses the top-7 critical gaps identified by an expert
audit, transforming the symbolic execution engine and analysis pipeline
from proof-of-concept quality into production-ready components.
Test count: **430 → 541** (111 new tests, 7 skipped).

#### New — Sub-Register Aliasing + SIB Addressing (`analysis.symbolic_execution`)
- **Full x86-64 sub-register model** — `_SUBREG_MAP_64`/`_SUBREG_MAP_32` lookup tables map
  every sub-register (al/ah/ax/eax, r8b/r8w/r8d, sil/dil/bpl/spl) to `(parent, bit_lo, width, zero_ext)` tuples (`6a10bec`)
- `get_register()` uses z3.Extract for symbolic reads, bit masking for concrete
- `set_register()` with zero-extension for 32-bit writes on x64 (x86-64 ABI)
- **SIB tokenizer** — `_resolve_sib_address()` parses full `[base+index*scale+disp]` addressing modes via regex tokenizer + arithmetic evaluator that promotes to z3 when any operand is symbolic
- Rewrote `_resolve_operand()`, `_write_operand()`, `_resolve_effective_address()` to use new sub-register + SIB infrastructure
- 40 new tests (22 sub-register, 9 SIB, 9 integration)

#### New — Byte-Granular Memory Model (`analysis.symbolic_execution.state`)
- Replaced single-slot `Dict[int, Any]` with **byte-addressable store** (`4a8cd77`)
- `write_memory(addr, val, size)` splits into individual bytes (little-endian)
- `read_memory(addr, size)` coalesces bytes into int or z3.Concat for symbolic
- `_resolve_operand_sized()` for size-prefixed memory reads (`byte ptr`, `word ptr`, etc.)
- Legacy fast-path preserved for backwards compatibility
- 12 new memory tests (concrete, symbolic, overlap, fork)

#### New — VA ↔ File-Offset Mapping (`analysis.binary_format`)
- `section_at_va()`, `va_to_offset()`, `offset_to_va()` for PE/ELF section-based address translation (`d933de1`)
- `load_sections(data)` returns `{va: bytes}` memory map
- `read_va(data, va, size)` reads bytes at any virtual address
- 11 new tests (VA mapping, roundtrips, load, edge cases)

#### New — Built-in Unicorn Trace Engine (`analysis.trace_engine`) — P0
- `TraceEngine` class wraps Unicorn for x86/x86-64 emulation (`954d03e`)
- `trace(data, entry_va)` → `ExecutionTrace` with instructions, memory accesses, and control flow
- `trace_parsed(parsed_binary, data)` integrates with ParsedBinary metadata
- `TraceConfig` for max_instructions, register/memory capture, stop_addresses
- Auto-maps unmapped memory, Capstone disassembly integration
- 18 new tests (64-bit, 32-bit, config, parsed binary, pipeline)

#### Fixed — INC/DEC Carry Flag Preservation (`analysis.symbolic_execution.state`)
- `update_flags_inc_dec()` now saves/restores CF before/after `update_flags_arith()` (`24fcf6b`)
- Cleaned up executor's inline workaround
- 4 new tests (concrete CF, ZF+CF, executor integration)

#### New — Symbolic vIP Identification (`analysis.vm_discovery.handler_boundaries`)
- `score_vip_from_symbolic()` analyzes `HandlerSymbolicSummary.final_registers` to detect which `in_{reg}` symbol self-advances (vIP pattern) (`d473d91`)
- `identify_vip_register()` gains `symbolic_summaries` parameter; when provided, symbolic self-advance score blended in at 0.30 weight
- `VIPCandidate.symbolic_score` field added
- 13 new tests (9 standalone symbolic + 4 integration)

#### Enhanced — MBA Rewrite Rules (`analysis.mba_simplifier`)
- Expanded from 16 → 31 proven rules: 21 two-variable + 10 three-variable (`e2aab65`)
- New 2-var rules: De Morgan (nor/nand), `or_and_to_add`, complement constants, `complement_to_neg`, `and_xor_or_to_xor`, `xor_xor_and_to_or`
- New 3-var rules: `or_xor_to_and ± w`, `or_and ± w`, `neg_add_3`
- 14 new proven tests

#### Test Suite
- **541 tests** (541 pass, 7 skip — yara-python only)
- New test files: `test_phase10_subreg_sib`, `test_trace_engine`, `test_symbolic_vip`
- Enhanced: `test_binary_format`, `test_mba_simplifier`
- Trajectory: 430 (Phase 9 end) → 470 → 481 → 492 → 510 → 514 → 527 → 541

---

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
