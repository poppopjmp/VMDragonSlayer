# Changelog

All notable changes to VMDragonSlayer are documented here.

## [Unreleased] — dev-0.9.1

### Dynamic backends wired + devirt pipeline runs end-to-end

Got the dynamic-analysis backends working and made the orchestrated
devirtualization pipeline produce real output on a compiled VM binary.

- **Triton** (3 real bugs fixed): the `lief.ELF.ELF_CLASS` arch check used a
  removed LIEF API; code was loaded only from sections (so section-less /
  packed binaries mapped no code) → added PT_LOAD segment fallback; and
  `processing()` now returns an `EXCEPTION` code (`NO_FAULT == 0` on success)
  so the old `if not processing()` broke after the first instruction. Triton
  now executes and its trace ingests into the pipeline.
- **angr**: verified wired — loads the binary, recovers functions/CFG and
  explores handler targets supplied by `vm_discovery`.
- **qiling**: wired; requires a rootfs to emulate (the plugin reports this
  clearly). Operational requirement, not a code bug.
- **vIP fallback (b)**: `step_segment_handlers` now derives a dispatch anchor
  from the trace's most-revisited addresses when no dispatcher is detected,
  so non-jump-table interpreters can still be segmented and devirtualised.
- **Devirt pipeline trace-typing fixes**: several stages passed an
  `ExecutionTrace` where a list of trace records was expected
  (`find_dispatcher`, `extract_handler_bodies`, `identify_vm_context`,
  the decryptors, `cluster_handlers_by_semantics`). These were latent (the
  trace was always `None` before) and surfaced once the built-in trace
  fallback populated it; all normalised. The CLI
  `analyze --type vmprotect_devirt` now succeeds end-to-end (recovers the
  vIP, opcode table, and emits pseudocode).
- **Jump-table fixture (a)**: `tests/fixtures/build_vm_sample_jumptable.py`
  builds a valid ELF whose VM uses `jmp [table + opcode*8]` dispatch — the
  canonical shape `find_dispatcher` targets (now covered by an e2e test).
- **Tests/CI**: added `tests/test_e2e_dynamic_backends.py` (jump-table
  detection, full devirt pipeline, Triton, angr); the `emulation` CI job runs
  both e2e suites.


### End-to-end emulation/devirtualization wiring + fixture

Made the dynamic-analysis path actually run end to end and proved it on a
real compiled binary.

- **Built-in trace fallback**: `devirt_stages.step_ingest_trace` now falls
  back to the built-in Unicorn `TraceEngine` (parsing the binary for its
  entry point) when no dynamic-analysis plugin supplied a trace. Previously
  the devirt pipeline produced empty output unless Qiling/Triton/angr were
  installed.
- **Dispatcher input fix**: `step_identify_dispatcher` passed a whole
  `ExecutionTrace` to `find_dispatcher` (which expects a list of trace-record
  dicts and calls `len()`), crashing once a trace was actually present. Now
  normalised to records.
- **Test fixture**: added `tests/fixtures/build_vm_sample.py` — generates a
  valid x86-64 ELF containing a real fetch→decode→dispatch bytecode VM
  (no real protector/malware) — plus `tests/test_e2e_vm_sample.py`, which
  drives the Unicorn engine over it and asserts the trace executes, the vIP
  (`rsi`) is recovered, handlers are segmented, and pseudocode is emitted.
- **CI**: new `emulation` job installs the Unicorn backend and runs the
  end-to-end test (the core `test` job can't, as it installs core deps only).
- **Dependency fix**: `triton-library>=1.0` was unsatisfiable (only
  `1.0.0rcN` wheels are published) → relaxed to `>=1.0.0rc4`.


### CI Green-Up: Test / Lint / Security Quality Gate

End-to-end pass to make the CI quality gate green and fix the issues it
surfaced.

- **Capstone compatibility (critical)**: `analysis/symbolic_execution/lifter.py`
  accessed `insn.detail`, which raises `AttributeError` on capstone ≥ 5.0.x
  bindings (the instruction exposes `regs_read`/`operands` directly and no
  longer has a `.detail` attribute). This broke the entire lift → symbolic
  execution → pseudocode path — **58 tests**. Reworked to read detail fields
  directly under a guarded `try`/`except`.
- **CV devirt classifier bug**: `analysis/cv_devirt.classify_cv_handler_entries`
  disassembled `max_insns * 15` bytes without stopping at the handler
  terminator, so trailing zero-padding (`00 00` → `add byte ptr [eax], al`)
  swamped the mnemonic histogram and mis-classified handlers (e.g. `xor` →
  `vm_add`). Now stops at the first `ret`/`jmp`/`iret` terminator.
- **Packaging**: added the missing top-level `dragonslayer/__init__.py`
  (the package previously imported as an implicit namespace package). This
  fixes the mypy "source file found twice" error and exposes
  `dragonslayer.__version__`. Reconciled the version to `0.9.1` across
  `pyproject.toml` and the package.
- **Security (SAST)**: tagged MD5/SHA-1 file-fingerprint hashes with
  `usedforsecurity=False` (`core/orchestrator.py` + plugin content hashes);
  annotated the trusted-model `pickle.load` with `# nosec B301`; documented
  intentional non-cryptographic `random` usage via per-file ignores. `bandit`
  now passes.
- **Lint**: cleared the full `ruff` rule set (`E,W,F,B,UP,SIM,I,C4,S`) —
  ~3,000 auto-fixed (PEP 585/604 typing, import sorting), plus manual fixes for
  `B904` exception chaining (35 sites), `F821` dangling annotations,
  `F841`/`B018` dead code, `B023` loop-variable closures, and `SIM`
  simplifications. Aligned `pyproject.toml`'s ruff `select` with the CI
  `--select` (added `SIM`).
- **Docs/policy**: populated the previously-empty `SECURITY.md` with a
  vulnerability-reporting process and analysis threat model.

### Dependency Audit + Intel PIN → Tracing Migration (`3d4fabf`)

Comprehensive dependency reconciliation and backend replacement to remove
the hard dependency on Intel PIN (not universally available).

- **`pyproject.toml`**: Removed unused core deps (`cryptography`, `psutil`); removed unused optional deps (`pandas`, `torch`, `tensorflow` from `[ml]`; `websockets`, `aiohttp`, `jinja2` from `[web]`; `graphene`, `schedule` from `[enterprise]`); added `qiling>=1.4.6` + `triton-library>=1.0` to `[emulation]`; added `requests>=2.31.0` to `[web]`; added new `[enrichment]` extra (`pyelftools`, `macholib`, `pefile`, `python-magic`, `ssdeep`, `oletools`, `binexport2`, `multidecoder`); added `elasticsearch>=8.0.0` to `[enterprise]`; updated `[all]`
- **`requirements.txt`**: Synced with pyproject.toml core deps; optional groups listed as comments
- **`config/vmdragonslayer.yml`**: Replaced `pin:` section with `tracing:` section — `backend: auto` (enum: `auto|unicorn|triton|angr|qiling|file`), `timeout`, `max_instructions`, `capture_registers/memory`, `trace_output_dir`, per-backend subsections
- **`config/analysis_profiles.json`**: Added `tracing_backend` preference per profile (fast→unicorn, deep/debug→auto/triton)
- **`dragonslayer/core/config.py`**: `DEFAULTS['pin']` → `DEFAULTS['tracing']`; env var `VMDS_PIN_PATH` → `VMDS_TRACING_BACKEND`; validation updated (backend enum check + timeout + max_instructions); `'pin'` kept in `known_sections` for backward compat
- **`data/schemas/config_schema.json`**: `pin` schema replaced with full `tracing` schema (backend enum, per-backend typed objects)
- **Tests `test_b64`, `test_b66`**: Updated env var and config key references

