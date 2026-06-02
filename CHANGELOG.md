# Changelog

All notable changes to VMDragonSlayer are documented here.

## [Unreleased] — dev-0.9.1

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

