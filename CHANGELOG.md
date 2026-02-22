# Changelog

All notable changes to VMDragonSlayer are documented here.

## [Unreleased] — dev-0.9.1

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

