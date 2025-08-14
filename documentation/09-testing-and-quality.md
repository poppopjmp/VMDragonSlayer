# Testing & Quality

This page outlines how to run tests, measure coverage, lint the codebase, and enforce security/quality gates using the utilities under `tools/`.

## Test layout and markers

- Tests live under `tests/` with subfolders like `unit/`.
- Common fixtures: see `tests/conftest.py` (`temp_dir`, `sample_config`, `sample_bytecode`, model mocks, helpers to create mock files/models).
- Markers defined: `slow`, `ml`, `integration`, `gpu` (use with `-m`).

Examples:

```pwsh
# Run all tests
pytest

# Unit tests only
pytest tests/unit

# Skip slow tests
pytest -m "not slow"

# Run only ML tests
pytest -m ml
```

## Coverage

Generate coverage and produce Cobertura XML under `evidence/coverage.xml` for CI gates:

```pwsh
pytest --cov=dragonslayer --cov-report=term --cov-report=xml:evidence/coverage.xml
```

Gate thresholds (enforced by `tools/coverage_gate.py`):
- Validated-scope line coverage ≥ 0.85 (core + key analysis modules)
- Core branch coverage ≥ 0.90

Run the gate:

```pwsh
python tools/coverage_gate.py
```

## Linters and type checks

Ruff and MyPy are configured in `pyproject.toml`.

```pwsh
ruff check dragonslayer
mypy dragonslayer
```

Optional: Black/Isort formatting (configured in `pyproject.toml`).

## Security scans

Static analysis and dependency scans:

```pwsh
# Bandit security checks
bandit -r dragonslayer -f xml -o evidence/bandit.xml
python tools/bandit_gate.py

# Dependency vulnerabilities
pip-audit -f json -o evidence/pip_audit.json
python tools/pip_audit_gate.py
```

## Schema validation

Validate JSON artifacts (results, pattern DBs) against schemas (draft-07):

```pwsh
python -m tools.schema_validate "artifacts/results/*.json" "data/schemas/analysis_result_schema.json" --out evidence/schema_validation.json
python tools/schema_validate.py "data/patterns/*.json" "data/schemas/pattern_database_schema.json"
```

## Determinism and regression checks

Ensure analysis outputs are stable for identical inputs:

```pwsh
python tools/determinism_runner.py --analysis vm_discovery --size 2048 --seed 42 --out evidence/determinism_report.json
```

Compare pattern candidates with external tool exports:

```pwsh
python tools/pattern_diff_testing.py --ours artifacts/patterns/ours.json `
	--external ghidra=artifacts/ghidra/patterns.json `
	--external ida=artifacts/ida/patterns.json
```

## Evidence collection

Bundle common artifacts and environment info:

```pwsh
python tools/evidence_pack.py --out evidence
```

## CI tips

- Keep `evidence/` artifacts between jobs to allow gates to run without rework.
- Use markers and `-m "not slow"` to keep PR runs fast; run full suites on main/nightly.
- See `BUILD_PLUGINS.md` for extended CI/release flows.
