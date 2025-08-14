# CLI and Tools

Utilities in `tools/` support quality gates, evidence collection, validation, and analysis workflows. Below are the core scripts, their purpose, key flags, inputs/outputs, and example usage.

## Evidence and Gates

- `tools/evidence_pack.py`
	- Purpose: Collect common artifacts (configs, logs, reports, `evidence/*`) into a manifest and write environment info.
	- Flags: `--out <dir>` (default: `evidence`).
	- Writes: `<out>/ENVIRONMENT.txt`, `<out>/manifest.json`.
	- Example (PowerShell):
		```pwsh
		python tools/evidence_pack.py --out evidence
		```

- `tools/coverage_gate.py`
	- Purpose: Enforce minimum coverage thresholds from `evidence/coverage.xml` (Cobertura XML). Validates scoped line coverage for analysis modules and branch coverage for `dragonslayer/core`.
	- Thresholds: validated-scope line rate >= 0.85; core branch rate >= 0.90.
	- Exit codes: 0 on pass; 1 on failure; prints rates and failures to STDERR.
	- Example:
		```pwsh
		python tools/coverage_gate.py
		```

- `tools/bandit_gate.py`
	- Purpose: Fail the build if Bandit report (`evidence/bandit.xml`) contains HIGH or CRITICAL severities.
	- Exit codes: 0 on pass; 1 on failure.
	- Example:
		```pwsh
		python tools/bandit_gate.py
		```

- `tools/pip_audit_gate.py`
	- Purpose: Fail if `evidence/pip_audit.json` contains any HIGH or CRITICAL vulnerabilities.
	- Exit codes: 0 on pass; 1 on failure.
	- Example:
		```pwsh
		python tools/pip_audit_gate.py
		```

## Schema Validation

- `tools/schema_validate.py`
	- Purpose: Validate JSON artifacts (results, pattern DBs) against one or more JSON Schemas.
	- Modes: supports flag-style (`--targets`, `--schemas`) and positional (`<artifacts_glob> <schemas_glob>`). Writes a report to `--out`.
	- Common patterns:
		- Validate result artifacts against the analysis schema:
			```pwsh
			python -m tools.schema_validate "artifacts/results/*.json" "data/schemas/analysis_result_schema.json" --out evidence/schema_validation.json
			```
		- Validate pattern databases (dev and prod) against the pattern DB schema:
			```pwsh
			python tools/schema_validate.py "data/patterns/*.json" "data/schemas/pattern_database_schema.json"
			```

## Determinism & Differential Testing

- `tools/determinism_runner.py`
	- Purpose: Run the orchestrator multiple times on the same synthetic input to ensure outputs are deterministic (after removing timestamps), then compare digests.
	- Flags: `--analysis <vm_discovery|pattern_analysis|...>` (default `vm_discovery`), `--size <bytes>` (default 1024), `--seed <int>` (default 123), `--out <path>` (default `evidence/determinism_report.json`).
	- Exit: 0 if all runs match; 1 if any mismatch. Writes a JSON report with the per-run digests.
	- Example:
		```pwsh
		python tools/determinism_runner.py --analysis vm_discovery --size 2048 --seed 42
		```

- `tools/pattern_diff_testing.py`
	- Purpose: Compare our pattern candidates against exports from external tools (Ghidra, IDA, Binary Ninja) and summarize overlaps and discrepancies.
	- Flags: `--ours <path>` (default `artifacts/patterns/ours.json`); repeatable `--external name=path.json`; `--reports-dir <dir>` (default `reports`).
	- Output: `reports/pattern_diff_summary.md` with overall overlap metrics and per-sample discrepancies.
	- Example:
		```pwsh
		python tools/pattern_diff_testing.py --ours artifacts/patterns/ours.json `
			--external ghidra=artifacts/ghidra/patterns.json `
			--external ida=artifacts/ida/patterns.json
		```

## Dataset/Model Ops

- `data/models/model_registry_config.toml`
	- Defines the SQLite schema for model tracking and a bootstrap list of default models. See Data & Models for details.

## VM Detection Validation

- `tools/validate_vm_detection.py`
	- Purpose: Score predictions against a labeled registry and emit metrics plus an optional confusion matrix figure.
	- Inputs: `--registry` (default `data/samples/sample_registry.json`), `--predictions-dir` (default `artifacts/vm_detection/`, files named by sample hash containing `vm_detected` and optional `confidence`).
	- Outputs: `--reports-dir` (default `reports`): `vm_detect_metrics.json` and `confusion_matrix.png` if matplotlib is available.
	- Acceptance Gate: passes if precision and recall are both ≥ 0.95; reports class balance and missing predictions.
	- Example:
		```pwsh
		python tools/validate_vm_detection.py --registry data/samples/sample_registry.json `
			--predictions-dir artifacts/vm_detection --reports-dir reports
		```

## Licenses

- `tools/add_license_headers.py`
	- Purpose: Insert GPL license header comments into Python (and plugin Java) sources.
	- Flags: `--apply` to write changes, `--check` to exit non-zero if any file is missing a header, `--include-tests` to cover tests/.
	- Behavior: Reads `LICENSE-HEADER.txt`; preserves shebangs; skips files already containing the marker; avoids venv/build artifacts.
	- Examples:
		```pwsh
		# Dry-run and report how many files would change
		python tools/add_license_headers.py

		# Apply changes
		python tools/add_license_headers.py --apply

		# CI check mode
		python tools/add_license_headers.py --check
		```

## Notes

- All examples assume PowerShell on Windows. Adjust quoting for other shells as needed.
- Many tools read from or write to `evidence/` and `reports/`; ensure those directories exist or let the tools create them.
