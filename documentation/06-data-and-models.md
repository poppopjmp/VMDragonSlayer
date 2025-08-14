# Data & Models

This page explains the data artifacts shipped with the repo: machine-readable schemas, the model registry, and training datasets/configuration. It also points to the validation utilities to keep these artifacts healthy over time.

## Layout

- `data/schemas/`
	- `analysis_result_schema.json` — JSON Schema for analysis results produced by the orchestrator and engines.
	- `pattern_database_schema.json` — JSON Schema for the pattern database consumed by pattern analysis.
- `data/models/`
	- `model_registry_config.toml` — DDL and bootstrap entries for the on-disk SQLite registry.
	- `pretrained/` — default model binaries (excluded from packaging by `pyproject.toml`).
	- `metadata/` — optional metadata, versioning notes.
- `data/training/`
	- `training_config.json` — datasets, feature extractors, model/ensemble configs, evaluation, tuning, and augmentation knobs.
- `data/patterns/`
	- `pattern_database.json`/`pattern_database_dev.json` — pattern DBs that should validate against the schema above.

## Analysis Result Schema (`data/schemas/analysis_result_schema.json`)

Contract for structured results persisted/emitted by analyses:

- Top-level (required): `analysis_id` (UUIDv4), `timestamp` (ISO 8601), `file_info`, `analysis_type`, `status`, `results`.
- `analysis_type` enum: `vm_discovery | pattern_analysis | taint_tracking | symbolic_execution | hybrid | batch`.
- `status` enum: `completed | failed | timeout | partial`.
- `file_info`: filename, size, hashes (`md5`, `sha1`, `sha256`), optional `file_type`, `entropy [0..8]`.
- `results`: may include per-engine sections:
	- `vm_detection`: `is_vm_protected` (bool), `confidence [0..1]`, `vm_type` enum (`vmprotect | themida | custom | unknown`), version, handler/region stats.
	- `pattern_analysis`: `patterns_found` list with `pattern_id`, `pattern_name`, `confidence`, and `locations` (address/size); optional `classification` summary with features used.
	- `taint_tracking`: `handlers_analyzed`, and `taint_flows` each with `source`, `sink`, `path` details.
	- `symbolic_execution`: path exploration results, constraints, coverage metrics.

Notes:

- `$schema` is draft-07; `$id` is a stable URI for cross-references.
- Numeric confidences are bounded to `[0,1]`; sizes are non-negative.
- Use the Schema Validation tool (see CLI section) to enforce this contract on produced artifacts.

## Pattern Database Schema (`data/schemas/pattern_database_schema.json`)

Describes the structure of the pattern knowledge base used by the `pattern_analysis` engine:

- Required: `version` (SemVer `x.y.z`) and `categories`.
- `categories` is a map keyed by `[A-Za-z_][A-Za-z0-9_]*` with:
	- `description` (free text).
	- `patterns`[] with required fields: `id` (identifier), `name`, `type`, and `confidence [0..1]`.
	- Optional per-pattern fields: `bytecode_signature`, `handler_patterns`[], `assembly_patterns`[], `description`, `variants`[], `frequency [0..1]`, `vm_family`, `version`, `evasion_type`, `indicators`[].
- Optional `statistics` block: totals, confidence distribution, accuracy, last training size.
- Optional `metadata`: `source`, `validation_method`, sample counts, `cross_validation_score`.

This schema supports both curated knowledge and empirically derived metrics, while keeping the core identification fields strict.

## Model Registry (`data/models/model_registry_config.toml`)

A self-describing SQLite registry for models and their lifecycle. The TOML defines DDL for tables and a set of default models to bootstrap:

- Tables and purpose:
	- `model_registry` — authoritative records for each model: `model_id` (unique), `model_name`, `model_type` (`classifier|detector|ensemble`), `version`, `file_path`, size/hashes, perf summaries, `training_config`/`metadata` JSON blobs, `status` (`active|deprecated|testing`).
	- `model_performance` — per-test metrics: dataset size, accuracy, precision/recall/F1, inference time, memory, plus `test_config` JSON.
	- `training_history` — runs with timing, epochs, final loss/accuracy, early stopping flags, logs path, status/error.
	- `model_versions` — model lineage and release management: `(model_name, version)` unique, pointer to `model_id`, parent, `is_current`, change notes.
- Initialization set (`[initialization].default_models`):
	- `bytecode_classifier_v1` → `data/models/pretrained/bytecode_classifier_v1.pkl`.
	- `vm_detector_v1` → `data/models/pretrained/vm_detector_v1.pkl`.
	- `handler_classifier_v1` → `data/models/pretrained/handler_classifier_v1.pkl`.

Operational tips:

- Keep large binaries out of the sdist/wheel; packaging excludes `data/models/pretrained/*` in `pyproject.toml`.
- When adding a new model, register it here and record `training_history` and `model_performance` rows to preserve provenance.

## Training Configuration (`data/training/training_config.json`)

End-to-end configuration for datasets, features, models, ensembling, and evaluation:

- `training_datasets` — three built-in dataset specs:
	- `bytecode_classification` — 50k samples, 256 features, class distribution across common VM ops; 20% validation, 10% test; preprocessing via `standard_scaler` and `select_k_best (k=200)`.
	- `vm_detection` — 20k samples, 128 features; 20% validation, 15% test; min-max scaling.
	- `handler_classification` — 35k samples, 512 features; robust scaler + RFE (`k_features=300`).
- `feature_extractors` — `opcode_ngrams` (n=[1,2,3], max_features=1000, df thresholds), `structural_features` (blocks/branches/complexity), `byte_histogram` (bins=256), `entropy_features` (window sizes, local entropy).
- `model_configurations` — `random_forest_classifier`, `gradient_boosting_classifier`, `svm_classifier`, `neural_network_classifier` with sensible defaults.
- `ensemble_configurations` — `voting_classifier` (soft voting with weights) and `stacking_classifier` (meta-model = NN).
- `evaluation_metrics` — macro/weighted metrics and ROC AUC with CV options (stratified, shuffled, seeded).
- `hyperparameter_tuning` — grid search with per-model grids; `cv_folds`, `scoring`, `n_jobs`.
- `data_augmentation` — opt-in techniques and parameters.

## Validation & QA

- Use `tools/schema_validate.py` to validate result artifacts and pattern DBs against schemas. It supports both flag-style and positional arguments and writes a JSON report under `evidence/`.
- The `tools/coverage_gate.py`, `tools/bandit_gate.py`, and `tools/pip_audit_gate.py` scripts read files under `evidence/` to enforce quality/security gates in CI.

## Compatibility

- Schemas follow JSON Schema draft-07.
- Hash formats: `md5` (32 hex), `sha1` (40 hex), `sha256` (64 hex).
- Versions: SemVer `x.y.z`.

If any schema evolves, update the `$id` or version sections and run schema validation across all stored artifacts before merging.
