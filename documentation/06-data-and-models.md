# Data & Models

This page explains the data artifacts and enhanced model capabilities shipped with the repo: machine-readable schemas, the extended model registry, training datasets, and validation utilities for maintaining data quality.

## Enhanced Data Layout

- **`data/schemas/`**
	- `analysis_result_schema.json` — Enhanced JSON Schema for unified analysis results
	- `pattern_database_schema.json` — Extended schema supporting metamorphic patterns
	- `pattern_database_validation_schema.json` — Validation rules for pattern integrity
- **`data/models/`**
	- `model_registry_config.toml` — Enhanced registry with ML ensemble support
	- `pretrained/` — Extended model collection with ensemble methods
	- `metadata/` — Model provenance and confidence metadata
- **`data/training/`**
	- `training_config.json` — Enhanced training configuration with adversarial resistance
- **`data/patterns/`**
	- `pattern_database.json` — Extended pattern database with metamorphic support
	- `pattern_database_dev.json` — Development patterns for testing

## Enhanced Analysis Result Schema (`data/schemas/analysis_result_schema.json`)

Extended contract for unified analysis results:

### Core Structure
- **Top-level (required)**: `analysis_id`, `timestamp`, `file_info`, `analysis_type`, `status`, `results`, `confidence_scores`
- **Enhanced `analysis_type`**: `unified | hybrid | extended_patterns | ml_detection | symbolic_execution | multi_arch | security_extensions | realtime`
- **Extended `status`**: `completed | failed | timeout | partial | streaming`

### Enhanced Results Structure
```json
{
  "results": {
    "vm_detection": {
      "is_vm_protected": true,
      "overall_confidence": 0.92,
      "vm_types": ["vmprotect_4x", "custom"],
      "architecture": ["x86", "x64"],
      "metamorphic_variants": 3,
      "evasion_techniques": ["anti_debug", "timing_checks"]
    },
    "extended_patterns": {
      "patterns_found": [
        {
          "pattern_id": "vmprotect_4x_control_flow",
          "confidence": 0.95,
          "metamorphic_variants": ["variant_a", "variant_b"],
          "locations": [{"address": "0x401000", "size": 64}]
        }
      ],
      "context_analysis": {...},
      "similarity_clusters": [...]
    },
    "ml_detection": {
      "ensemble_confidence": 0.87,
      "algorithm_results": {
        "random_forest": 0.89,
        "gradient_boosting": 0.85,
        "neural_network": 0.88
      },
      "feature_importance": {...},
      "adversarial_resistance": 0.92
    },
    "symbolic_execution": {
      "paths_explored": 156,
      "constraints_solved": 89,
      "vm_oracles_validated": 12,
      "coverage_metrics": {...}
    },
    "multi_arch_analysis": {
      "architectures_detected": ["x86", "x64", "arm"],
      "cross_platform_correlation": 0.91,
      "architecture_specific_patterns": {...}
    },
    "security_assessment": {
      "anti_analysis_techniques": [...],
      "stealth_analysis_required": false,
      "environment_normalization": {...}
    }
  },
  "confidence_scores": {
    "pattern_analysis": 0.95,
    "ml_detection": 0.87,
    "symbolic_validation": 0.92,
    "overall_confidence": 0.91
  }
}
```

## Enhanced Pattern Database Schema

Extended pattern database supporting advanced VM detection:

### Core Structure
```json
{
  "version": "2.1.0",
  "categories": {
    "extended_patterns": {
      "description": "Extended VM patterns with metamorphic support",
      "patterns": [
        {
          "id": "vmprotect_4x_extended",
          "name": "VMProtect 4.x Extended Pattern",
          "type": "metamorphic",
          "confidence": 0.95,
          "metamorphic_variants": [...],
          "context_patterns": [...],
          "architectural_requirements": ["x64"],
          "entropy_threshold": 7.0
        }
      ]
    }
  },
  "ml_models": {
    "ensemble_methods": [...],
    "feature_extractors": [...],
    "confidence_calibration": {...}
  }
}
```

## Extended Model Registry (`data/models/model_registry_config.toml`)

Enhanced SQLite registry supporting ML ensembles and advanced models:

### Enhanced Tables
- **`model_registry`** — Extended with ensemble support, confidence calibration, and adversarial resistance metrics
- **`ensemble_models`** — New table for managing ensemble method configurations  
- **`model_performance`** — Enhanced with multi-metric evaluation and confidence intervals
- **`confidence_calibration`** — New table for confidence score calibration data

### Extended Model Collection
```toml
[initialization.extended_models]
# Core ML Detection Models
ml_ensemble_v2 = "data/models/pretrained/ml_ensemble_v2.pkl"
adversarial_detector_v1 = "data/models/pretrained/adversarial_detector_v1.pkl"

# Extended Pattern Models  
metamorphic_classifier_v1 = "data/models/pretrained/metamorphic_classifier_v1.pkl"
context_analyzer_v1 = "data/models/pretrained/context_analyzer_v1.pkl"

# Symbolic Execution Models
constraint_solver_v1 = "data/models/pretrained/constraint_solver_v1.pkl"
vm_oracle_v1 = "data/models/pretrained/vm_oracle_v1.pkl"

# Multi-Architecture Models
cross_platform_detector_v1 = "data/models/pretrained/cross_platform_detector_v1.pkl"

# Security Models
anti_evasion_v1 = "data/models/pretrained/anti_evasion_v1.pkl"
stealth_analyzer_v1 = "data/models/pretrained/stealth_analyzer_v1.pkl"
```
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
