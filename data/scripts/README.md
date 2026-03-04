# VMDragonSlayer Data Pipeline Scripts

This directory contains automated scripts for the complete data pipeline, from model training to deployment and maintenance.

## Scripts Overview

### 1. `train_models.py` - Automated Model Training Pipeline

Comprehensive pipeline for training VM detection models with automated data loading, feature extraction, model training, and validation.

#### Features:
- **Multi-source Data Loading**: Directory structures, CSV files, JSON manifests
- **Advanced Feature Extraction**: File statistics, entropy analysis, byte distribution, n-grams, opcode patterns
- **Multiple Model Support**: Random Forest, Gradient Boosting, Neural Networks, SVM
- **Cross-Validation**: K-fold cross-validation with stratified sampling
- **Feature Caching**: Persistent caching of extracted features for faster subsequent runs
- **Comprehensive Evaluation**: Classification reports, confusion matrices, performance metrics

#### Usage:
```bash
# Basic training with configuration file
python data/scripts/train_models.py --config data/training/training_config.json --output models/

# Training with cross-validation
python data/scripts/train_models.py --config data/training/training_config.json --output models/ --cross-validate

# Verbose logging for debugging
python data/scripts/train_models.py --config data/training/training_config.json --output models/ --verbose
```

#### Configuration:
The training script uses a JSON configuration file with the following sections:

```json
{
  "data": {
    "data_sources": [
      {
        "type": "directory",
        "path": "data/samples",
        "description": "Labeled binary samples"
      }
    ]
  },
  "features": {
    "feature_types": ["file_stats", "entropy", "byte_distribution", "ngrams", "opcodes"],
    "cache_features": true,
    "cache_dir": "data/feature_cache"
  },
  "training": {
    "test_size": 0.2,
    "models": {
      "random_forest": {
        "type": "random_forest",
        "parameters": {"n_estimators": 100, "max_depth": 20}
      }
    }
  },
  "validation": {
    "n_folds": 5,
    "metrics": ["accuracy", "precision", "recall", "f1_score"]
  }
}
```

### 2. `validate_patterns.py` - Pattern Database Validation

Validates pattern database integrity, schema compliance, and pattern quality for VM detection signatures.

#### Features:
- **Schema Validation**: JSON Schema compliance checking
- **Pattern Quality Assessment**: Confidence scores, coverage analysis, duplicate detection
- **Signature Validation**: Format checking for bytes, regex, YARA, opcode patterns
- **Coverage Analysis**: Category and type distribution analysis
- **False Positive Risk Assessment**: Pattern reliability evaluation

#### Usage:
```bash
# Validate patterns with schema
python data/scripts/validate_patterns.py data/patterns/pattern_database.json --schema data/schemas/pattern_database_validation_schema.json

# Create default schema file
python data/scripts/validate_patterns.py --create-schema --output-schema my_schema.json

# Verbose validation with detailed output
python data/scripts/validate_patterns.py data/patterns/pattern_database.json --verbose
```

#### Validation Features:
- **Structure Validation**: Required fields, data types, format compliance
- **Content Validation**: Pattern syntax, confidence scores, category coverage
- **Quality Metrics**: Pattern effectiveness, false positive risk, performance impact
- **Comprehensive Reporting**: Detailed error and warning messages

### 3. `model_versioning.py` - Model Registry and Version Management

Advanced model lifecycle management with version control, lineage tracking, and performance monitoring.

#### Features:
- **Model Registry**: Centralized model metadata and versioning
- **Git Integration**: Automatic version control with commit tracking
- **Lineage Tracking**: Parent-child relationships, ensemble components
- **Performance History**: Metrics tracking over time with benchmarking
- **Automated Backup**: Database backup with configurable retention

#### Usage:
```bash
# Register a new model
python data/scripts/model_versioning.py register --name "VM_Classifier_v2" --type classifier --path models/vm_classifier.joblib --accuracy 0.92

# List all models
python data/scripts/model_versioning.py list

# Get detailed model information
python data/scripts/model_versioning.py info vm_classifier_20250101_120000

# Update model performance metrics
python data/scripts/model_versioning.py update-performance vm_classifier_20250101_120000 --accuracy 0.94 --precision 0.91 --recall 0.90

# Create new model version
python data/scripts/model_versioning.py create-version vm_classifier_20250101_120000 2.1.0 --changelog "Improved feature extraction"

# Deprecate old model
python data/scripts/model_versioning.py deprecate old_model_id --replacement new_model_id

# Backup registry
python data/scripts/model_versioning.py backup
```

## Data Pipeline Configuration

### Model Registry Configuration (`data/models/model_registry_config.toml`)

Comprehensive configuration for model versioning and tracking:

```toml
[database]
type = "sqlite"
path = "data/models/model_registry.db"

[version_control_system]
enabled = true
git_backend = true
auto_commit = true
branch_strategy = "feature_branch"

[model_lineage_tracking]
enabled = true
track_parent_models = true
track_training_data = true

[performance_metrics_history]
enabled = true
retention_days = 365
performance_thresholds = {
    accuracy = 0.85,
    precision = 0.80,
    recall = 0.80,
    f1_score = 0.80
}
```

### Pattern Database Schema (`data/schemas/pattern_database_validation_schema.json`)

JSON Schema for pattern validation with comprehensive rules:

- **Pattern Structure**: ID, name, type, category, signature, confidence
- **Signature Types**: bytes, regex, YARA, opcode, structural, behavioral
- **Metadata Fields**: references, tags, VM families, performance impact
- **Quality Metrics**: confidence scores, false positive risk, severity levels

## Integration Workflow

### Complete Training Pipeline

1. **Data Preparation**: Organize samples in directory structure or create manifest files
2. **Configuration**: Set up training configuration with desired models and features
3. **Feature Extraction**: Run automated feature extraction with caching
4. **Model Training**: Train multiple models with cross-validation
5. **Model Registration**: Register trained models in version control system
6. **Performance Tracking**: Monitor model performance over time
7. **Pattern Validation**: Validate detection patterns for quality and coverage

### Example Complete Workflow:

```bash
# 1. Train models with cross-validation
python data/scripts/train_models.py \
    --config data/training/training_config.json \
    --output models/vm_detection_v2 \
    --cross-validate

# 2. Register best performing model
python data/scripts/model_versioning.py register \
    --name "VM_Detection_RF_v2" \
    --type classifier \
    --path models/vm_detection_v2/random_forest_model.joblib \
    --accuracy 0.94

# 3. Validate pattern database
python data/scripts/validate_patterns.py \
    data/patterns/pattern_database.json \
    --schema data/schemas/pattern_database_validation_schema.json

# 4. Update performance metrics after deployment
python data/scripts/model_versioning.py update-performance \
    vm_detection_rf_v2_20250101_120000 \
    --accuracy 0.93 \
    --precision 0.92 \
    --recall 0.91 \
    --f1 0.92
```

## Advanced Features

### Automated Feature Engineering

The training pipeline includes sophisticated feature extraction:

- **File Statistics**: Size, entropy, byte distributions
- **Structural Features**: PE sections, import tables, export tables  
- **Behavioral Patterns**: API call sequences, control flow graphs
- **Opcode Analysis**: Instruction pattern recognition
- **N-gram Analysis**: Byte and instruction sequence analysis

### Model Ensemble Support

Support for ensemble models with lineage tracking:

- **Voting Classifiers**: Hard and soft voting across multiple models
- **Stacking Ensembles**: Meta-learners trained on base model predictions
- **Boosting Ensembles**: Sequential model improvement
- **Lineage Tracking**: Parent-child relationships in ensemble construction

### Performance Monitoring

Comprehensive performance tracking and alerting:

- **Real-time Metrics**: Accuracy, precision, recall, F1-score tracking
- **Drift Detection**: Model performance degradation alerts
- **A/B Testing**: Comparative model performance evaluation
- **Benchmark Datasets**: Consistent evaluation across model versions

## Troubleshooting

### Common Issues:

1. **Memory Issues**: Large datasets may require feature selection or chunked processing
2. **Git Integration**: Ensure Git is installed and configured for version control
3. **Permission Errors**: Check file permissions for model and data directories
4. **Schema Validation**: Install jsonschema package for pattern validation

### Debug Options:

- Use `--verbose` flag for detailed logging
- Check feature cache directory for extraction issues  
- Validate configuration files before running pipelines
- Monitor database integrity with backup verification

## Dependencies

Required Python packages:
- numpy, pandas, scikit-learn
- joblib (model serialization)
- toml (configuration files)
- jsonschema (validation)
- sqlite3 (model registry)
- git (version control)

Install with:
```bash
pip install numpy pandas scikit-learn joblib toml jsonschema
```
