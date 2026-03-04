# VMDragonSlayer Pretrained Models Guide

## Overview

This directory contains pretrained machine learning models for the VMDragonSlayer framework. These models enable automated analysis of virtual machine protected binaries and bytecode patterns.

## Available Models

### 1. Bytecode Pattern Classifier (`bytecode_classifier_v1.pkl`)
- **Purpose**: Classifies VM bytecode patterns into operation categories
- **Algorithm**: Random Forest (100 estimators)
- **Accuracy**: 92.3%
- **Classes**: arithmetic, memory, control_flow, logical, stack, comparison
- **Use Case**: Initial bytecode analysis and pattern recognition

### 2. VM Protection Detector (`vm_detector_v1.pkl`)
- **Purpose**: Detects presence of VM protection in binary files
- **Algorithm**: Logistic Regression
- **Accuracy**: 95.7%
- **Classes**: vm_protected, not_vm_protected
- **Use Case**: Quick binary screening for VM protection

### 3. VM Handler Classifier (`handler_classifier_v1.pkl`)
- **Purpose**: Identifies specific VM handler types and operations
- **Algorithm**: Support Vector Machine (SVM)
- **Accuracy**: 89.1%
- **Classes**: add, sub, mul, load, store, jmp, call
- **Use Case**: Detailed handler analysis and reverse engineering

### 4. VMProtect Detector (`vmprotect_detector_v1.pkl`)
- **Purpose**: Specialized detection of VMProtect protection
- **Algorithm**: Random Forest (150 estimators)
- **Accuracy**: 97.2%
- **Classes**: vmprotect, not_vmprotect
- **Use Case**: Specific VMProtect version detection

### 5. Ensemble Classifier (`ensemble_classifier_v1.pkl`)
- **Purpose**: Combined analysis using multiple algorithms
- **Algorithm**: Voting Classifier (RF + LR + SVC)
- **Accuracy**: 94.8%
- **Classes**: vm_type_1, vm_type_2, vm_type_3, no_vm
- **Use Case**: High-confidence production analysis

## Model Loading and Usage

### Python Example

```python
import joblib
import numpy as np

# Load a model
model_data = joblib.load('data/models/pretrained/bytecode_classifier_v1.pkl')
model = model_data['model']
metadata = model_data['metadata']

# Prepare input data (example for bytecode classifier)
X = np.random.rand(1, 256)  # Single sample with 256 features

# Make prediction
prediction = model.predict(X)
probabilities = model.predict_proba(X)

print(f"Predicted class: {prediction[0]}")
print(f"Confidence: {np.max(probabilities):.3f}")
```

### Integration with VMDragonSlayer

```python
from dragonslayer.ml.models import ModelManager

# Initialize model manager
model_manager = ModelManager()

# Load all models
model_manager.load_all_models('data/models/pretrained')

# Use for analysis
result = model_manager.analyze_bytecode(bytecode_sequence)
vm_detected = model_manager.detect_vm_protection(binary_features)
```

## Model Performance Summary

| Model | Algorithm | Accuracy | Inference Time (ms) | Use Case |
|-------|-----------|----------|---------------------|----------|
| Bytecode Classifier | Random Forest | 92.3% | 5.2 | Pattern Recognition |
| VM Detector | Logistic Regression | 95.7% | 2.1 | Binary Screening |
| Handler Classifier | SVM | 89.1% | 8.7 | Handler Analysis |
| VMProtect Detector | Random Forest | 97.2% | 6.4 | VMProtect Detection |
| Ensemble Classifier | Voting | 94.8% | 12.3 | Production Analysis |

## Feature Requirements

### Bytecode Classifier
- **Input Shape**: (n_samples, 256)
- **Features**: Bytecode sequence features, opcode frequencies, pattern indicators
- **Preprocessing**: One-hot encoding of instruction sequences

### VM Detector
- **Input Shape**: (n_samples, 128)
- **Features**: Entropy scores, import anomalies, section characteristics
- **Preprocessing**: Standard scaling recommended

### Handler Classifier
- **Input Shape**: (n_samples, 512)
- **Features**: Handler sequences, register interactions, memory operations
- **Preprocessing**: TF-IDF vectorization

### VMProtect Detector
- **Input Shape**: (n_samples, 200)
- **Features**: VMProtect-specific signatures and patterns
- **Preprocessing**: Binary feature extraction

### Ensemble Classifier
- **Input Shape**: (n_samples, 100)
- **Features**: Combined structural and behavioral features
- **Preprocessing**: Standard scaling and feature selection

## Model Updates and Versioning

### Version Naming Convention
- Format: `{model_name}_v{major}.{minor}.{patch}`
- Example: `bytecode_classifier_v1.0.0`

### Model Registry Integration
Models are registered in the SQLite database defined in `model_registry_config.toml`:

```sql
-- Check registered models
SELECT * FROM models WHERE status = 'active';

-- View performance metrics
SELECT * FROM model_performance ORDER BY accuracy DESC;
```

## Production Deployment

### Confidence Thresholds
- **High Confidence**: 0.9+ (production decisions)
- **Medium Confidence**: 0.7-0.9 (manual review)
- **Low Confidence**: 0.5-0.7 (flagged for analysis)

### Performance Monitoring
- Track inference times and accuracy
- Monitor for model drift
- Automatic fallback to ensemble model for low confidence

### Memory Usage
- Bytecode Classifier: ~2.3 MB
- VM Detector: ~0.8 MB
- Handler Classifier: ~4.1 MB
- VMProtect Detector: ~3.2 MB
- Ensemble Classifier: ~5.7 MB
- **Total**: ~16.1 MB

## Troubleshooting

### Common Issues
1. **Model Loading Errors**: Ensure scikit-learn version compatibility
2. **Feature Dimension Mismatch**: Verify input shape matches expected dimensions
3. **Low Confidence Predictions**: Consider ensemble model or additional features

### Debug Mode
Enable debug logging in VMDragonSlayer configuration:
```yaml
ml_engine:
  debug_mode: true
  log_predictions: true
  confidence_threshold: 0.5
```

## Model Retraining

### Data Requirements
- **Minimum samples**: 500 per class
- **Feature quality**: Consistent preprocessing pipeline
- **Validation**: 5-fold cross-validation recommended

### Retraining Schedule
- **Quarterly**: Performance evaluation
- **Bi-annually**: Full model retraining
- **On-demand**: New VM protection techniques discovered

## Contact and Support

For model-related issues or questions:
- Create issue in VMDragonSlayer repository
- Include model version and error details
- Provide sample input data if possible
