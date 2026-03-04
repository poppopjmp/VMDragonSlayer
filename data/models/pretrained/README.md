# VMDragonSlayer Pretrained Models

This directory contains pretrained machine learning models for VM analysis tasks.

## Available Models

### 1. Bytecode Pattern Classifier (bytecode_classifier_v1.pkl)
- **Purpose**: Classifies VM bytecode patterns into semantic categories
- **Type**: Multi-class classifier
- **Classes**: arithmetic, memory, control_flow, logical, stack, comparison
- **Training Data**: 50,000 labeled bytecode samples
- **Accuracy**: 92.3%
- **Features**: Opcode n-grams, structural features

### 2. VM Detection Model (vm_detector_v1.pkl)
- **Purpose**: Binary classification for VM presence detection
- **Type**: Binary classifier
- **Classes**: vm_protected, not_vm_protected
- **Training Data**: 20,000 labeled binary samples
- **Accuracy**: 95.7%
- **Features**: Entropy, byte histograms, structural analysis

### 3. Handler Classification Model (handler_classifier_v1.pkl)
- **Purpose**: Classifies VM handler types and operations
- **Type**: Multi-class classifier
- **Classes**: Various VM operation types
- **Training Data**: 35,000 labeled handler samples
- **Accuracy**: 89.1%
- **Features**: Assembly patterns, control flow analysis

### 4. VMProtect Detector (vmprotect_detector_v1.pkl)
- **Purpose**: Specialized detector for VMProtect protection
- **Type**: Binary classifier with confidence scoring
- **Training Data**: 15,000 VMProtect samples
- **Accuracy**: 97.2%
- **Features**: VMProtect-specific patterns and heuristics

### 5. Ensemble Model (ensemble_classifier_v1.pkl)
- **Purpose**: Combines multiple models for improved accuracy
- **Type**: Ensemble (voting classifier)
- **Base Models**: bytecode_classifier, vm_detector, handler_classifier
- **Accuracy**: 94.8%
- **Method**: Soft voting with weighted predictions

## Model Format

All models are saved using scikit-learn's joblib format for efficient loading and compatibility.

## Usage

```python
from vmdragonslayer.ml import EnsemblePredictor
from vmdragonslayer import get_config

config = get_config()
predictor = EnsemblePredictor()
predictor.load_models(config.models_dir + "/pretrained/")

# Predict on new data
result = predictor.predict(features)
```

## Retraining

Models can be retrained using the training configurations in `data/training/training_config.json`.

## Model Versioning

- v1.0.0: Initial release models
- Models are versioned using semantic versioning
- Performance metrics are tracked in the model registry database
